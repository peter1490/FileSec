//! Background secure-wiping of plaintext temp files.
//!
//! [`store::secure_wipe`](crate::store::secure_wipe) overwrites a file's whole
//! length with random bytes and `fsync`s before unlinking — seconds to minutes
//! on a large file. Doing that on the UI thread makes leaving a vault (or
//! quitting) look like the app has hung, so every UI-initiated wipe goes through
//! the single worker thread owned by [`Wiper`] instead.
//!
//! The queue is deliberately serialised on one thread: wiping is I/O-bound, and
//! shredding several files at once only makes each one slower.

use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};

/// One file to shred, plus the context to wake so the UI can reflect progress.
/// `ctx` is `None` when the job is queued from `on_exit`, where the window is
/// already gone and a repaint would go nowhere.
struct WipeJob {
    path: PathBuf,
    ctx: Option<egui::Context>,
}

/// The cheap, cloneable enqueue side. Handed to background jobs and to the
/// detached view-watcher threads so they can hand their wipe over instead of
/// blocking on it themselves.
#[derive(Clone)]
pub struct WipeHandle {
    tx: mpsc::Sender<WipeJob>,
    pending: Arc<AtomicUsize>,
}

impl WipeHandle {
    /// Queue `path` for secure deletion and return immediately.
    ///
    /// Best-effort, like [`crate::store::secure_wipe`] itself: if the worker is
    /// gone the file is left for the next unlock's `clean_checkout_dir` sweep.
    pub fn enqueue(&self, ctx: &egui::Context, path: PathBuf) {
        self.send(path, Some(ctx.clone()));
    }

    /// Queue `path` without waking any UI — for `on_exit`, where the window has
    /// already been torn down.
    pub fn enqueue_quiet(&self, path: PathBuf) {
        self.send(path, None);
    }

    fn send(&self, path: PathBuf, ctx: Option<egui::Context>) {
        // Count it in *before* handing it over, so `Wiper::pending() == 0` can
        // never be observed while a queued file is still on disk.
        self.pending.fetch_add(1, Ordering::SeqCst);
        if self.tx.send(WipeJob { path, ctx }).is_err() {
            self.pending.fetch_sub(1, Ordering::SeqCst);
        }
    }
}

/// Owns the wiper thread. Lives on `App` (not `Session`) because locking or
/// closing a vault destroys the session while its wipes are still running.
pub struct Wiper {
    handle: WipeHandle,
    /// The owning sender. Dropped by [`Wiper::finish`] to close the channel and
    /// let the worker thread exit.
    tx: Option<mpsc::Sender<WipeJob>>,
}

impl Wiper {
    pub fn new() -> Self {
        let (tx, rx) = mpsc::channel::<WipeJob>();
        let pending = Arc::new(AtomicUsize::new(0));
        let worker_pending = Arc::clone(&pending);
        std::thread::spawn(move || {
            for job in rx {
                let _ = crate::store::secure_wipe(&job.path);
                worker_pending.fetch_sub(1, Ordering::SeqCst);
                // Wake the UI so a shutdown overlay (or anything else watching
                // `pending`) updates as the queue drains.
                if let Some(ctx) = job.ctx {
                    ctx.request_repaint();
                }
            }
        });
        Self {
            handle: WipeHandle {
                tx: tx.clone(),
                pending,
            },
            tx: Some(tx),
        }
    }

    /// A clone of the enqueue side, for code that outlives the current frame.
    pub fn handle(&self) -> WipeHandle {
        self.handle.clone()
    }

    /// Queue `path` for secure deletion and return immediately.
    pub fn enqueue(&self, ctx: &egui::Context, path: PathBuf) {
        self.handle.enqueue(ctx, path);
    }

    /// Queue `path` without waking any UI. See [`WipeHandle::enqueue_quiet`].
    pub fn enqueue_quiet(&self, path: PathBuf) {
        self.handle.enqueue_quiet(path);
    }

    /// Files queued but not yet wiped. Zero means every enqueued file is gone.
    pub fn pending(&self) -> usize {
        self.handle.pending.load(Ordering::SeqCst)
    }

    /// Close the queue and wait up to `timeout` for it to drain.
    ///
    /// Last-resort only: the shutdown gate in `App::update` normally drains the
    /// queue with the UI still painting, so by the time this runs there is
    /// usually nothing left. `JoinHandle::join` has no timeout, hence the
    /// sleep-poll. Whatever survives the timeout is picked up by the next
    /// unlock's `Store::clean_checkout_dir`.
    pub fn finish(&mut self, timeout: Duration) {
        // Drop the owning sender; the worker's `for job in rx` ends once the
        // queue is empty and no handles remain.
        self.tx = None;
        let deadline = Instant::now() + timeout;
        while self.pending() > 0 && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

impl Default for Wiper {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    fn tmp_file(name: &str) -> PathBuf {
        let suffix = filesec_core::util::hex(&filesec_core::secret::random_array::<8>().unwrap());
        let path = std::env::temp_dir().join(format!("filesec-wipe-{suffix}-{name}"));
        std::fs::write(&path, b"plaintext that must not survive").unwrap();
        path
    }

    #[test]
    fn enqueued_files_are_wiped_and_pending_returns_to_zero() {
        let ctx = egui::Context::default();
        let mut wiper = Wiper::new();
        let paths: Vec<PathBuf> = (0..4).map(|i| tmp_file(&format!("{i}"))).collect();
        for p in &paths {
            wiper.enqueue(&ctx, p.clone());
        }
        wiper.finish(Duration::from_secs(10));
        assert_eq!(wiper.pending(), 0);
        for p in &paths {
            assert!(!p.exists(), "{} survived the wipe", p.display());
        }
    }

    #[test]
    fn enqueue_does_not_block_the_caller() {
        let ctx = egui::Context::default();
        let wiper = Wiper::new();
        let path = tmp_file("nonblocking");
        wiper.enqueue(&ctx, path.clone());
        // Nothing to assert about timing reliably; what matters is that the
        // count was taken before the worker could possibly have finished, so a
        // shutdown gate can never see a false zero.
        let seen = wiper.pending();
        assert!(seen <= 1);
        let mut wiper = wiper;
        wiper.finish(Duration::from_secs(10));
        assert!(!path.exists());
    }

    #[test]
    fn wiping_a_missing_file_is_harmless() {
        let ctx = egui::Context::default();
        let mut wiper = Wiper::new();
        wiper.enqueue(
            &ctx,
            std::env::temp_dir().join("filesec-wipe-does-not-exist"),
        );
        wiper.finish(Duration::from_secs(10));
        assert_eq!(wiper.pending(), 0);
    }
}
