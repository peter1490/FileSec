//! A UI-agnostic "wake the UI" handle for background threads.
//!
//! Background work (the job worker, the secure wiper, the network transfer
//! threads, the read-only view watchers) runs on plain `std::thread`s and must
//! tell the UI that something changed so it can re-render. The UI toolkit's own
//! context types are not `Send` (GPUI's `App` lives on the main thread), so the
//! workers hold this small, cloneable, thread-safe callback instead.
//!
//! [`crate::app`] builds the live handle from a channel that a foreground GPUI
//! task drains (see `FileSecApp::new`); tests and headless callers use
//! [`Repaint::noop`], which wakes nothing.

use std::fmt;
use std::sync::Arc;

/// A cheap, cloneable, `Send + Sync` request-a-repaint callback.
#[derive(Clone, Default)]
pub struct Repaint(Option<Arc<dyn Fn() + Send + Sync>>);

impl Repaint {
    /// Wake the UI by calling `wake` (from any thread).
    pub fn new(wake: impl Fn() + Send + Sync + 'static) -> Self {
        Self(Some(Arc::new(wake)))
    }

    /// A handle that wakes nothing — for tests, and for work queued after the
    /// window is gone.
    #[must_use]
    pub fn noop() -> Self {
        Self(None)
    }

    /// Ask the UI to re-render soon. Cheap and non-blocking; coalescing repeated
    /// requests is the receiver's job.
    pub fn request_repaint(&self) {
        if let Some(wake) = &self.0 {
            wake();
        }
    }
}

impl fmt::Debug for Repaint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Repaint")
            .field("live", &self.0.is_some())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn a_live_handle_calls_its_waker_from_any_thread() {
        let hits = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&hits);
        let repaint = Repaint::new(move || {
            counter.fetch_add(1, Ordering::SeqCst);
        });
        let remote = repaint.clone();
        std::thread::spawn(move || remote.request_repaint())
            .join()
            .expect("thread");
        repaint.request_repaint();
        assert_eq!(hits.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn a_noop_handle_is_harmless() {
        Repaint::noop().request_repaint();
        Repaint::default().request_repaint();
    }
}
