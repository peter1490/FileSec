//! Listener DoS controls: a non-blocking counting semaphore that bounds how many
//! connections may be handshaking at once, and a per-IP backoff that throttles a
//! peer that keeps failing the handshake.
//!
//! Both are transport-agnostic and unit-tested with an injected clock so the
//! policy is exercised without real sockets or sleeps.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

// ---------------------------------------------------------------------------
// Bounded worker permits
// ---------------------------------------------------------------------------

/// A tiny non-blocking counting semaphore. The accept loop takes a permit before
/// spawning a handshake worker and drops it (via [`Permit`]) when the worker
/// exits, so at most `capacity` connections are ever in flight — a flood beyond
/// that is refused immediately rather than spawning unbounded threads.
pub struct Semaphore {
    available: AtomicUsize,
}

impl Semaphore {
    /// Create a semaphore with `capacity` permits.
    pub fn new(capacity: usize) -> Arc<Self> {
        Arc::new(Self {
            available: AtomicUsize::new(capacity),
        })
    }

    /// Try to take one permit without blocking. Returns a guard that returns the
    /// permit on drop, or `None` if the pool is currently full.
    pub fn try_acquire(self: &Arc<Self>) -> Option<Permit> {
        let mut current = self.available.load(Ordering::Acquire);
        loop {
            if current == 0 {
                return None;
            }
            match self.available.compare_exchange_weak(
                current,
                current - 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    return Some(Permit {
                        sem: Arc::clone(self),
                    })
                }
                Err(observed) => current = observed,
            }
        }
    }

    /// Permits currently available (test/observability helper).
    #[cfg(test)]
    pub fn available(&self) -> usize {
        self.available.load(Ordering::Acquire)
    }
}

/// RAII guard returning its permit to the [`Semaphore`] on drop.
pub struct Permit {
    sem: Arc<Semaphore>,
}

impl Drop for Permit {
    fn drop(&mut self) {
        self.sem.available.fetch_add(1, Ordering::AcqRel);
    }
}

// ---------------------------------------------------------------------------
// Per-IP failed-handshake backoff
// ---------------------------------------------------------------------------

/// How many consecutive failures a peer IP may accrue before it is blocked.
const FAILURE_THRESHOLD: u32 = 5;
/// Base backoff once the threshold is crossed; doubles per extra failure.
const BASE_BACKOFF: Duration = Duration::from_secs(1);
/// Ceiling on a single block window.
const MAX_BACKOFF: Duration = Duration::from_secs(60);
/// Idle time after which a peer's failure record is forgotten.
const FORGET_AFTER: Duration = Duration::from_secs(300);
/// Hard ceiling on tracked peers (FS-17). Time-based pruning alone bounds how
/// long a record lives, not how many exist: a sustained churn of real source
/// addresses could otherwise grow the map with the arrival rate. A record is
/// ~64 bytes, so this caps the table at a few hundred KiB.
const MAX_TRACKED_PEERS: usize = 4096;

/// The unit a failure is charged to. IPv4 addresses (and IPv4-mapped IPv6)
/// count individually; IPv6 addresses are aggregated to their /64, the block a
/// single host or customer is typically assigned — otherwise one machine could
/// rotate through 2^64 addresses to dodge its backoff and flood the table.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum PeerKey {
    V4(std::net::Ipv4Addr),
    V6Prefix64([u8; 8]),
}

impl PeerKey {
    fn of(ip: IpAddr) -> Self {
        match ip {
            IpAddr::V4(v4) => Self::V4(v4),
            IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
                Some(v4) => Self::V4(v4),
                None => {
                    let mut prefix = [0u8; 8];
                    prefix.copy_from_slice(&v6.octets()[..8]);
                    Self::V6Prefix64(prefix)
                }
            },
        }
    }
}

#[derive(Clone, Copy)]
struct Record {
    failures: u32,
    /// The peer is refused until this instant (once past the threshold).
    blocked_until: Option<Instant>,
    /// Last time we saw activity from this IP (for pruning).
    last_seen: Instant,
}

/// Tracks failed handshakes per source IP and answers whether a new connection
/// from that IP should currently be accepted. A successful handshake clears the
/// peer's record; repeated failures back it off exponentially.
#[derive(Default)]
pub struct RateLimiter {
    peers: HashMap<PeerKey, Record>,
}

impl RateLimiter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether a connection from `ip` should be accepted right now.
    pub fn allow(&mut self, ip: IpAddr, now: Instant) -> bool {
        match self.peers.get(&PeerKey::of(ip)) {
            Some(rec) => match rec.blocked_until {
                Some(until) => now >= until,
                None => true,
            },
            None => true,
        }
    }

    /// Record a failed handshake from `ip`, extending its backoff.
    pub fn record_failure(&mut self, ip: IpAddr, now: Instant) {
        let key = PeerKey::of(ip);
        if !self.peers.contains_key(&key) && self.peers.len() >= MAX_TRACKED_PEERS {
            self.make_room(now);
        }
        let rec = self.peers.entry(key).or_insert(Record {
            failures: 0,
            blocked_until: None,
            last_seen: now,
        });
        rec.failures = rec.failures.saturating_add(1);
        rec.last_seen = now;
        if rec.failures >= FAILURE_THRESHOLD {
            let over = rec.failures - FAILURE_THRESHOLD;
            // BASE * 2^over, saturating at MAX_BACKOFF.
            let backoff = BASE_BACKOFF
                .checked_mul(1u32.checked_shl(over.min(16)).unwrap_or(u32::MAX))
                .unwrap_or(MAX_BACKOFF)
                .min(MAX_BACKOFF);
            rec.blocked_until = Some(now + backoff);
        }
    }

    /// Clear a peer's record after a successful, authenticated handshake.
    pub fn record_success(&mut self, ip: IpAddr) {
        self.peers.remove(&PeerKey::of(ip));
    }

    /// Free room at the cardinality ceiling: forget expired records first,
    /// then, if the table is still full, the least recently seen eighth — in
    /// one pass, so a churn of new addresses costs amortized O(log n) each.
    fn make_room(&mut self, now: Instant) {
        self.prune(now);
        if self.peers.len() < MAX_TRACKED_PEERS {
            return;
        }
        let mut by_age: Vec<(Instant, PeerKey)> = self
            .peers
            .iter()
            .map(|(key, rec)| (rec.last_seen, *key))
            .collect();
        by_age.sort_unstable_by_key(|(seen, _)| *seen);
        for (_, key) in by_age.into_iter().take(MAX_TRACKED_PEERS / 8) {
            self.peers.remove(&key);
        }
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.peers.len()
    }

    /// Drop records for peers not seen within [`FORGET_AFTER`], so the map cannot
    /// grow without bound under a churn of source addresses.
    pub fn prune(&mut self, now: Instant) {
        self.peers
            .retain(|_, rec| now.duration_since(rec.last_seen) < FORGET_AFTER);
    }

    #[cfg(test)]
    fn failure_count(&self, ip: IpAddr) -> u32 {
        self.peers
            .get(&PeerKey::of(ip))
            .map(|r| r.failures)
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn ip(n: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, n))
    }

    #[test]
    fn semaphore_caps_concurrent_permits() {
        let sem = Semaphore::new(2);
        let a = sem.try_acquire().expect("first permit");
        let b = sem.try_acquire().expect("second permit");
        assert!(sem.try_acquire().is_none(), "pool is full at capacity");
        assert_eq!(sem.available(), 0);
        drop(a);
        assert_eq!(sem.available(), 1);
        let _c = sem.try_acquire().expect("a freed permit is reusable");
        assert!(sem.try_acquire().is_none());
        drop(b);
    }

    #[test]
    fn rate_limiter_blocks_after_threshold_then_recovers() {
        let mut rl = RateLimiter::new();
        let t0 = Instant::now();
        let peer = ip(9);

        // Below the threshold: still allowed.
        for _ in 0..(FAILURE_THRESHOLD - 1) {
            rl.record_failure(peer, t0);
            assert!(rl.allow(peer, t0));
        }
        // Crossing the threshold blocks the peer.
        rl.record_failure(peer, t0);
        assert!(!rl.allow(peer, t0), "peer must be blocked at the threshold");
        assert_eq!(rl.failure_count(peer), FAILURE_THRESHOLD);

        // Still blocked mid-window, allowed once the window elapses.
        assert!(!rl.allow(peer, t0 + BASE_BACKOFF / 2));
        assert!(rl.allow(peer, t0 + BASE_BACKOFF + Duration::from_millis(1)));
    }

    #[test]
    fn backoff_grows_and_caps() {
        let mut rl = RateLimiter::new();
        let t0 = Instant::now();
        let peer = ip(10);
        // Push well past the threshold; the window must never exceed MAX_BACKOFF.
        for _ in 0..40 {
            rl.record_failure(peer, t0);
        }
        assert!(!rl.allow(peer, t0 + MAX_BACKOFF - Duration::from_millis(1)));
        assert!(rl.allow(peer, t0 + MAX_BACKOFF + Duration::from_millis(1)));
    }

    #[test]
    fn success_resets_and_other_ips_are_independent() {
        let mut rl = RateLimiter::new();
        let t0 = Instant::now();
        let (a, b) = (ip(1), ip(2));
        for _ in 0..FAILURE_THRESHOLD {
            rl.record_failure(a, t0);
        }
        assert!(!rl.allow(a, t0));
        assert!(rl.allow(b, t0), "an unrelated IP is unaffected");
        rl.record_success(a);
        assert!(rl.allow(a, t0), "a successful handshake clears the block");
        assert_eq!(rl.failure_count(a), 0);
    }

    #[test]
    fn prune_forgets_stale_peers() {
        let mut rl = RateLimiter::new();
        let t0 = Instant::now();
        rl.record_failure(ip(3), t0);
        rl.prune(t0 + FORGET_AFTER + Duration::from_secs(1));
        assert_eq!(rl.failure_count(ip(3)), 0);
    }

    /// FS-17: a sustained churn of distinct source addresses cannot grow the
    /// table past its ceiling, and the newest offenders stay tracked.
    #[test]
    fn unique_address_churn_is_bounded() {
        let mut rl = RateLimiter::new();
        let t0 = Instant::now();
        for n in 0..50_000u32 {
            let addr = IpAddr::V4(Ipv4Addr::from(0x0A00_0000 + n));
            rl.record_failure(addr, t0 + Duration::from_micros(u64::from(n)));
            assert!(rl.len() <= MAX_TRACKED_PEERS);
        }
        assert!(rl.len() > MAX_TRACKED_PEERS / 2);
        let newest = IpAddr::V4(Ipv4Addr::from(0x0A00_0000 + 49_999));
        assert_eq!(rl.failure_count(newest), 1, "recent peers are kept");
        let oldest = IpAddr::V4(Ipv4Addr::from(0x0A00_0000u32));
        assert_eq!(rl.failure_count(oldest), 0, "the least recent was evicted");
    }

    #[test]
    fn ipv6_is_aggregated_to_its_slash_64_and_mapped_v4_to_v4() {
        use std::net::Ipv6Addr;
        let mut rl = RateLimiter::new();
        let t0 = Instant::now();
        for host in 0..FAILURE_THRESHOLD as u16 {
            let addr = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 1, 2, 0, 0, 0, host + 1));
            rl.record_failure(addr, t0);
        }
        // A fresh host in the same /64 inherits the block; another /64 does not.
        let same = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 1, 2, 9, 9, 9, 9));
        let other = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 1, 3, 0, 0, 0, 1));
        assert!(!rl.allow(same, t0));
        assert!(rl.allow(other, t0));
        assert_eq!(rl.len(), 1);

        let mapped = IpAddr::V6(Ipv4Addr::new(198, 51, 100, 7).to_ipv6_mapped());
        rl.record_failure(mapped, t0);
        assert_eq!(
            rl.failure_count(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7))),
            1
        );
    }
}
