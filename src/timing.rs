//! RFC 6762 timing helpers: per-record-per-interface multicast rate limiting
//! and randomized response delays.
//!
//! Two distinct mechanisms live here:
//!
//!   * [`MulticastTracker`] enforces RFC 6762 §6: *"a Multicast DNS responder
//!     MUST NOT (except in the one special case of answering probe queries)
//!     multicast a record on a given interface until at least one second has
//!     elapsed since the last time that record was multicast on that
//!     particular interface."* Probe defense is allowed at 250 ms instead.
//!
//!   * [`response_delay`] computes the randomized response delay required by
//!     §6 and §6.3 (20–120 ms for shared / multi-question, 400–500 ms when
//!     the query has TC set, ≤10 ms for unique probe defense).

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use hickory_proto::rr::Record;

use crate::record_key::RecordKey;

/// Minimum interval between identical multicast responses for the same
/// record on the same interface (RFC 6762 §6).
pub const MIN_MULTICAST_INTERVAL: Duration = Duration::from_secs(1);

/// Reduced minimum interval used when defending a unique record against a
/// probe (RFC 6762 §6, last paragraph).
pub const PROBE_DEFENSE_INTERVAL: Duration = Duration::from_millis(250);

/// One-second gap between announcement transmissions (RFC 6762 §8.3).
pub const ANNOUNCE_GAP: Duration = Duration::from_secs(1);

/// Probe interval (RFC 6762 §8.1): three probes spaced 250 ms apart.
pub const PROBE_INTERVAL: Duration = Duration::from_millis(250);

/// Maximum random initial delay before the first probe (RFC 6762 §8.1).
pub const PROBE_INITIAL_MAX: Duration = Duration::from_millis(250);

/// Per-(interface, record) "last multicast" timestamps.
#[derive(Default)]
pub struct MulticastTracker {
    last: Mutex<HashMap<(u32, RecordKey), Instant>>,
}

impl MulticastTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record that `rec` was just multicast on interface `ifindex`.
    pub fn mark(&self, ifindex: u32, rec: &Record) {
        let key = (ifindex, RecordKey::of(rec));
        self.last.lock().unwrap().insert(key, Instant::now());
    }

    /// Number of tracked `(iface, record)` entries.
    pub fn len(&self) -> usize {
        self.last.lock().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Drop entries whose last-multicast timestamp is older than
    /// `min_interval`. Once that much time has elapsed the entry no longer
    /// affects rate limiting (a missing key and a stale key both mean
    /// "allowed"), so it is pure dead weight. Sweeping it bounds the map's
    /// memory on a busy or hostile network, where it would otherwise grow
    /// without limit for the daemon's lifetime.
    pub fn prune_older_than(&self, min_interval: Duration) {
        let now = Instant::now();
        self.last
            .lock()
            .unwrap()
            .retain(|_, t| now.duration_since(*t) < min_interval);
    }

    /// True if at least `min_interval` has elapsed since this record was
    /// last multicast on `ifindex` (or it was never sent).
    pub fn allows(&self, ifindex: u32, rec: &Record, min_interval: Duration) -> bool {
        let key = (ifindex, RecordKey::of(rec));
        let g = self.last.lock().unwrap();
        match g.get(&key) {
            Some(t) => t.elapsed() >= min_interval,
            None => true,
        }
    }

    /// Atomic check-and-mark. Returns `true` and stamps "now" if the record
    /// is allowed to be multicast on `ifindex` (i.e. at least `min_interval`
    /// has elapsed since the last send). Returns `false` and leaves the
    /// timestamp untouched if rate-limited. Use this from the hot path so
    /// concurrent handlers cannot both observe `allows() == true` and then
    /// double-send.
    pub fn check_and_mark(&self, ifindex: u32, rec: &Record, min_interval: Duration) -> bool {
        let key = (ifindex, RecordKey::of(rec));
        let now = Instant::now();
        let mut g = self.last.lock().unwrap();
        match g.get(&key) {
            Some(t) if now.duration_since(*t) < min_interval => false,
            _ => {
                g.insert(key, now);
                true
            }
        }
    }
}

/// Classification of an outgoing response, governing its randomized delay.
#[derive(Debug, Clone, Copy)]
pub enum DelayClass {
    /// Probe defense: defending a unique record. RFC 6762 §6 says respond
    /// "without delay" — at most 10 ms.
    ProbeDefense,
    /// Single-question, every answer is a unique record we own outright.
    /// RFC 6762 §6: SHOULD NOT impose a random delay; SHOULD respond within
    /// at most 10 ms.
    UniqueAnswer,
    /// Multi-question or shared-record answer. 20–120 ms uniform.
    Shared,
    /// Query had TC bit set (more known-answer packets to follow). 400–500 ms.
    Truncated,
}

/// Pick a concrete random delay for `class`.
pub fn response_delay(class: DelayClass) -> Duration {
    match class {
        DelayClass::ProbeDefense | DelayClass::UniqueAnswer => Duration::from_millis(0),
        DelayClass::Shared => Duration::from_millis(fastrand::u64(20..=120)),
        DelayClass::Truncated => Duration::from_millis(fastrand::u64(400..=500)),
    }
}

/// Random initial delay before the first probe (§8.1) or browser query (§5.2).
pub fn jitter_0_to_max(max: Duration) -> Duration {
    Duration::from_millis(fastrand::u64(0..=max.as_millis() as u64))
}

/// Random jitter in 20–120 ms — used as the first-query random delay
/// described in RFC 6762 §5.2.
pub fn first_query_jitter() -> Duration {
    Duration::from_millis(fastrand::u64(20..=120))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::rr::rdata::A;
    use hickory_proto::rr::{Name, RData};
    use std::net::Ipv4Addr;
    use std::str::FromStr;

    fn rec(ip: [u8; 4]) -> Record {
        Record::from_rdata(
            Name::from_str("foo.local.").unwrap(),
            120,
            RData::A(A(Ipv4Addr::from(ip))),
        )
    }

    #[test]
    fn allows_first_send() {
        let t = MulticastTracker::new();
        let r = rec([1, 2, 3, 4]);
        assert!(t.allows(1, &r, MIN_MULTICAST_INTERVAL));
    }

    #[test]
    fn blocks_within_interval() {
        let t = MulticastTracker::new();
        let r = rec([1, 2, 3, 4]);
        t.mark(1, &r);
        assert!(!t.allows(1, &r, MIN_MULTICAST_INTERVAL));
        // Different iface is independent.
        assert!(t.allows(2, &r, MIN_MULTICAST_INTERVAL));
    }

    #[test]
    fn allows_after_interval_zero() {
        let t = MulticastTracker::new();
        let r = rec([1, 2, 3, 4]);
        t.mark(1, &r);
        assert!(t.allows(1, &r, Duration::from_millis(0)));
    }

    #[test]
    fn prune_drops_stale_entries() {
        let t = MulticastTracker::new();
        t.mark(1, &rec([1, 2, 3, 4]));
        assert_eq!(t.len(), 1);
        // With a zero interval every existing entry is already "stale".
        t.prune_older_than(Duration::from_millis(0));
        assert_eq!(t.len(), 0, "stale rate-limit entries must be swept");
    }

    #[test]
    fn prune_keeps_recent_entries() {
        let t = MulticastTracker::new();
        t.mark(1, &rec([1, 2, 3, 4]));
        t.prune_older_than(Duration::from_secs(3600));
        assert_eq!(t.len(), 1, "entries within the interval must be kept");
    }

    #[test]
    fn delay_ranges_match_rfc() {
        for _ in 0..100 {
            let d = response_delay(DelayClass::Shared);
            assert!(d >= Duration::from_millis(20) && d <= Duration::from_millis(120));
            let d = response_delay(DelayClass::Truncated);
            assert!(d >= Duration::from_millis(400) && d <= Duration::from_millis(500));
            assert_eq!(response_delay(DelayClass::ProbeDefense), Duration::ZERO);
            assert_eq!(response_delay(DelayClass::UniqueAnswer), Duration::ZERO);
        }
    }
}
