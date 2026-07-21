//! mDNS record cache.
//!
//! Stores resource records observed on the wire keyed by `(name, type,
//! rdata)` and tracks per-record TTL plus the interface where each record
//! was learned. A periodic [`Cache::evict_expired`] sweep removes entries
//! past their deadline, and an upper bound on the number of entries protects
//! the daemon from a malicious peer flooding the link with bogus records
//! (RFC 6762 §16).

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use hickory_proto::rr::{Name, Record, RecordType};

use crate::record_key::RecordKey;

/// Default ceiling on the number of cached records. Tunable via
/// [`Cache::with_capacity`].
pub const DEFAULT_MAX_ENTRIES: usize = 4096;

/// Outcome of [`Cache::insert`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InsertOutcome {
    /// Newly cached record.
    Inserted,
    /// Replaced an existing entry (refreshed TTL).
    Refreshed,
    /// TTL = 0 goodbye; an existing entry was removed.
    GoodbyeRemoved,
    /// TTL = 0 goodbye; nothing to remove.
    GoodbyeNoOp,
    /// Cache is at capacity; record was rejected.
    Rejected,
}

#[derive(Debug, Clone)]
pub struct Entry {
    pub record: Record,
    pub deadline: Instant,
    pub source_ifindex: Option<u32>,
}

pub struct Cache {
    inner: Mutex<Inner>,
}

struct Inner {
    by_key: HashMap<RecordKey, Entry>,
    max_entries: usize,
    max_ttl: Option<u64>,
}

impl Cache {
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_MAX_ENTRIES)
    }

    pub fn with_capacity(max_entries: usize) -> Self {
        Self::with_capacity_and_max_ttl(max_entries, None)
    }

    pub fn with_capacity_and_max_ttl(max_entries: usize, max_ttl: Option<u64>) -> Self {
        Self {
            inner: Mutex::new(Inner {
                by_key: HashMap::new(),
                max_entries: max_entries.max(1),
                max_ttl,
            }),
        }
    }

    /// Insert (or refresh) a record without source-interface metadata.
    pub fn insert(&self, record: Record) -> InsertOutcome {
        self.insert_from(record, None)
    }

    /// Insert (or refresh) a record. TTL=0 deletes the matching entry per
    /// RFC 6762 §10.1 ("goodbye" packet).
    ///
    /// When the cache is at capacity the soonest-to-expire entry is
    /// evicted to make room; if no entries are close to expiring the new
    /// record is rejected. This bounds memory growth from a hostile peer.
    ///
    /// If `max_ttl` is configured, the record's TTL is capped before storage,
    /// limiting how long a cached (potentially poisoned) record can persist.
    /// This is a security trade-off: lower caps reduce the window for cache
    /// poisoning on cross-interface bridges but also shorten the TTL of
    /// legitimate long-lived service records. Goodbye (TTL=0) records are
    /// never capped so they always correctly evict the matching entry.
    pub fn insert_from(&self, mut record: Record, source_ifindex: Option<u32>) -> InsertOutcome {
        let key = RecordKey::of(&record);
        let mut g = self.inner.lock().unwrap();

        // Cap the TTL before any decisions. Goodbye (TTL=0) records are
        // never capped so they always correctly evict the matching entry.
        // `max_ttl` is guaranteed by config validation to be in 1..=u32::MAX,
        // so the `as u32` cast is safe.
        if record.ttl > 0 {
            if let Some(cap) = g.max_ttl {
                record.ttl = record.ttl.min(cap as u32);
            }
        }

        if record.ttl == 0 {
            return if g.by_key.remove(&key).is_some() {
                InsertOutcome::GoodbyeRemoved
            } else {
                InsertOutcome::GoodbyeNoOp
            };
        }

        // RFC 6762 §10.2: a record with the cache-flush bit set replaces all
        // cached records of the same (name, type, class). Purge stale siblings
        // with different rdata; the exact-rdata match (if any) is refreshed by
        // the normal path below.
        if record.mdns_cache_flush {
            let rtype = record.record_type();
            let class = record.dns_class;
            g.by_key.retain(|k, _| {
                !(k.name == record.name
                    && k.rtype == rtype
                    && k.class == class
                    && k.rdata != record.data)
            });
        }

        let deadline = Instant::now() + Duration::from_secs(record.ttl as u64);

        use std::collections::hash_map::Entry as HEntry;
        if let HEntry::Occupied(mut e) = g.by_key.entry(key.clone()) {
            let source_ifindex = source_ifindex.or(e.get().source_ifindex);
            e.insert(Entry {
                record,
                deadline,
                source_ifindex,
            });
            return InsertOutcome::Refreshed;
        }

        if g.by_key.len() >= g.max_entries {
            // At capacity, evict the soonest-to-expire entry to admit the new
            // record. Evicting unconditionally (rather than only when the
            // victim is near expiry) keeps the cache bounded without letting a
            // flood of long-TTL records wedge it shut. (A full LRU would need
            // an extra list; deadline-based eviction is good enough for a
            // bounded mDNS cache.)
            let victim = g
                .by_key
                .iter()
                .min_by_key(|(_, e)| e.deadline)
                .map(|(k, _)| k.clone());
            if let Some(k) = victim {
                g.by_key.remove(&k);
            }
        }

        g.by_key.insert(
            key,
            Entry {
                record,
                deadline,
                source_ifindex,
            },
        );
        InsertOutcome::Inserted
    }

    /// Number of live entries.
    pub fn len(&self) -> usize {
        self.inner.lock().unwrap().by_key.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Remove all entries past their deadline. Returns the count evicted.
    pub fn evict_expired(&self) -> usize {
        let now = Instant::now();
        let mut g = self.inner.lock().unwrap();
        let before = g.by_key.len();
        g.by_key.retain(|_, e| e.deadline > now);
        before - g.by_key.len()
    }

    /// Snapshot all live records of a given (name, type). `ANY` matches all
    /// record types for the name. Returned records have TTLs reduced to the
    /// remaining lifetime at lookup time.
    pub fn lookup(&self, name: &Name, rtype: RecordType) -> Vec<Record> {
        self.lookup_inner(name, rtype, |_| true)
    }

    /// Snapshot live records for `name`/`rtype` that were learned on a
    /// different interface than `arrival_ifindex`.
    ///
    /// These records are relayed onto another link, so the cache-flush bit is
    /// cleared: nmdns does not own them and must not instruct receivers to
    /// flush the true owner's records (RFC 6762 §10.2).
    pub fn lookup_from_other_ifaces(
        &self,
        name: &Name,
        rtype: RecordType,
        arrival_ifindex: u32,
    ) -> Vec<Record> {
        let mut records = self.lookup_inner(name, rtype, |e| {
            matches!(e.source_ifindex, Some(source_ifindex) if source_ifindex != arrival_ifindex)
        });
        for r in &mut records {
            r.mdns_cache_flush = false;
        }
        records
    }

    fn lookup_inner<F>(&self, name: &Name, rtype: RecordType, source_filter: F) -> Vec<Record>
    where
        F: Fn(&Entry) -> bool,
    {
        let now = Instant::now();
        let g = self.inner.lock().unwrap();
        g.by_key
            .values()
            .filter(|e| record_matches(&e.record, name, rtype) && source_filter(e))
            .filter_map(|e| record_with_remaining_ttl(e, now))
            .collect()
    }

    /// Iterate every cached record (snapshot). For diagnostics only.
    pub fn snapshot(&self) -> Vec<Record> {
        let now = Instant::now();
        self.inner
            .lock()
            .unwrap()
            .by_key
            .values()
            .filter_map(|e| record_with_remaining_ttl(e, now))
            .collect()
    }
}

fn record_matches(record: &Record, name: &Name, rtype: RecordType) -> bool {
    &record.name == name && (rtype == RecordType::ANY || record.record_type() == rtype)
}

fn record_with_remaining_ttl(entry: &Entry, now: Instant) -> Option<Record> {
    let remaining = entry.deadline.checked_duration_since(now)?;
    let mut ttl = remaining.as_secs();
    if remaining.subsec_nanos() > 0 {
        ttl = ttl.saturating_add(1);
    }
    if ttl == 0 {
        return None;
    }

    let mut record = entry.record.clone();
    record.ttl = ttl.min(u32::MAX as u64) as u32;
    Some(record)
}

impl Default for Cache {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::rr::rdata::{A, AAAA};
    use hickory_proto::rr::{DNSClass, RData, RecordType};
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::str::FromStr;

    fn rec(name: &str, ttl: u32, ip: [u8; 4]) -> Record {
        Record::from_rdata(
            Name::from_str(name).unwrap(),
            ttl,
            RData::A(A(Ipv4Addr::from(ip))),
        )
    }

    fn rec_aaaa(name: &str, ttl: u32, ip: Ipv6Addr) -> Record {
        Record::from_rdata(Name::from_str(name).unwrap(), ttl, RData::AAAA(AAAA(ip)))
    }

    #[test]
    fn insert_and_lookup() {
        let c = Cache::new();
        assert_eq!(
            c.insert(rec("foo.local.", 120, [1, 2, 3, 4])),
            InsertOutcome::Inserted
        );
        let hits = c.lookup(&Name::from_str("foo.local.").unwrap(), RecordType::A);
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn insert_and_lookup_aaaa() {
        let c = Cache::new();
        assert_eq!(
            c.insert(rec_aaaa("foo.local.", 120, Ipv6Addr::LOCALHOST)),
            InsertOutcome::Inserted
        );
        let hits = c.lookup(&Name::from_str("foo.local.").unwrap(), RecordType::AAAA);
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn a_and_aaaa_are_distinct_records() {
        let c = Cache::new();
        c.insert(rec("foo.local.", 120, [1, 2, 3, 4]));
        c.insert(rec_aaaa("foo.local.", 120, Ipv6Addr::LOCALHOST));
        assert_eq!(
            c.lookup(&Name::from_str("foo.local.").unwrap(), RecordType::A)
                .len(),
            1
        );
        assert_eq!(
            c.lookup(&Name::from_str("foo.local.").unwrap(), RecordType::AAAA)
                .len(),
            1
        );
        assert_eq!(
            c.lookup(&Name::from_str("foo.local.").unwrap(), RecordType::ANY)
                .len(),
            2
        );
    }

    #[test]
    fn ttl_zero_deletes() {
        let c = Cache::new();
        c.insert(rec("foo.local.", 120, [1, 2, 3, 4]));
        assert_eq!(
            c.insert(rec("foo.local.", 0, [1, 2, 3, 4])),
            InsertOutcome::GoodbyeRemoved
        );
        assert_eq!(c.len(), 0);
        assert_eq!(
            c.insert(rec("foo.local.", 0, [9, 9, 9, 9])),
            InsertOutcome::GoodbyeNoOp
        );
    }

    #[test]
    fn dns_class_is_part_of_key() {
        // A record differing only in DNS class must not collide with (and
        // overwrite) the legitimate class-IN entry. DNS record identity is
        // (name, type, class, rdata); the cache key must include class.
        let c = Cache::new();
        c.insert(rec("foo.local.", 120, [1, 2, 3, 4])); // class IN by default
        let mut other = rec("foo.local.", 120, [1, 2, 3, 4]);
        other.dns_class = DNSClass::ANY;
        c.insert(other);
        assert_eq!(c.len(), 2, "class-ANY record must not overwrite class-IN");
        let hits = c.lookup(&Name::from_str("foo.local.").unwrap(), RecordType::A);
        assert!(
            hits.iter().any(|r| r.dns_class == DNSClass::IN),
            "the legitimate class-IN record must survive"
        );
    }

    #[test]
    fn distinct_rdata_kept_separately() {
        let c = Cache::new();
        c.insert(rec("foo.local.", 120, [1, 2, 3, 4]));
        c.insert(rec("foo.local.", 120, [5, 6, 7, 8]));
        assert_eq!(c.len(), 2);
    }

    #[test]
    fn cache_flush_replaces_stale_rdata() {
        // RFC 6762 §10.2: a record with the cache-flush bit set replaces all
        // prior records of the same (name, type, class), even with different
        // rdata — an address renumber must not leave the dead address behind.
        let c = Cache::new();
        let mut old = rec("printer.local.", 120, [192, 168, 20, 50]);
        old.mdns_cache_flush = true;
        c.insert(old);
        let mut new = rec("printer.local.", 120, [192, 168, 20, 60]);
        new.mdns_cache_flush = true;
        c.insert(new);

        let hits = c.lookup(&Name::from_str("printer.local.").unwrap(), RecordType::A);
        assert_eq!(hits.len(), 1, "stale address must be flushed");
        assert!(
            matches!(&hits[0].data, RData::A(A(a)) if *a == Ipv4Addr::new(192, 168, 20, 60)),
            "only the new address remains"
        );
    }

    #[test]
    fn cache_flush_does_not_purge_shared_records() {
        // Shared records (cache-flush bit NOT set, e.g. PTR) stay additive.
        let c = Cache::new();
        c.insert(rec("foo.local.", 120, [1, 2, 3, 4]));
        c.insert(rec("foo.local.", 120, [5, 6, 7, 8]));
        assert_eq!(
            c.len(),
            2,
            "non-cache-flush records must not purge siblings"
        );
    }

    #[test]
    fn refresh_replaces() {
        let c = Cache::new();
        assert_eq!(
            c.insert(rec("foo.local.", 60, [1, 2, 3, 4])),
            InsertOutcome::Inserted
        );
        assert_eq!(
            c.insert(rec("foo.local.", 120, [1, 2, 3, 4])),
            InsertOutcome::Refreshed
        );
        assert_eq!(c.len(), 1);
    }

    #[test]
    fn capacity_bounds_growth() {
        let c = Cache::with_capacity(2);
        c.insert(rec("a.local.", 600, [1, 0, 0, 1]));
        c.insert(rec("b.local.", 600, [1, 0, 0, 2]));
        // At capacity, a new record evicts the soonest-to-expire entry rather
        // than being rejected, so the cache stays bounded but keeps accepting.
        assert_eq!(
            c.insert(rec("c.local.", 600, [1, 0, 0, 3])),
            InsertOutcome::Inserted
        );
        assert_eq!(c.len(), 2);
    }

    #[test]
    fn full_cache_evicts_soonest_to_expire_not_wedge() {
        // A full cache of long-TTL records must not lock out new inserts (a
        // hostile-flood DoS): the soonest-to-expire entry is evicted to admit
        // a newer record.
        let c = Cache::with_capacity(2);
        c.insert(rec("soon.local.", 30, [1, 0, 0, 1])); // soonest deadline
        c.insert(rec("later.local.", 600, [1, 0, 0, 2]));
        assert_eq!(
            c.insert(rec("new.local.", 600, [1, 0, 0, 3])),
            InsertOutcome::Inserted
        );
        assert_eq!(c.len(), 2);
        assert!(
            c.lookup(&Name::from_str("soon.local.").unwrap(), RecordType::A)
                .is_empty(),
            "soonest-to-expire entry is the eviction victim"
        );
        assert!(
            !c.lookup(&Name::from_str("new.local.").unwrap(), RecordType::A)
                .is_empty(),
            "the new record was admitted"
        );
    }

    #[test]
    fn max_ttl_caps_stored_ttl() {
        let c = Cache::with_capacity_and_max_ttl(100, Some(60));
        assert_eq!(
            c.insert(rec("foo.local.", 4500, [1, 2, 3, 4])),
            InsertOutcome::Inserted
        );
        let hits = c.lookup(&Name::from_str("foo.local.").unwrap(), RecordType::A);
        assert_eq!(hits.len(), 1);
        assert!(
            hits[0].ttl <= 60,
            "TTL should be capped to 60, got {}",
            hits[0].ttl
        );
    }

    #[test]
    fn max_ttl_does_not_cap_below_actual() {
        let c = Cache::with_capacity_and_max_ttl(100, Some(300));
        assert_eq!(
            c.insert(rec("foo.local.", 120, [1, 2, 3, 4])),
            InsertOutcome::Inserted
        );
        let hits = c.lookup(&Name::from_str("foo.local.").unwrap(), RecordType::A);
        assert_eq!(hits.len(), 1);
        assert!(hits[0].ttl <= 120, "TTL below cap should be preserved");
    }

    #[test]
    fn max_ttl_does_not_cap_goodbye() {
        let c = Cache::with_capacity_and_max_ttl(100, Some(60));
        c.insert(rec("foo.local.", 120, [1, 2, 3, 4]));
        assert_eq!(
            c.insert(rec("foo.local.", 0, [1, 2, 3, 4])),
            InsertOutcome::GoodbyeRemoved
        );
        assert_eq!(c.len(), 0);
    }

    #[test]
    fn no_max_ttl_preserves_original() {
        let c = Cache::with_capacity_and_max_ttl(100, None);
        assert_eq!(
            c.insert(rec("foo.local.", 4500, [1, 2, 3, 4])),
            InsertOutcome::Inserted
        );
        let hits = c.lookup(&Name::from_str("foo.local.").unwrap(), RecordType::A);
        assert_eq!(hits.len(), 1);
        assert!(hits[0].ttl <= 4500);
        assert!(
            hits[0].ttl > 4490,
            "TTL should be near original, got {}",
            hits[0].ttl
        );
    }
}
