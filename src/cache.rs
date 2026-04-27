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
}

impl Cache {
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_MAX_ENTRIES)
    }

    pub fn with_capacity(max_entries: usize) -> Self {
        Self {
            inner: Mutex::new(Inner {
                by_key: HashMap::new(),
                max_entries: max_entries.max(1),
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
    pub fn insert_from(&self, record: Record, source_ifindex: Option<u32>) -> InsertOutcome {
        let key = RecordKey::of(&record);
        let ttl = record.ttl;
        let mut g = self.inner.lock().unwrap();

        if ttl == 0 {
            return if g.by_key.remove(&key).is_some() {
                InsertOutcome::GoodbyeRemoved
            } else {
                InsertOutcome::GoodbyeNoOp
            };
        }

        let deadline = Instant::now() + Duration::from_secs(ttl as u64);

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
            // Evict the soonest-to-expire entry, but only if it's "close
            // enough" to expiry that we'd have evicted it within the next
            // few seconds anyway. (A full LRU would need an extra list;
            // deadline-based eviction is good enough for a bounded mDNS
            // cache.)
            let now = Instant::now();
            let victim = g
                .by_key
                .iter()
                .min_by_key(|(_, e)| e.deadline)
                .map(|(k, e)| (k.clone(), e.deadline));
            match victim {
                Some((k, d)) if d <= now + Duration::from_secs(1) => {
                    g.by_key.remove(&k);
                }
                _ => return InsertOutcome::Rejected,
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
    pub fn lookup_from_other_ifaces(
        &self,
        name: &Name,
        rtype: RecordType,
        arrival_ifindex: u32,
    ) -> Vec<Record> {
        self.lookup_inner(name, rtype, |e| {
            matches!(e.source_ifindex, Some(source_ifindex) if source_ifindex != arrival_ifindex)
        })
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
    use hickory_proto::rr::RData;
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
    fn distinct_rdata_kept_separately() {
        let c = Cache::new();
        c.insert(rec("foo.local.", 120, [1, 2, 3, 4]));
        c.insert(rec("foo.local.", 120, [5, 6, 7, 8]));
        assert_eq!(c.len(), 2);
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
        assert_eq!(
            c.insert(rec("c.local.", 600, [1, 0, 0, 3])),
            InsertOutcome::Rejected
        );
        assert_eq!(c.len(), 2);
    }
}
