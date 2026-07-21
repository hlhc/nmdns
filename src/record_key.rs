//! Stable identity for a resource record.
//!
//! Used as the hash key for the cache ([`crate::cache`]) and the
//! per-interface multicast rate limiter ([`crate::timing`]).
//!
//! `hickory_proto::rr::RData` derives `Hash + Eq + PartialEq`, so we key on
//! it directly. (Earlier revisions hashed `format!("{:?}", rdata)`, which
//! tied us to an unstable Debug format and could silently break across
//! `hickory-proto` versions.)

use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct RecordKey {
    pub name: Name,
    pub rtype: RecordType,
    pub class: DNSClass,
    pub rdata: RData,
}

impl RecordKey {
    pub fn of(rec: &Record) -> Self {
        Self {
            name: rec.name.clone(),
            rtype: rec.record_type(),
            class: rec.dns_class,
            rdata: rec.data.clone(),
        }
    }
}

/// True when two rdata values compare equal.
pub fn rdata_eq(a: &RData, b: &RData) -> bool {
    a == b
}
