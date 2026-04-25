//! Shared runtime state — cloned via `Arc<State>` into every task.

use std::sync::atomic::AtomicU64;
use std::sync::Arc;

use tokio_util::sync::CancellationToken;

use crate::cache::Cache;
use crate::config::Resolved;
use crate::iface::Iface;
use crate::timing::MulticastTracker;

#[derive(Default)]
pub struct Metrics {
    pub queries_received: AtomicU64,
    pub queries_sent: AtomicU64,
    pub responses: AtomicU64,
    pub repeated: AtomicU64,
    /// Records evicted by the periodic TTL sweep.
    pub cache_evicted: AtomicU64,
    /// Records removed because we received a TTL=0 goodbye.
    pub cache_goodbyes: AtomicU64,
    /// Records rejected because the cache was full.
    pub cache_rejected: AtomicU64,
    pub parse_errors: AtomicU64,
}

pub struct State {
    pub config: Resolved,
    pub ifaces: Vec<Arc<Iface>>,
    pub cache: Cache,
    pub metrics: Metrics,
    /// Cancellation token signalled when the daemon should shut down.
    pub shutdown: CancellationToken,
    /// Per-(iface, record) last-multicast timestamps for the RFC 6762 §6
    /// one-second-per-record rate limit.
    pub mc_tracker: MulticastTracker,
}
