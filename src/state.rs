//! Shared runtime state — cloned via `Arc<State>` into every task.

use std::sync::Arc;

use tokio_util::sync::CancellationToken;

use crate::cache::Cache;
use crate::config::Resolved;
use crate::iface::Iface;
use crate::timing::MulticastTracker;

pub struct State {
    pub config: Resolved,
    pub ifaces: Vec<Arc<Iface>>,
    pub cache: Cache,
    /// Cancellation token signalled when the daemon should shut down.
    pub shutdown: CancellationToken,
    /// Per-(iface, record) last-multicast timestamps for the RFC 6762 §6
    /// one-second-per-record rate limit.
    pub mc_tracker: MulticastTracker,
}
