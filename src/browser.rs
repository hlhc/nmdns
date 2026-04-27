//! Active browser: periodically query for service types of interest so the
//! cache stays warm. Implements RFC 6762 §5.2 timing:
//!
//!   * The first query is delayed by a random 20–120 ms to avoid accidental
//!     synchronisation between hosts that boot together.
//!   * Successive query intervals double (1 s, 2 s, 4 s, …) up to a
//!     configured ceiling (default 60 s; RFC permits up to one query / hour).

use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::{DNSClass, Name, RecordType};
use tokio::time::sleep;

use crate::state::State;
use crate::timing::first_query_jitter;

/// Background task: periodically send PTR queries for each browse target on
/// every interface. Responses populate the cache via the main receive loop.
pub async fn run(state: Arc<State>, browse: Vec<String>, interval_secs: u64) {
    if browse.is_empty() {
        return;
    }
    let names: Vec<Name> = browse
        .iter()
        .filter_map(|s| match Name::from_str(s) {
            Ok(n) => Some(n),
            Err(e) => {
                tracing::warn!(name = %s, err = %e, "invalid browse target, skipping");
                None
            }
        })
        .collect();
    if names.is_empty() {
        return;
    }

    // RFC 6762 §5.2: delay the very first query by 20–120 ms.
    tokio::select! {
        _ = sleep(first_query_jitter()) => {}
        _ = state.shutdown.cancelled() => return,
    }

    let cap = Duration::from_secs(interval_secs.max(1));
    let mut delay = Duration::from_secs(1);

    loop {
        if state.shutdown.is_cancelled() {
            return;
        }
        send_queries(&state, &names).await;

        tokio::select! {
            _ = sleep(delay) => {}
            _ = state.shutdown.cancelled() => return,
        }

        // RFC 6762 §5.2: successive intervals MUST double, capped.
        delay = (delay * 2).min(cap);
    }
}

async fn send_queries(state: &Arc<State>, names: &[Name]) {
    let mut msg = Message::new(0, MessageType::Query, OpCode::Query);
    for n in names {
        let mut q = Query::new();
        q.set_name(n.clone())
            .set_query_type(RecordType::PTR)
            .set_query_class(DNSClass::IN);
        msg.add_query(q);
    }
    let bytes = match msg.to_vec() {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!(err = %e, "browser: encode failed");
            return;
        }
    };

    for iface in &state.ifaces {
        match iface.send_mdns_all(&bytes).await {
            Ok(sent) => {
                state
                    .metrics
                    .queries_sent
                    .fetch_add(sent as u64, std::sync::atomic::Ordering::Relaxed);
            }
            Err(e) => tracing::debug!(iface = %iface.name, err = %e, "browser: send failed"),
        }
    }
}
