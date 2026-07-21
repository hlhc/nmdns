//! Daemon orchestration: builds [`State`], runs the receive loop, kicks off
//! background tasks (cache evictor, browser, signal watcher), and drives
//! graceful shutdown.

use std::sync::Arc;
use std::time::Duration;

use hickory_proto::op::{Message, MessageType};
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::Semaphore;
use tokio::time::{interval, MissedTickBehavior};
use tokio_util::sync::CancellationToken;

use crate::browser;
use crate::cache::Cache;
use crate::config::Resolved;
use crate::exit_code;
use crate::iface::{self, Datagram};
use crate::repeater;
use crate::responder;
use crate::services;
use crate::state::State;
use crate::timing;

/// Maximum number of in-flight datagram handlers. Bounds the work the
/// receive loop will fan out so a query flood can't exhaust resources.
const MAX_INFLIGHT_HANDLERS: usize = 256;

/// Run the daemon to completion. Returns the desired process exit code.
pub async fn run(cfg: Resolved) -> i32 {
    let (recv_sock, ifaces) = match iface::setup(&cfg.interfaces) {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(err = %e, "interface setup failed");
            return exit_code::INTERFACE_SETUP;
        }
    };

    let hostname = services::resolve_hostname(&cfg.hostname);
    let published = match services::build(hostname.clone(), &cfg.services, &ifaces) {
        Ok(p) => Arc::new(p),
        Err(e) => {
            tracing::error!(err = %e, "service record construction failed");
            return exit_code::SERVICE_RECORDS;
        }
    };
    tracing::info!(
        hostname = %hostname,
        ifaces = ifaces.len(),
        services = published.services.len(),
        "starting nmdns",
    );

    let state = Arc::new(State {
        cache: Cache::with_capacity_and_max_ttl(cfg.max_cache_entries, cfg.cache_max_ttl_secs),
        config: cfg,
        ifaces,
        shutdown: CancellationToken::new(),
        mc_tracker: timing::MulticastTracker::new(),
    });

    // RFC 6762 §8.1: probe for our unique records before announcing.
    responder::probe_all(&state, &published).await;

    // RFC 6762 §8.3: initial announcement (sent twice, 1 s apart).
    responder::announce_all(&state, &published).await;

    // Background tasks.
    let cache_task = tokio::spawn(cache_evictor(state.clone()));
    let browser_task = tokio::spawn(browser::run(
        state.clone(),
        state.config.browse.clone(),
        state.config.browse_interval_secs,
    ));
    let signal_task = tokio::spawn(signal_watcher(state.clone()));

    // Main receive loop runs on the current task.
    main_loop(state.clone(), recv_sock, published.clone()).await;

    // Graceful shutdown sequence.
    tracing::info!("shutting down");
    responder::announce_goodbye(&state, &published).await;

    // CancellationToken makes background tasks return cleanly; we just await
    // them with a small timeout to avoid hanging on a stuck I/O syscall.
    let drain = async {
        let _ = cache_task.await;
        let _ = browser_task.await;
        let _ = signal_task.await;
    };
    let _ = tokio::time::timeout(Duration::from_millis(200), drain).await;

    exit_code::OK
}

/// Translate SIGINT/SIGTERM into a shutdown signal.
async fn signal_watcher(state: Arc<State>) {
    let mut int = match signal(SignalKind::interrupt()) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(err = %e, "SIGINT handler failed");
            return;
        }
    };
    let mut term = match signal(SignalKind::terminate()) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(err = %e, "SIGTERM handler failed");
            return;
        }
    };
    tokio::select! {
        _ = int.recv() => tracing::info!("SIGINT received"),
        _ = term.recv() => tracing::info!("SIGTERM received"),
    }
    state.shutdown.cancel();
}

/// Periodic cache eviction.
async fn cache_evictor(state: Arc<State>) {
    let secs = state.config.cache_tick_secs.max(1);
    let mut tick = interval(Duration::from_secs(secs));
    tick.set_missed_tick_behavior(MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = state.shutdown.cancelled() => return,
            _ = tick.tick() => {}
        }
        let n = state.cache.evict_expired();
        // Sweep rate-limiter entries that have aged past the multicast interval;
        // they no longer affect rate limiting and would otherwise leak.
        state
            .mc_tracker
            .prune_older_than(timing::MIN_MULTICAST_INTERVAL);
        if n > 0 {
            tracing::debug!(evicted = n, alive = state.cache.len(), "cache swept");
        }
    }
}

/// Receive loop: dispatch each datagram to responder, cache, and (optionally) repeater.
async fn main_loop(
    state: Arc<State>,
    recv: iface::RecvSocket,
    published: Arc<services::Published>,
) {
    // Bound the number of concurrent handlers: a 400-500 ms truncated-query
    // delay must not block the receive loop, but unbounded fan-out lets a
    // single attacker amplify itself into the daemon's task budget.
    let inflight = Arc::new(Semaphore::new(MAX_INFLIGHT_HANDLERS));

    loop {
        let pkt = tokio::select! {
            r = recv.recv() => r,
            _ = state.shutdown.cancelled() => return,
        };

        let pkt = match pkt {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!(err = %e, "recv failed");
                continue;
            }
        };

        // try_acquire_owned: if we're saturated, drop the packet rather
        // than back up the receive loop.
        let permit = match inflight.clone().try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                tracing::trace!("handler queue saturated, dropping datagram");
                continue;
            }
        };

        let st = state.clone();
        let pb = published.clone();
        tokio::spawn(async move {
            let _permit = permit; // released on task completion
            handle_datagram(&st, &pb, pkt).await;
        });
    }
}

async fn handle_datagram(state: &Arc<State>, published: &Arc<services::Published>, pkt: Datagram) {
    let from = pkt.source.ip();

    // RFC 6762 §6/§11: ignore datagrams whose source UDP port is not 5353.
    if !is_mdns_source(&pkt.source) {
        tracing::trace!(src = %pkt.source, "ignoring datagram from non-5353 source port");
        return;
    }

    // Loopback prevention.
    if state.ifaces.iter().any(|i| i.has_addr(from)) {
        return;
    }

    // Source filter.
    if !state.config.allow_source(from) {
        return;
    }

    let recv_idx = repeater::identify_recv_iface(&pkt, &state.ifaces);
    if recv_idx.is_none() && !state.config.repeat {
        // We can't identify the iface and we don't intend to repeat -- ignore.
        return;
    }

    // Parse failures are still candidates for repeating since mdns-repeater
    // does so.
    match Message::from_vec(&pkt.data) {
        Ok(msg) if msg.metadata.message_type == MessageType::Query => {
            log_query(state, &msg, &pkt, recv_idx);
            handle_query_msg(state, published, &msg, recv_idx, pkt.family).await;
        }
        Ok(msg) => {
            log_response(state, &msg, &pkt, recv_idx);
            handle_response_msg(state, &msg, recv_idx);
        }
        Err(e) => {
            tracing::trace!(from = %from, err = %e, "non-DNS payload");
        }
    }

    if state.config.repeat {
        repeater::forward(state, &pkt, recv_idx).await;
    }
}

async fn handle_query_msg(
    state: &Arc<State>,
    published: &Arc<services::Published>,
    msg: &Message,
    recv_idx: Option<usize>,
    family: iface::IpFamily,
) {
    if let Some(idx) = recv_idx {
        let arrival = state.ifaces[idx].clone();
        responder::handle_query(state, msg, &arrival, family, published).await;
    }
}

fn handle_response_msg(state: &Arc<State>, msg: &Message, recv_idx: Option<usize>) {
    let source_ifindex = recv_idx.map(|idx| state.ifaces[idx].ifindex);
    let mut inserted = 0usize;
    let mut refreshed = 0usize;
    let mut goodbyes = 0usize;
    let mut rejected = 0usize;
    for ans in msg
        .answers
        .iter()
        .chain(msg.authorities.iter())
        .chain(msg.additionals.iter())
    {
        match state.cache.insert_from(ans.clone(), source_ifindex) {
            crate::cache::InsertOutcome::Inserted => inserted += 1,
            crate::cache::InsertOutcome::Refreshed => refreshed += 1,
            crate::cache::InsertOutcome::GoodbyeRemoved => goodbyes += 1,
            crate::cache::InsertOutcome::Rejected => rejected += 1,
            crate::cache::InsertOutcome::GoodbyeNoOp => {}
        }
    }
    if inserted + refreshed + goodbyes + rejected > 0 {
        tracing::debug!(
            inserted,
            refreshed,
            goodbyes,
            rejected,
            cache_size = state.cache.len(),
            "cache updated from response",
        );
    }
}

fn log_query(state: &State, msg: &Message, pkt: &Datagram, recv_idx: Option<usize>) {
    let iface = recv_idx
        .map(|i| state.ifaces[i].name.as_str())
        .unwrap_or("?");
    if tracing::enabled!(tracing::Level::TRACE) {
        for q in &msg.queries {
            tracing::trace!(
                iface,
                src = %pkt.source,
                qname = %q.name(),
                qtype = %q.query_type(),
                qclass = ?q.query_class(),
                tc = msg.metadata.truncation,
                "query",
            );
        }
    }
    tracing::debug!(
        iface,
        src = %pkt.source,
        family = ?pkt.family,
        bytes = pkt.data.len(),
        questions = msg.queries.len(),
        known_answers = msg.answers.len(),
        authorities = msg.authorities.len(),
        "query received",
    );
}

/// RFC 6762 §6/§11: a conformant mDNS node sends from UDP port 5353. Datagrams
/// from any other source port are ignored (not cached, answered, or repeated),
/// closing an injection vector where a unicast packet from an ephemeral port
/// poisons the cache or is reflected onto every monitored link.
fn is_mdns_source(source: &std::net::SocketAddr) -> bool {
    source.port() == iface::MDNS_PORT
}

fn log_response(state: &State, msg: &Message, pkt: &Datagram, recv_idx: Option<usize>) {
    let iface = recv_idx
        .map(|i| state.ifaces[i].name.as_str())
        .unwrap_or("?");
    if tracing::enabled!(tracing::Level::TRACE) {
        for r in msg
            .answers
            .iter()
            .chain(msg.authorities.iter())
            .chain(msg.additionals.iter())
        {
            tracing::trace!(
                iface,
                src = %pkt.source,
                rname = %r.name,
                rtype = %r.record_type(),
                ttl = r.ttl,
                cache_flush = r.mdns_cache_flush,
                "response record",
            );
        }
    }
    tracing::debug!(
        iface,
        src = %pkt.source,
        family = ?pkt.family,
        bytes = pkt.data.len(),
        answers = msg.answers.len(),
        authorities = msg.authorities.len(),
        additionals = msg.additionals.len(),
        "response received",
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

    fn source(port: u16) -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 5), port))
    }

    #[test]
    fn only_port_5353_is_accepted_as_mdns() {
        assert!(is_mdns_source(&source(5353)));
        assert!(
            !is_mdns_source(&source(40000)),
            "an ephemeral source port must be rejected (RFC 6762 §6/§11)"
        );
    }
}
