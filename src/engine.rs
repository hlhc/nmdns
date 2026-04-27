//! Daemon orchestration: builds [`State`], runs the receive loop, kicks off
//! background tasks (cache evictor, browser, signal watcher), and drives
//! graceful shutdown.

use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use hickory_proto::op::{Message, MessageType};
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::Semaphore;
use tokio::time::{interval, MissedTickBehavior};
use tokio_util::sync::CancellationToken;

use crate::cache::{Cache, InsertOutcome};
use crate::config::Resolved;
use crate::exit_code;
use crate::iface::{self, Datagram};
use crate::repeater;
use crate::responder;
use crate::services;
use crate::state::{Metrics, State};
use crate::timing;
use crate::browser;

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
        cache: Cache::with_capacity(cfg.max_cache_entries),
        config: cfg,
        ifaces,
        metrics: Metrics::default(),
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

    log_metrics(&state);
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
        if n > 0 {
            state
                .metrics
                .cache_evicted
                .fetch_add(n as u64, Ordering::Relaxed);
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
    let from = *pkt.source.ip();

    // Loopback prevention.
    if state.ifaces.iter().any(|i| i.addr == from) {
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
            handle_query_msg(state, published, &msg, recv_idx).await;
        }
        Ok(msg) => handle_response_msg(state, &msg),
        Err(e) => {
            state.metrics.parse_errors.fetch_add(1, Ordering::Relaxed);
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
) {
    state
        .metrics
        .queries_received
        .fetch_add(1, Ordering::Relaxed);
    if let Some(idx) = recv_idx {
        let arrival = state.ifaces[idx].clone();
        responder::handle_query(state, msg, &arrival, published).await;
    }
}

fn handle_response_msg(state: &Arc<State>, msg: &Message) {
    for ans in msg.answers.iter().chain(msg.additionals.iter()) {
        match state.cache.insert(ans.clone()) {
            InsertOutcome::GoodbyeRemoved => {
                state.metrics.cache_goodbyes.fetch_add(1, Ordering::Relaxed);
            }
            InsertOutcome::Rejected => {
                state.metrics.cache_rejected.fetch_add(1, Ordering::Relaxed);
            }
            InsertOutcome::Inserted | InsertOutcome::Refreshed | InsertOutcome::GoodbyeNoOp => {}
        }
    }
}

fn log_metrics(state: &State) {
    tracing::info!(
        queries_received = state.metrics.queries_received.load(Ordering::Relaxed),
        queries_sent = state.metrics.queries_sent.load(Ordering::Relaxed),
        responses = state.metrics.responses.load(Ordering::Relaxed),
        repeated = state.metrics.repeated.load(Ordering::Relaxed),
        cache_evicted = state.metrics.cache_evicted.load(Ordering::Relaxed),
        cache_goodbyes = state.metrics.cache_goodbyes.load(Ordering::Relaxed),
        cache_rejected = state.metrics.cache_rejected.load(Ordering::Relaxed),
        parse_errors = state.metrics.parse_errors.load(Ordering::Relaxed),
        cache_size = state.cache.len(),
        "session stats"
    );
}
