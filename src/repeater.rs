//! Cross-interface mDNS repeater (mdns-repeater behaviour).
//!
//! Forwards every monitored datagram to all *other* monitored interfaces.
//! This is a best-effort fallback for clients that don't speak DNS-SD
//! correctly across subnets; the responder covers the daemon's own services.

use std::sync::Arc;

use crate::iface::{Datagram, Iface};
use crate::state::State;

/// Forward `pkt` to every iface that is *not* the receiving iface.
pub async fn forward(state: &Arc<State>, pkt: &Datagram, recv_iface_idx: Option<usize>) {
    let from_ip = pkt.source.ip();
    let recv_name = recv_iface_idx.map(|i| state.ifaces[i].name.as_str());
    let mut forwarded = 0usize;
    let mut skipped = 0usize;

    for (j, iface) in state.ifaces.iter().enumerate() {
        let skip = match recv_iface_idx {
            Some(i) => j == i,
            // Fallback: skip ifaces on the same subnet as the source.
            None => iface.contains(from_ip),
        };
        if skip {
            skipped += 1;
            continue;
        }
        match iface.send_mdns_on(pkt.family, &pkt.data).await {
            Ok(n) => {
                forwarded += 1;
                tracing::trace!(
                    out = %iface.name,
                    src = %from_ip,
                    family = ?pkt.family,
                    bytes = n,
                    "repeated datagram",
                );
            }
            Err(e) => tracing::debug!(
                out = %iface.name,
                err = %e,
                "repeat send failed",
            ),
        }
    }

    tracing::debug!(
        recv = recv_name.unwrap_or("?"),
        src = %from_ip,
        family = ?pkt.family,
        bytes = pkt.data.len(),
        forwarded,
        skipped,
        "repeater forward",
    );
}

/// Find the index of the iface a packet arrived on, by ifindex (preferred)
/// or by source-subnet membership (fallback).
pub fn identify_recv_iface(pkt: &Datagram, ifaces: &[Arc<Iface>]) -> Option<usize> {
    if let Some(idx) = pkt.recv_ifindex {
        if let Some(p) = ifaces.iter().position(|i| i.ifindex == idx) {
            return Some(p);
        }
        tracing::trace!(
            ifindex = idx,
            "recv ifindex not in monitored set; falling back to subnet match",
        );
    }
    let from = pkt.source.ip();
    let p = ifaces.iter().position(|i| i.contains(from));
    if p.is_none() {
        tracing::trace!(src = %from, "could not identify recv iface");
    }
    p
}
