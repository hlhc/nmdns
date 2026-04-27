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
    for (j, iface) in state.ifaces.iter().enumerate() {
        let skip = match recv_iface_idx {
            Some(i) => j == i,
            // Fallback: skip ifaces on the same subnet as the source.
            None => iface.contains(from_ip),
        };
        if skip {
            continue;
        }
        if let Err(e) = iface.send_mdns_on(pkt.family, &pkt.data).await {
            tracing::debug!(iface = %iface.name, err = %e, "repeat send failed");
        }
    }
}

/// Find the index of the iface a packet arrived on, by ifindex (preferred)
/// or by source-subnet membership (fallback).
pub fn identify_recv_iface(pkt: &Datagram, ifaces: &[Arc<Iface>]) -> Option<usize> {
    if let Some(idx) = pkt.recv_ifindex {
        if let Some(p) = ifaces.iter().position(|i| i.ifindex == idx) {
            return Some(p);
        }
    }
    let from = pkt.source.ip();
    ifaces.iter().position(|i| i.contains(from))
}
