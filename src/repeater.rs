//! Cross-interface mDNS repeater (mdns-repeater behaviour).
//!
//! Forwards every monitored datagram to all *other* monitored interfaces.
//! This is a best-effort fallback for clients that don't speak DNS-SD
//! correctly across subnets; the responder covers the daemon's own services.

use std::net::IpAddr;
use std::sync::Arc;

use crate::iface::{Datagram, Iface};
use crate::state::State;

/// Decide which interface indices a datagram should be forwarded to.
///
///   * Known ingress (`recv_idx = Some`): every *other* interface.
///   * Unknown ingress: only usable as a subnet fallback. Forward to the
///     interfaces whose subnet does *not* contain the source — but only when
///     the source is on some monitored subnet at all. A source on no monitored
///     subnet (e.g. an off-link unicast to :5353, or a link-local v6 packet we
///     could not attribute) is NOT reflected anywhere: blindly forwarding it to
///     every interface would inject off-link traffic and, for a source that is
///     actually on-link, echo the packet back onto its own segment.
pub fn forward_targets(
    recv_idx: Option<usize>,
    source: IpAddr,
    ifaces: &[Arc<Iface>],
) -> Vec<usize> {
    match recv_idx {
        Some(i) => (0..ifaces.len()).filter(|&j| j != i).collect(),
        None => {
            if ifaces.iter().any(|iface| iface.contains(source)) {
                (0..ifaces.len())
                    .filter(|&j| !ifaces[j].contains(source))
                    .collect()
            } else {
                Vec::new()
            }
        }
    }
}

/// Forward `pkt` to every iface that is *not* the receiving iface.
pub async fn forward(state: &Arc<State>, pkt: &Datagram, recv_iface_idx: Option<usize>) {
    let from_ip = pkt.source.ip();
    let recv_name = recv_iface_idx.map(|i| state.ifaces[i].name.as_str());
    let targets = forward_targets(recv_iface_idx, from_ip, &state.ifaces);
    let skipped = state.ifaces.len() - targets.len();
    let mut forwarded = 0usize;

    for j in targets {
        let iface = &state.ifaces[j];
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
    // Link-local IPv6 sources share fe80::/64 on every interface, so a subnet
    // match cannot disambiguate the arrival link. Trust only the PKTINFO
    // ifindex for them rather than mis-attributing to the first interface.
    if matches!(from, IpAddr::V6(ip) if ip.is_unicast_link_local()) {
        tracing::trace!(src = %from, "link-local v6 source; not subnet-guessing recv iface");
        return None;
    }
    let p = ifaces.iter().position(|i| i.contains(from));
    if p.is_none() {
        tracing::trace!(src = %from, "could not identify recv iface");
    }
    p
}
