//! mDNS responder — handle incoming queries and emit answers, with the
//! timing rules of RFC 6762 §6, §6.3, §7.1 (Known-Answer Suppression),
//! §8.1 (Probing), §8.3 (Announcing), and §10.1 (Goodbye).

use std::sync::Arc;

use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::{DNSClass, Name, Record, RecordType};
use tokio::time::sleep;

use crate::iface::Iface;
use crate::record_key::rdata_eq;
use crate::services::Published;
use crate::state::State;
use crate::timing::{
    self, response_delay, DelayClass, ANNOUNCE_GAP, MIN_MULTICAST_INTERVAL, PROBE_DEFENSE_INTERVAL,
    PROBE_INITIAL_MAX, PROBE_INTERVAL,
};

/// Build a response message. Returns `None` if there are no answers.
fn build_response(query_id: u16, answers: &[Record]) -> Option<Vec<u8>> {
    if answers.is_empty() {
        return None;
    }
    let mut msg = Message::response(query_id, OpCode::Query);
    msg.metadata.authoritative = true;
    for a in answers {
        msg.add_answer(a.clone());
    }
    msg.to_vec().ok()
}

/// Detect whether `msg` is a probe query for one of `unique` (RFC 6762 §8.2):
/// a probe places the *proposed* records into the Authority Section. We
/// match only on `(name, record_type)` because the *whole point* of probing
/// is to discover conflicting `rdata` for a name we also claim — comparing
/// rdata would silently let conflicting probes slip past defense. The query
/// section's QU/QM bits are not consulted (some senders mis-set them); the
/// presence of authority records keyed on a name+type we own is sufficient.
pub fn is_probe_for_us(msg: &Message, unique: &[Record]) -> bool {
    if msg.authorities.is_empty() {
        return false;
    }
    msg.authorities.iter().any(|a| {
        unique
            .iter()
            .any(|u| u.name == a.name && u.record_type() == a.record_type())
    })
}

/// Apply Known-Answer Suppression (RFC 6762 §7.1): drop any of `answers`
/// that already appears in the query's Answer Section with a remaining TTL
/// of at least half of our value.
pub fn apply_known_answers(answers: &mut Vec<Record>, query_msg: &Message) {
    if query_msg.answers.is_empty() {
        return;
    }
    answers.retain(|ans| {
        !query_msg.answers.iter().any(|known| {
            known.name == ans.name
                && known.record_type() == ans.record_type()
                && rdata_eq(&known.data, &ans.data)
                && known.ttl.saturating_mul(2) >= ans.ttl
        })
    });
}

/// Inspect a parsed query message; respond on the iface it arrived on,
/// honouring randomized response delays and per-record rate limiting.
pub async fn handle_query(
    state: &Arc<State>,
    msg: &Message,
    arrival: &Arc<Iface>,
    pub_records: &Published,
) {
    if msg.metadata.message_type != MessageType::Query {
        return;
    }
    if msg.queries.is_empty() {
        return;
    }

    // Gather candidate answers.
    let mut answers: Vec<Record> = Vec::new();
    let mut all_unique = true;
    let mut any_unique = false;
    for q in &msg.queries {
        let recs = pub_records.answer(q.name(), q.query_type());
        for r in recs {
            // Strip out non-local-iface host A records.
            if r.record_type() == RecordType::A
                && !pub_records
                    .host_a_for(arrival.addr)
                    .iter()
                    .any(|hr| hr == &r)
            {
                continue;
            }
            if r.mdns_cache_flush {
                any_unique = true;
            } else {
                all_unique = false;
            }
            answers.push(r);
        }
    }

    // RFC 6762 §7.1: Known-Answer Suppression.
    apply_known_answers(&mut answers, msg);

    if answers.is_empty() {
        return;
    }

    // RFC 6762 §8.1/§8.2: a probe arrives as a query with the proposed
    // records in the Authority Section. Defenders MUST answer immediately.
    let unique_records = pub_records.unique_for_iface(arrival.addr);
    let probe_defense = is_probe_for_us(msg, &unique_records);

    let class = if probe_defense {
        DelayClass::ProbeDefense
    } else if msg.metadata.truncation {
        DelayClass::Truncated
    } else if msg.queries.len() == 1 && all_unique && any_unique {
        DelayClass::UniqueAnswer
    } else {
        DelayClass::Shared
    };

    let delay = response_delay(class);
    if !delay.is_zero() {
        sleep(delay).await;
    }

    // RFC 6762 §6: per-record-per-iface multicast rate limit. Probe defense
    // uses the reduced 250 ms interval; everything else uses 1 s.
    // `check_and_mark` is atomic so two concurrent handlers can't both
    // see the slot as free and both transmit.
    let min_iv = if probe_defense {
        PROBE_DEFENSE_INTERVAL
    } else {
        MIN_MULTICAST_INTERVAL
    };
    let ifindex = arrival.ifindex;
    answers.retain(|r| state.mc_tracker.check_and_mark(ifindex, r, min_iv));

    let bytes = match build_response(msg.metadata.id, &answers) {
        Some(b) => b,
        None => return,
    };

    if let Err(e) = arrival.send_mdns(&bytes).await {
        tracing::warn!(iface = %arrival.name, err = %e, "respond send failed");
        return;
    }
    tracing::debug!(
        iface = %arrival.name,
        bytes = bytes.len(),
        answers = answers.len(),
        ?class,
        "answered query"
    );
    state
        .metrics
        .responses
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
}

/// Build an unsolicited announcement message for `iface`.
fn build_announce(pub_records: &Published, iface: &Iface) -> Option<Vec<u8>> {
    let mut msg = Message::response(0, OpCode::Query);
    msg.metadata.authoritative = true;

    for r in pub_records.host_a_for(iface.addr) {
        msg.add_answer(r);
    }
    for s in &pub_records.services {
        msg.add_answer(s.ptr_type_to_instance.clone());
        msg.add_answer(s.ptr_meta_to_type.clone());
        msg.add_answer(s.srv.clone());
        msg.add_answer(s.txt.clone());
    }
    if msg.answers.is_empty() {
        return None;
    }
    msg.to_vec().ok()
}

/// RFC 6762 §8.1 — send three probe queries 250 ms apart on every interface,
/// preceded by a random 0–250 ms delay. Each probe carries our proposed
/// unique records in the Authority Section so simultaneous probers can
/// apply tiebreaking (§8.2). Full conflict-resolution logic is intentionally
/// out of scope; we emit the probes so peers can defer to us.
pub async fn probe_all(state: &Arc<State>, pub_records: &Published) {
    for iface in &state.ifaces {
        let unique = pub_records.unique_for_iface(iface.addr);
        if unique.is_empty() {
            continue;
        }

        // 0–250 ms initial random delay (§8.1).
        sleep(timing::jitter_0_to_max(PROBE_INITIAL_MAX)).await;

        // Names to probe — deduplicate so a host with multiple records
        // appears only once in the Question Section.
        let mut names: Vec<Name> = Vec::new();
        for r in &unique {
            if !names.iter().any(|n| n == &r.name) {
                names.push(r.name.clone());
            }
        }

        for attempt in 0..3 {
            let mut msg = Message::new(fastrand::u16(..), MessageType::Query, OpCode::Query);
            for n in &names {
                let mut q = Query::new();
                // §8.1: probes use qtype=ANY (255), qclass=IN, with the
                // unicast-response (QU) bit set so other hosts can reply
                // directly during the brief probe window.
                q.set_name(n.clone())
                    .set_query_type(RecordType::ANY)
                    .set_query_class(DNSClass::IN);
                q.set_mdns_unicast_response(true);
                msg.add_query(q);
            }
            for r in &unique {
                msg.add_authority(r.clone());
            }
            if let Ok(bytes) = msg.to_vec() {
                if let Err(e) = iface.send_mdns(&bytes).await {
                    tracing::warn!(
                        iface = %iface.name, err = %e, "probe send failed"
                    );
                    break;
                }
                tracing::debug!(
                    iface = %iface.name,
                    attempt = attempt + 1,
                    names = names.len(),
                    "probe sent"
                );
            }
            if attempt < 2 {
                sleep(PROBE_INTERVAL).await;
            }
        }
    }
}

/// RFC 6762 §8.3 — send the initial unsolicited announcement *twice*, with a
/// one-second gap. (The RFC permits up to 8 announcements with the interval
/// doubling each time; two is the minimum-compliant behaviour.)
pub async fn announce_all(state: &Arc<State>, pub_records: &Published) {
    for round in 0..2u32 {
        for iface in &state.ifaces {
            let bytes = match build_announce(pub_records, iface) {
                Some(b) => b,
                None => continue,
            };
            if let Err(e) = iface.send_mdns(&bytes).await {
                tracing::warn!(iface = %iface.name, err = %e, "announce send failed");
                continue;
            }
            for r in pub_records.unique_for_iface(iface.addr) {
                state.mc_tracker.mark(iface.ifindex, &r);
            }
        }
        if round == 0 {
            tokio::select! {
                _ = sleep(ANNOUNCE_GAP) => {}
                _ = state.shutdown.cancelled() => return,
            }
        }
    }
}

/// RFC 6762 §10.1 — send goodbye (TTL=0) packets *twice*, one second apart.
pub async fn announce_goodbye(state: &Arc<State>, pub_records: &Published) {
    let goodbye_recs = crate::services::goodbye(pub_records);
    if goodbye_recs.is_empty() {
        return;
    }
    for round in 0..2u32 {
        for iface in &state.ifaces {
            let mut msg = Message::response(0, OpCode::Query);
            msg.metadata.authoritative = true;
            for r in &goodbye_recs {
                msg.add_answer(r.clone());
            }
            if let Ok(bytes) = msg.to_vec() {
                let _ = iface.send_mdns(&bytes).await;
            }
        }
        if round == 0 {
            sleep(ANNOUNCE_GAP).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::rr::rdata::A;
    use hickory_proto::rr::RData;
    use std::net::Ipv4Addr;
    use std::str::FromStr;

    #[test]
    fn known_answer_suppresses_fresh_match() {
        let name = Name::from_str("foo.local.").unwrap();
        let mut ans = vec![Record::from_rdata(
            name.clone(),
            120,
            RData::A(A(Ipv4Addr::new(1, 2, 3, 4))),
        )];
        let mut q = Message::new(0, MessageType::Query, OpCode::Query);
        q.add_answer(Record::from_rdata(
            name,
            120, // fresh: TTL*2 >= ours
            RData::A(A(Ipv4Addr::new(1, 2, 3, 4))),
        ));
        apply_known_answers(&mut ans, &q);
        assert!(ans.is_empty());
    }

    #[test]
    fn known_answer_keeps_stale_match() {
        let name = Name::from_str("foo.local.").unwrap();
        let mut ans = vec![Record::from_rdata(
            name.clone(),
            120,
            RData::A(A(Ipv4Addr::new(1, 2, 3, 4))),
        )];
        let mut q = Message::new(0, MessageType::Query, OpCode::Query);
        q.add_answer(Record::from_rdata(
            name,
            30, // stale: 30*2 < 120
            RData::A(A(Ipv4Addr::new(1, 2, 3, 4))),
        ));
        apply_known_answers(&mut ans, &q);
        assert_eq!(ans.len(), 1);
    }

    #[test]
    fn probe_detection() {
        let name = Name::from_str("foo.local.").unwrap();
        let mut unique =
            Record::from_rdata(name.clone(), 120, RData::A(A(Ipv4Addr::new(1, 2, 3, 4))));
        unique.mdns_cache_flush = true;

        let mut probe = Message::new(0, MessageType::Query, OpCode::Query);
        let mut q = Query::new();
        q.set_name(name.clone()).set_query_type(RecordType::ANY);
        probe.add_query(q);
        probe.add_authority(unique.clone());
        assert!(is_probe_for_us(&probe, &[unique.clone()]));

        // Plain query (no authority) is not a probe.
        let mut plain = Message::new(0, MessageType::Query, OpCode::Query);
        let mut q = Query::new();
        q.set_name(name).set_query_type(RecordType::A);
        plain.add_query(q);
        assert!(!is_probe_for_us(&plain, &[unique]));
    }
}
