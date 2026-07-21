//! mDNS responder — handle incoming queries and emit answers, with the
//! timing rules of RFC 6762 §6, §6.3, §7.1 (Known-Answer Suppression),
//! §8.1 (Probing), §8.3 (Announcing), and §10.1 (Goodbye).

use std::collections::HashSet;
use std::sync::Arc;

use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::rdata::PTR;
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};
use tokio::time::sleep;

use crate::iface::{Iface, IpFamily};
use crate::record_key::RecordKey;
use crate::services::Published;
use crate::state::State;
use crate::timing::{
    self, response_delay, DelayClass, ANNOUNCE_GAP, MIN_MULTICAST_INTERVAL, PROBE_DEFENSE_INTERVAL,
    PROBE_INITIAL_MAX, PROBE_INTERVAL,
};

/// Build a response message. Returns `None` if there are no answers.
fn build_response(query_id: u16, answers: &[Record], additionals: &[Record]) -> Option<Vec<u8>> {
    if answers.is_empty() {
        return None;
    }
    let mut msg = Message::response(query_id, OpCode::Query);
    msg.metadata.authoritative = true;
    for a in answers {
        msg.add_answer(a.clone());
    }
    for a in additionals {
        msg.add_additional(a.clone());
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
                && known.data == ans.data
                && known.ttl.saturating_mul(2) >= ans.ttl
        })
    });
}

fn push_unique(out: &mut Vec<Record>, seen: &mut HashSet<RecordKey>, record: Record) {
    if seen.insert(RecordKey::of(&record)) {
        out.push(record);
    }
}

fn candidate_answers(
    state: &Arc<State>,
    msg: &Message,
    arrival: &Arc<Iface>,
    pub_records: &Published,
) -> Vec<Record> {
    let mut answers = Vec::new();
    let mut seen = HashSet::new();

    for q in &msg.queries {
        let pub_before = answers.len();
        for r in pub_records.answer(q.name(), q.query_type()) {
            // Strip out host address records that do not belong to the
            // interface where the query arrived.
            if matches!(r.record_type(), RecordType::A | RecordType::AAAA)
                && !pub_records
                    .host_records_for_iface(arrival)
                    .iter()
                    .any(|hr| hr == &r)
            {
                continue;
            }
            push_unique(&mut answers, &mut seen, r);
        }
        let from_published = answers.len() - pub_before;

        let mut from_cache = 0usize;
        if state.config.answer_from_cache {
            for r in state
                .cache
                .lookup_from_other_ifaces(q.name(), q.query_type(), arrival.ifindex)
            {
                let before = answers.len();
                push_unique(&mut answers, &mut seen, r);
                if answers.len() != before {
                    from_cache += 1;
                }
            }
        }

        if from_published + from_cache > 0 {
            tracing::debug!(
                iface = %arrival.name,
                qname = %q.name(),
                qtype = %q.query_type(),
                from_published,
                from_cache,
                "candidate answers",
            );
        }
    }

    answers
}

fn add_cached_records(
    state: &Arc<State>,
    name: &Name,
    rtype: RecordType,
    arrival_ifindex: u32,
    out: &mut Vec<Record>,
    seen: &mut HashSet<RecordKey>,
) {
    for record in state
        .cache
        .lookup_from_other_ifaces(name, rtype, arrival_ifindex)
    {
        push_unique(out, seen, record);
    }
}

fn cached_additionals(state: &Arc<State>, answers: &[Record], arrival: &Arc<Iface>) -> Vec<Record> {
    if !state.config.answer_from_cache {
        return Vec::new();
    }

    let mut additionals = Vec::new();
    let mut seen: HashSet<RecordKey> = answers.iter().map(RecordKey::of).collect();

    for answer in answers {
        if let RData::PTR(PTR(target)) = &answer.data {
            add_cached_records(
                state,
                target,
                RecordType::SRV,
                arrival.ifindex,
                &mut additionals,
                &mut seen,
            );
            add_cached_records(
                state,
                target,
                RecordType::TXT,
                arrival.ifindex,
                &mut additionals,
                &mut seen,
            );
        }
    }

    let srv_records: Vec<Record> = answers
        .iter()
        .chain(additionals.iter())
        .filter(|r| r.record_type() == RecordType::SRV)
        .cloned()
        .collect();

    for record in srv_records {
        if let RData::SRV(srv) = &record.data {
            add_cached_records(
                state,
                &srv.target,
                RecordType::A,
                arrival.ifindex,
                &mut additionals,
                &mut seen,
            );
            add_cached_records(
                state,
                &srv.target,
                RecordType::AAAA,
                arrival.ifindex,
                &mut additionals,
                &mut seen,
            );
        }
    }

    additionals
}

fn answer_uniqueness(answers: &[Record]) -> (bool, bool) {
    let any_unique = answers.iter().any(|r| r.mdns_cache_flush);
    let all_unique = answers.iter().all(|r| r.mdns_cache_flush);
    (all_unique, any_unique)
}

/// Choose the randomized-response delay class for a query (RFC 6762 §6). The
/// zero-delay `UniqueAnswer` fast path is reserved for single-question queries
/// answered entirely with records we own outright (cache-flush set); records
/// relayed from cache have their cache-flush bit cleared, so they correctly
/// fall through to the jittered `Shared` class.
fn classify_delay(msg: &Message, answers: &[Record], probe_defense: bool) -> DelayClass {
    let (all_unique, any_unique) = answer_uniqueness(answers);
    if probe_defense {
        DelayClass::ProbeDefense
    } else if msg.metadata.truncation {
        DelayClass::Truncated
    } else if msg.queries.len() == 1 && all_unique && any_unique {
        DelayClass::UniqueAnswer
    } else {
        DelayClass::Shared
    }
}

/// Inspect a parsed query message; respond on the iface it arrived on,
/// honouring randomized response delays and per-record rate limiting.
pub async fn handle_query(
    state: &Arc<State>,
    msg: &Message,
    arrival: &Arc<Iface>,
    arrival_family: IpFamily,
    pub_records: &Published,
) {
    if msg.metadata.message_type != MessageType::Query {
        return;
    }
    if msg.queries.is_empty() {
        return;
    }

    // Gather candidate answers from published records and, when enabled,
    // from records learned on other interfaces.
    let mut answers = candidate_answers(state, msg, arrival, pub_records);

    // RFC 6762 §7.1: Known-Answer Suppression.
    apply_known_answers(&mut answers, msg);

    if answers.is_empty() {
        return;
    }

    let mut additionals = cached_additionals(state, &answers, arrival);

    // RFC 6762 §8.1/§8.2: a probe arrives as a query with the proposed
    // records in the Authority Section. Defenders MUST answer immediately.
    let unique_records = pub_records.unique_for_iface(arrival);
    let probe_defense = is_probe_for_us(msg, &unique_records);

    let class = classify_delay(msg, &answers, probe_defense);

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
    additionals.retain(|r| state.mc_tracker.check_and_mark(ifindex, r, min_iv));

    let bytes = match build_response(msg.metadata.id, &answers, &additionals) {
        Some(b) => b,
        None => return,
    };

    if let Err(e) = arrival.send_mdns_on(arrival_family, &bytes).await {
        tracing::warn!(iface = %arrival.name, err = %e, "respond send failed");
        return;
    }
    tracing::debug!(
        iface = %arrival.name,
        bytes = bytes.len(),
        answers = answers.len(),
        additionals = additionals.len(),
        ?class,
        "answered query"
    );
}

/// Build an unsolicited announcement message for `iface`.
fn build_announce(pub_records: &Published, iface: &Iface) -> Option<Vec<u8>> {
    let mut msg = Message::response(0, OpCode::Query);
    msg.metadata.authoritative = true;

    for r in pub_records.host_records_for_iface(iface) {
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
        let unique = pub_records.unique_for_iface(iface);
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
            for r in pub_records.unique_for_iface(iface) {
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
    use hickory_proto::rr::rdata::{A, AAAA, SRV, TXT};
    use hickory_proto::rr::RData;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::str::FromStr;
    use std::sync::OnceLock;
    use tokio_util::sync::CancellationToken;

    use crate::cache::Cache;
    use crate::config::Resolved;
    use crate::iface::IfaceV4;

    fn fake_iface(name: &str, ip: [u8; 4], ifindex: u32) -> Arc<Iface> {
        static RT: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
        let rt = RT.get_or_init(|| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("test runtime")
        });
        let std_sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        std_sock.set_nonblocking(true).unwrap();
        let send = rt.block_on(async { tokio::net::UdpSocket::from_std(std_sock).unwrap() });
        let addr = Ipv4Addr::from(ip);
        Arc::new(Iface {
            name: name.into(),
            ifindex,
            v4: Some(IfaceV4 {
                addr,
                mask: Ipv4Addr::new(255, 255, 255, 0),
                net: Ipv4Addr::from([ip[0], ip[1], ip[2], 0]),
                send,
            }),
            v6: None,
        })
    }

    fn test_state(ifaces: Vec<Arc<Iface>>, answer_from_cache: bool) -> Arc<State> {
        let cfg = Resolved::parse(&format!(
            r#"
interfaces = ["test0"]
answer_from_cache = {answer_from_cache}
"#
        ))
        .unwrap();
        Arc::new(State {
            config: cfg,
            ifaces,
            cache: Cache::new(),
            shutdown: CancellationToken::new(),
            mc_tracker: timing::MulticastTracker::new(),
        })
    }

    fn query(name: &str, rtype: RecordType) -> Message {
        let mut msg = Message::new(0, MessageType::Query, OpCode::Query);
        let mut q = Query::new();
        q.set_name(Name::from_str(name).unwrap())
            .set_query_type(rtype)
            .set_query_class(DNSClass::IN);
        msg.add_query(q);
        msg
    }

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

    #[test]
    fn cache_relayed_answers_clear_cache_flush_bit() {
        let trusted = fake_iface("trusted", [192, 168, 10, 1], 10);
        let iot = fake_iface("iot", [192, 168, 20, 1], 20);
        let state = test_state(vec![trusted.clone(), iot.clone()], true);
        let published = Published {
            hostname: Name::from_str("router.local.").unwrap(),
            host_a: Vec::new(),
            host_aaaa: Vec::new(),
            services: Vec::new(),
        };
        // A record learned from a peer that owns it (cache-flush set).
        let mut owned_by_peer = Record::from_rdata(
            Name::from_str("printer.local.").unwrap(),
            120,
            RData::A(A(Ipv4Addr::new(192, 168, 20, 50))),
        );
        owned_by_peer.mdns_cache_flush = true;
        state.cache.insert_from(owned_by_peer, Some(iot.ifindex));

        let msg = query("printer.local.", RecordType::A);
        let answers = candidate_answers(&state, &msg, &trusted, &published);
        assert_eq!(answers.len(), 1);
        assert!(
            !answers[0].mdns_cache_flush,
            "a relayed cache record must not assert ownership on another link"
        );
    }

    #[test]
    fn cache_relayed_single_answer_is_jittered_not_zero_delay() {
        let name = Name::from_str("printer.local.").unwrap();
        let msg = query("printer.local.", RecordType::A);

        // Single-question answer we do NOT own (cache-flush cleared): must use
        // the Shared 20-120ms jitter, not the zero-delay UniqueAnswer path.
        let relayed = vec![Record::from_rdata(
            name.clone(),
            120,
            RData::A(A(Ipv4Addr::new(1, 2, 3, 4))),
        )];
        assert!(matches!(
            classify_delay(&msg, &relayed, false),
            DelayClass::Shared
        ));

        // An owned unique record (cache-flush set) still takes the fast path.
        let mut owned = relayed.clone();
        owned[0].mdns_cache_flush = true;
        assert!(matches!(
            classify_delay(&msg, &owned, false),
            DelayClass::UniqueAnswer
        ));
    }

    #[test]
    fn cached_answers_only_use_records_from_other_ifaces() {
        let trusted = fake_iface("trusted", [192, 168, 10, 1], 10);
        let iot = fake_iface("iot", [192, 168, 20, 1], 20);
        let state = test_state(vec![trusted.clone(), iot.clone()], true);
        let published = Published {
            hostname: Name::from_str("router.local.").unwrap(),
            host_a: Vec::new(),
            host_aaaa: Vec::new(),
            services: Vec::new(),
        };
        state.cache.insert_from(
            Record::from_rdata(
                Name::from_str("printer.local.").unwrap(),
                120,
                RData::A(A(Ipv4Addr::new(192, 168, 20, 50))),
            ),
            Some(iot.ifindex),
        );

        let msg = query("printer.local.", RecordType::A);
        let trusted_answers = candidate_answers(&state, &msg, &trusted, &published);
        assert_eq!(trusted_answers.len(), 1);

        let iot_answers = candidate_answers(&state, &msg, &iot, &published);
        assert!(iot_answers.is_empty());
    }

    #[test]
    fn cached_ptr_answers_include_srv_txt_and_address_additionals() {
        let trusted = fake_iface("trusted", [192, 168, 10, 1], 10);
        let iot = fake_iface("iot", [192, 168, 20, 1], 20);
        let state = test_state(vec![trusted.clone(), iot.clone()], true);
        let published = Published {
            hostname: Name::from_str("router.local.").unwrap(),
            host_a: Vec::new(),
            host_aaaa: Vec::new(),
            services: Vec::new(),
        };

        let service_type = Name::from_str("_ipp._tcp.local.").unwrap();
        let instance = Name::from_str("Office-Printer._ipp._tcp.local.").unwrap();
        let target = Name::from_str("printer.local.").unwrap();

        state.cache.insert_from(
            Record::from_rdata(
                service_type.clone(),
                4500,
                RData::PTR(PTR(instance.clone())),
            ),
            Some(iot.ifindex),
        );
        state.cache.insert_from(
            Record::from_rdata(
                instance.clone(),
                120,
                RData::SRV(SRV::new(0, 0, 631, target.clone())),
            ),
            Some(iot.ifindex),
        );
        state.cache.insert_from(
            Record::from_rdata(
                instance,
                4500,
                RData::TXT(TXT::new(vec!["rp=ipp/print".into()])),
            ),
            Some(iot.ifindex),
        );
        state.cache.insert_from(
            Record::from_rdata(target, 120, RData::A(A(Ipv4Addr::new(192, 168, 20, 50)))),
            Some(iot.ifindex),
        );
        state.cache.insert_from(
            Record::from_rdata(
                Name::from_str("printer.local.").unwrap(),
                120,
                RData::AAAA(AAAA(Ipv6Addr::from(
                    0xfe80_0000_0000_0000_0000_0000_0000_0050u128,
                ))),
            ),
            Some(iot.ifindex),
        );

        let msg = query("_ipp._tcp.local.", RecordType::PTR);
        let answers = candidate_answers(&state, &msg, &trusted, &published);
        let additionals = cached_additionals(&state, &answers, &trusted);

        assert_eq!(answers.len(), 1);
        assert!(additionals
            .iter()
            .any(|r| r.record_type() == RecordType::SRV));
        assert!(additionals
            .iter()
            .any(|r| r.record_type() == RecordType::TXT));
        assert!(additionals.iter().any(|r| r.record_type() == RecordType::A));
        assert!(additionals
            .iter()
            .any(|r| r.record_type() == RecordType::AAAA));
    }
}
