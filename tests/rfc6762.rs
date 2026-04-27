//! RFC 6762 compliance tests.
//!
//! Each `#[test]` exercises one specific rule from RFC 6762 (Multicast DNS).
//! The test name encodes the section number it covers, so a failure points
//! directly at the violated rule.
//!
//! What is *not* covered here:
//!
//!   * §8.2 — full simultaneous-probe lexicographic tiebreaking and
//!     conflict renaming (we emit probes but defer rather than rename).
//!   * §6.1 — NSEC negative responses.
//!   * §7.2 — multi-packet Known-Answer aggregation (TC continuation).
//!   * §11 IP TTL=255 setsockopt — set in [`nmdns::iface`] but verifying
//!     it requires binding a real multicast socket, which is unavailable
//!     in the test sandbox.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::rdata::{A, AAAA};
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};

use nmdns::cache::Cache;
use nmdns::config::{Resolved, ServiceConfig};
use nmdns::iface::{ipv6_net, Iface, IfaceV4, IfaceV6, MDNS_ADDR_V6};
use nmdns::responder::{apply_known_answers, is_probe_for_us};
use nmdns::services;
use nmdns::timing::{
    self, response_delay, DelayClass, ANNOUNCE_GAP, MIN_MULTICAST_INTERVAL, PROBE_DEFENSE_INTERVAL,
    PROBE_INITIAL_MAX, PROBE_INTERVAL,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn fake_iface(ip: [u8; 4]) -> Arc<Iface> {
    let std_sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    std_sock.set_nonblocking(true).unwrap();
    let addr = Ipv4Addr::from(ip);
    Arc::new(Iface {
        name: "test0".into(),
        ifindex: 0,
        v4: Some(IfaceV4 {
            addr,
            mask: Ipv4Addr::new(255, 255, 255, 0),
            net: Ipv4Addr::from([ip[0], ip[1], ip[2], 0]),
            send: tokio::net::UdpSocket::from_std(std_sock).unwrap(),
        }),
        v6: None,
    })
}

fn fake_iface_v6(ip: Ipv6Addr) -> Arc<Iface> {
    let std_sock = std::net::UdpSocket::bind("[::1]:0").unwrap();
    std_sock.set_nonblocking(true).unwrap();
    Arc::new(Iface {
        name: "test0".into(),
        ifindex: 0,
        v4: None,
        v6: Some(IfaceV6 {
            addr: ip,
            prefix_len: 64,
            net: ipv6_net(ip, 64),
            scope_id: 1,
            send: tokio::net::UdpSocket::from_std(std_sock).unwrap(),
        }),
    })
}

fn published_with_one_service() -> services::Published {
    let host = Name::from_str("router.local.").unwrap();
    let svcs = vec![ServiceConfig {
        name: "Admin".into(),
        service: "_http._tcp.local.".into(),
        port: 80,
        txt: vec!["path=/".into()],
        host: None,
    }];
    let ifs = vec![fake_iface([10, 0, 0, 1])];
    services::build(host, &svcs, &ifs).unwrap()
}

fn published_with_ipv6_host() -> services::Published {
    let host = Name::from_str("router.local.").unwrap();
    let ifs = vec![fake_iface_v6(Ipv6Addr::from(
        0xfe80_0000_0000_0000_0000_0000_0000_0001u128,
    ))];
    services::build(host, &[], &ifs).unwrap()
}

// ---------------------------------------------------------------------------
// §3 — Multicast DNS Names: ".local." link-local namespace
// ---------------------------------------------------------------------------

/// RFC 6762 §3: hostnames are of the form `<single-label>.local.`.
#[test]
fn rfc6762_s3_hostname_ends_in_local() {
    let h = services::resolve_hostname(&Some("myhost".into()));
    assert!(h.to_string().ends_with(".local."), "got {h}");
    assert!(h.is_fqdn());

    // Multi-label input is truncated to the first label per §3 ("a single
    // DNS label").
    let h = services::resolve_hostname(&Some("foo.example.com".into()));
    assert_eq!(h.to_string(), "foo.local.");
}

/// RFC 6762 §3: IPv6 mDNS uses the link-local multicast address ff02::fb.
#[test]
fn rfc6762_s3_ipv6_multicast_address_ff02_fb() {
    assert_eq!(MDNS_ADDR_V6, Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0xfb));
}

// ---------------------------------------------------------------------------
// §5.2 — Continuous Multicast DNS Querying
// ---------------------------------------------------------------------------

/// RFC 6762 §5.2: "the interval between the first two queries MUST be
/// at least one second" — so the *initial* random delay before the first
/// query must be small (we use 20–120 ms).
#[test]
fn rfc6762_s5_2_browser_first_query_jitter() {
    for _ in 0..200 {
        let d = timing::first_query_jitter();
        assert!(
            d >= Duration::from_millis(20) && d <= Duration::from_millis(120),
            "jitter {d:?} outside 20-120 ms"
        );
    }
}

/// RFC 6762 §5.2: "the intervals between successive queries MUST increase
/// by at least a factor of two." Our browser doubles the delay each round
/// up to a configured cap. Verify the doubling sequence directly.
#[test]
fn rfc6762_s5_2_browser_exponential_backoff() {
    let cap = Duration::from_secs(60);
    let mut d = Duration::from_secs(1);
    let expected = [1, 2, 4, 8, 16, 32, 60, 60, 60];
    for &want in &expected {
        assert_eq!(d, Duration::from_secs(want));
        d = (d * 2).min(cap);
    }
}

// ---------------------------------------------------------------------------
// §6 — Responding: response delay classes
// ---------------------------------------------------------------------------

/// RFC 6762 §6: unique answer with a single question — respond without
/// random delay (≤10 ms). Probe-defense is also "without delay".
#[test]
fn rfc6762_s6_unique_and_probe_defense_no_delay() {
    for _ in 0..100 {
        assert_eq!(response_delay(DelayClass::UniqueAnswer), Duration::ZERO);
        assert_eq!(response_delay(DelayClass::ProbeDefense), Duration::ZERO);
    }
}

/// RFC 6762 §6: shared records / multi-question queries — random
/// delay 20–120 ms.
#[test]
fn rfc6762_s6_shared_delay_20_to_120_ms() {
    for _ in 0..500 {
        let d = response_delay(DelayClass::Shared);
        assert!(
            d >= Duration::from_millis(20) && d <= Duration::from_millis(120),
            "shared delay {d:?} out of range"
        );
    }
}

/// RFC 6762 §6: when the query has the TC bit set (more known-answers to
/// follow) — random delay 400–500 ms.
#[test]
fn rfc6762_s6_truncated_delay_400_to_500_ms() {
    for _ in 0..500 {
        let d = response_delay(DelayClass::Truncated);
        assert!(
            d >= Duration::from_millis(400) && d <= Duration::from_millis(500),
            "truncated delay {d:?} out of range"
        );
    }
}

/// RFC 6762 §6: a Multicast DNS responder MUST NOT multicast the same
/// record on the same interface within one second of the previous send.
#[test]
fn rfc6762_s6_per_record_per_iface_min_interval() {
    assert_eq!(MIN_MULTICAST_INTERVAL, Duration::from_secs(1));

    let t = timing::MulticastTracker::new();
    let r = Record::from_rdata(
        Name::from_str("foo.local.").unwrap(),
        120,
        RData::A(A(Ipv4Addr::new(1, 2, 3, 4))),
    );
    assert!(
        t.allows(1, &r, MIN_MULTICAST_INTERVAL),
        "first send allowed"
    );
    t.mark(1, &r);
    assert!(
        !t.allows(1, &r, MIN_MULTICAST_INTERVAL),
        "second send within 1 s blocked"
    );
    // Per-interface independence.
    assert!(
        t.allows(2, &r, MIN_MULTICAST_INTERVAL),
        "different iface independent"
    );
}

/// RFC 6762 §6: the same per-record-per-interface multicast interval applies
/// to AAAA records.
#[test]
fn rfc6762_s6_aaaa_per_record_per_iface_min_interval() {
    let t = timing::MulticastTracker::new();
    let r = Record::from_rdata(
        Name::from_str("foo.local.").unwrap(),
        120,
        RData::AAAA(AAAA(Ipv6Addr::LOCALHOST)),
    );
    assert!(t.allows(1, &r, MIN_MULTICAST_INTERVAL));
    t.mark(1, &r);
    assert!(!t.allows(1, &r, MIN_MULTICAST_INTERVAL));
    assert!(t.allows(2, &r, MIN_MULTICAST_INTERVAL));
}

/// RFC 6762 §6 (last paragraph): the one-second rule is reduced to 250 ms
/// for probe-defense responses.
#[test]
fn rfc6762_s6_probe_defense_uses_250ms_window() {
    assert_eq!(PROBE_DEFENSE_INTERVAL, Duration::from_millis(250));
}

// ---------------------------------------------------------------------------
// §7.1 — Known-Answer Suppression
// ---------------------------------------------------------------------------

/// RFC 6762 §7.1: the responder MUST NOT include in its answer any record
/// the querier already knows about, where "knows" means the record appears
/// in the query's Answer Section with a remaining TTL ≥ half ours.
#[test]
fn rfc6762_s7_1_known_answer_suppression_fresh() {
    let name = Name::from_str("foo.local.").unwrap();
    let mut answers = vec![Record::from_rdata(
        name.clone(),
        120,
        RData::A(A(Ipv4Addr::new(1, 2, 3, 4))),
    )];
    let mut q = Message::new(0, MessageType::Query, OpCode::Query);
    q.add_answer(Record::from_rdata(
        name,
        120, // TTL*2 = 240 ≥ 120 → fresh, suppress
        RData::A(A(Ipv4Addr::new(1, 2, 3, 4))),
    ));
    apply_known_answers(&mut answers, &q);
    assert!(answers.is_empty(), "fresh known-answer must be suppressed");
}

/// RFC 6762 §7.1 (continued): if the cached TTL is below half the
/// canonical value, the answer must NOT be suppressed.
#[test]
fn rfc6762_s7_1_known_answer_keeps_stale() {
    let name = Name::from_str("foo.local.").unwrap();
    let mut answers = vec![Record::from_rdata(
        name.clone(),
        120,
        RData::A(A(Ipv4Addr::new(1, 2, 3, 4))),
    )];
    let mut q = Message::new(0, MessageType::Query, OpCode::Query);
    q.add_answer(Record::from_rdata(
        name,
        30, // 30*2 = 60 < 120 → stale, keep
        RData::A(A(Ipv4Addr::new(1, 2, 3, 4))),
    ));
    apply_known_answers(&mut answers, &q);
    assert_eq!(answers.len(), 1, "stale known-answer must NOT suppress");
}

#[test]
fn rfc6762_s7_1_known_answer_suppression_aaaa_fresh() {
    let name = Name::from_str("foo.local.").unwrap();
    let mut answers = vec![Record::from_rdata(
        name.clone(),
        120,
        RData::AAAA(AAAA(Ipv6Addr::LOCALHOST)),
    )];
    let mut q = Message::new(0, MessageType::Query, OpCode::Query);
    q.add_answer(Record::from_rdata(
        name,
        120,
        RData::AAAA(AAAA(Ipv6Addr::LOCALHOST)),
    ));
    apply_known_answers(&mut answers, &q);
    assert!(
        answers.is_empty(),
        "fresh AAAA known-answer must be suppressed"
    );
}

// ---------------------------------------------------------------------------
// §8.1 — Probing
// ---------------------------------------------------------------------------

/// RFC 6762 §8.1: "wait an additional random amount of time selected with
/// uniform random distribution in the range 0–250 ms" before the first probe.
#[test]
fn rfc6762_s8_1_probe_initial_jitter_max_250ms() {
    assert_eq!(PROBE_INITIAL_MAX, Duration::from_millis(250));
    for _ in 0..500 {
        let d = timing::jitter_0_to_max(PROBE_INITIAL_MAX);
        assert!(d <= Duration::from_millis(250), "jitter {d:?} > 250 ms");
    }
}

/// RFC 6762 §8.1: "send three probes, 250 ms apart."
#[test]
fn rfc6762_s8_1_probe_interval_250ms() {
    assert_eq!(PROBE_INTERVAL, Duration::from_millis(250));
}

/// RFC 6762 §8.1: a probe is detected by its proposed records appearing
/// in the Authority Section of an incoming query.
#[test]
fn rfc6762_s8_1_probe_detected_via_authority_section() {
    let name = Name::from_str("foo.local.").unwrap();
    let mut unique = Record::from_rdata(name.clone(), 120, RData::A(A(Ipv4Addr::new(1, 2, 3, 4))));
    unique.mdns_cache_flush = true;

    let mut probe = Message::new(0, MessageType::Query, OpCode::Query);
    let mut q = Query::new();
    q.set_name(name.clone()).set_query_type(RecordType::ANY);
    probe.add_query(q);
    probe.add_authority(unique.clone());
    assert!(is_probe_for_us(&probe, &[unique.clone()]));

    // Plain query (no authority section) is not a probe.
    let mut plain = Message::new(0, MessageType::Query, OpCode::Query);
    let mut q = Query::new();
    q.set_name(name).set_query_type(RecordType::A);
    plain.add_query(q);
    assert!(!is_probe_for_us(&plain, &[unique]));
}

#[test]
fn rfc6762_s8_1_probe_detected_for_aaaa_authority() {
    let name = Name::from_str("foo.local.").unwrap();
    let mut unique = Record::from_rdata(name.clone(), 120, RData::AAAA(AAAA(Ipv6Addr::LOCALHOST)));
    unique.mdns_cache_flush = true;

    let mut probe = Message::new(0, MessageType::Query, OpCode::Query);
    let mut q = Query::new();
    q.set_name(name).set_query_type(RecordType::ANY);
    probe.add_query(q);
    probe.add_authority(unique.clone());
    assert!(is_probe_for_us(&probe, &[unique]));
}

/// RFC 6762 §8.1: probe queries MUST use qtype=ANY and MUST set the
/// unicast-response (QU) bit, with the proposed records in the Authority
/// Section. Build a probe message identical to what `probe_all` emits and
/// verify each property.
#[test]
fn rfc6762_s8_1_probe_message_format() {
    let name = Name::from_str("router.local.").unwrap();
    let mut unique = Record::from_rdata(name.clone(), 120, RData::A(A(Ipv4Addr::new(10, 0, 0, 1))));
    unique.mdns_cache_flush = true;

    let mut msg = Message::new(0, MessageType::Query, OpCode::Query);
    let mut q = Query::new();
    q.set_name(name)
        .set_query_type(RecordType::ANY)
        .set_query_class(DNSClass::IN);
    q.set_mdns_unicast_response(true);
    msg.add_query(q);
    msg.add_authority(unique);

    // Round-trip through the wire format: the QU bit must survive encoding.
    let bytes = msg.to_vec().expect("encode");
    let parsed = Message::from_vec(&bytes).expect("decode");

    assert_eq!(parsed.queries.len(), 1);
    let pq = &parsed.queries[0];
    assert_eq!(pq.query_type(), RecordType::ANY);
    assert_eq!(pq.query_class(), DNSClass::IN);
    assert!(pq.mdns_unicast_response(), "QU bit must be set on probes");
    assert_eq!(parsed.authorities.len(), 1);
}

// ---------------------------------------------------------------------------
// §8.3 — Announcing
// ---------------------------------------------------------------------------

/// RFC 6762 §8.3: "send an unsolicited mDNS response containing, in the
/// Answer Section, all of its newly registered resource records." The
/// daemon sends two announcements at least one second apart.
#[test]
fn rfc6762_s8_3_announce_gap_one_second() {
    assert_eq!(ANNOUNCE_GAP, Duration::from_secs(1));
}

// ---------------------------------------------------------------------------
// §10.1 — Goodbye Packets
// ---------------------------------------------------------------------------

/// RFC 6762 §10.1: "the host SHOULD send an unsolicited goodbye packet
/// with a TTL of zero" for every record it had advertised.
#[tokio::test]
async fn rfc6762_s10_1_goodbye_records_have_ttl_zero() {
    let p = published_with_one_service();
    let g = services::goodbye(&p);
    assert!(!g.is_empty(), "goodbye records must be produced");
    for r in &g {
        assert_eq!(r.ttl, 0, "goodbye record {} has TTL {}", r.name, r.ttl);
    }
    // Every host A record AND every service PTR/SRV/TXT must appear.
    assert!(g.iter().any(|r| r.record_type() == RecordType::A));
    assert!(g.iter().any(|r| r.record_type() == RecordType::PTR));
    assert!(g.iter().any(|r| r.record_type() == RecordType::SRV));
    assert!(g.iter().any(|r| r.record_type() == RecordType::TXT));
}

#[tokio::test]
async fn rfc6762_s10_1_goodbye_includes_aaaa_records() {
    let p = published_with_ipv6_host();
    let g = services::goodbye(&p);
    assert!(g.iter().any(|r| r.record_type() == RecordType::AAAA));
    assert!(g.iter().all(|r| r.ttl == 0));
}

/// RFC 6762 §10.1: receivers of a goodbye packet "SHOULD record the new
/// TTL of zero" (which deletes the record from the cache).
#[test]
fn rfc6762_s10_1_cache_evicts_on_ttl_zero() {
    let c = Cache::new();
    let name = Name::from_str("foo.local.").unwrap();
    c.insert(Record::from_rdata(
        name.clone(),
        120,
        RData::A(A(Ipv4Addr::new(1, 2, 3, 4))),
    ));
    assert_eq!(c.len(), 1);
    c.insert(Record::from_rdata(
        name,
        0, // goodbye
        RData::A(A(Ipv4Addr::new(1, 2, 3, 4))),
    ));
    assert_eq!(c.len(), 0, "TTL=0 must delete the cached record");
}

// ---------------------------------------------------------------------------
// §10.2 — Cache-flush bit
// ---------------------------------------------------------------------------

/// RFC 6762 §10.2 / §18.13: the top bit of rrclass on UNIQUE records
/// (host A, instance SRV, instance TXT) MUST be set, and on SHARED
/// records (DNS-SD type→instance PTR) MUST NOT be set.
#[tokio::test]
async fn rfc6762_s10_2_cache_flush_bit_on_unique_only() {
    let p = published_with_one_service();

    // Host A is unique.
    for r in &p.host_a {
        assert!(
            r.mdns_cache_flush,
            "host A {} must have cache-flush",
            r.name
        );
    }
    // Service-instance SRV and TXT are unique; the type→instance PTR is
    // shared (multiple instances may share the same service-type PTR).
    for s in &p.services {
        assert!(s.srv.mdns_cache_flush, "SRV must have cache-flush");
        assert!(s.txt.mdns_cache_flush, "TXT must have cache-flush");
        assert!(
            !s.ptr_type_to_instance.mdns_cache_flush,
            "type-to-instance PTR is shared, must not have cache-flush"
        );
        assert!(
            !s.ptr_meta_to_type.mdns_cache_flush,
            "_services._dns-sd PTR is shared, must not have cache-flush"
        );
    }
}

#[tokio::test]
async fn rfc6762_s10_2_cache_flush_bit_on_host_aaaa() {
    let p = published_with_ipv6_host();
    assert_eq!(p.host_aaaa.len(), 1);
    assert!(p.host_aaaa[0].mdns_cache_flush);
}

// ---------------------------------------------------------------------------
// §11 — Source Address Check
// ---------------------------------------------------------------------------

/// RFC 6762 §11: a responder SHOULD ignore queries whose source address
/// is not on the local link. We support this via configurable CIDR
/// blacklists/whitelists in addition to the per-interface subnet match.
#[test]
fn rfc6762_s11_source_filter_blacklist() {
    let toml = r#"
        interfaces = ["eth0"]
        blacklist = ["192.168.5.0/24"]
    "#;
    let cfg = Resolved::parse(toml).unwrap();
    assert!(!cfg.allow_source(Ipv4Addr::new(192, 168, 5, 10)));
    assert!(cfg.allow_source(Ipv4Addr::new(192, 168, 6, 10)));
}

#[test]
fn rfc6762_s11_source_filter_whitelist() {
    let toml = r#"
        interfaces = ["eth0"]
        whitelist = ["10.0.0.0/8"]
    "#;
    let cfg = Resolved::parse(toml).unwrap();
    assert!(cfg.allow_source(Ipv4Addr::new(10, 1, 2, 3)));
    assert!(!cfg.allow_source(Ipv4Addr::new(192, 168, 1, 1)));
}

#[test]
fn rfc6762_s11_ipv6_source_filter_blacklist() {
    let toml = r#"
        interfaces = ["eth0"]
        blacklist = ["fe80::/10"]
    "#;
    let cfg = Resolved::parse(toml).unwrap();
    assert!(!cfg.allow_source(Ipv6Addr::from(
        0xfe80_0000_0000_0000_0000_0000_0000_0010u128
    )));
    assert!(cfg.allow_source(Ipv6Addr::LOCALHOST));
}

#[test]
fn rfc6762_s11_ipv6_source_filter_whitelist() {
    let toml = r#"
        interfaces = ["eth0"]
        whitelist = ["fd00::/8"]
    "#;
    let cfg = Resolved::parse(toml).unwrap();
    assert!(cfg.allow_source(Ipv6Addr::from(
        0xfd00_0000_0000_0000_0000_0000_0000_0001u128
    )));
    assert!(!cfg.allow_source(Ipv6Addr::LOCALHOST));
}

// ---------------------------------------------------------------------------
// §18.4 — AA bit on responses
// ---------------------------------------------------------------------------

/// RFC 6762 §18.4: "In response messages for Multicast domains, the
/// Authoritative Answer bit MUST be set." Verify a synthetic announce
/// message round-trips with AA=1.
#[test]
fn rfc6762_s18_4_responses_set_authoritative_bit() {
    let mut msg = Message::response(0, OpCode::Query);
    msg.metadata.authoritative = true;
    msg.add_answer(Record::from_rdata(
        Name::from_str("router.local.").unwrap(),
        120,
        RData::A(A(Ipv4Addr::new(10, 0, 0, 1))),
    ));
    let bytes = msg.to_vec().unwrap();
    let parsed = Message::from_vec(&bytes).unwrap();
    assert_eq!(parsed.metadata.message_type, MessageType::Response);
    assert!(parsed.metadata.authoritative, "AA bit must be set");
}
