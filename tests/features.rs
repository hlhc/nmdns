//! End-to-end feature integration tests.
//!
//! These exercise every public-facing behaviour of the daemon's logic
//! without going through the binary or binding privileged sockets:
//!
//!  - Config parsing & validation (CIDR filters, mutually-exclusive lists,
//!    defaults, every TOML knob)
//!  - Cache lifecycle (insert / TTL=0 goodbye / TTL expiry / multi-rdata /
//!    cross-interface responder lookups)
//!  - Service record building (host A, PTR type→instance, PTR meta,
//!    SRV, TXT) and `Published::answer` matching for ANY/A/PTR/SRV/TXT
//!  - `Published::host_a_for` per-iface filtering
//!  - `goodbye()` records have TTL=0
//!  - Repeater: identify_recv_iface via PKTINFO ifindex and via
//!    source-subnet fallback; `forward()` skips the receiving iface
//!  - Wire-format round trip with hickory-proto (sanity: tests the deps
//!    actually link).

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::rdata::{A, AAAA, PTR, SRV, TXT};
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};

use nmdns::cache::Cache;
use nmdns::config::{parse_subnet, Resolved, ServiceConfig};
use nmdns::iface::{ipv6_net, Datagram, Iface, IfaceV4, IfaceV6, IpFamily, MDNS_ADDR_V6};
use nmdns::repeater;
use nmdns::services;

// --------------------------------------------------------------------
// helpers
// --------------------------------------------------------------------

/// Construct a fake `Iface` for tests. The send socket is a real loopback
/// UDP socket (so the type is honoured), but the tests never actually
/// transmit through it. `tokio::net::UdpSocket::from_std` requires a
/// running tokio runtime, so we keep a lazy global one for tests.
fn fake_iface(name: &str, ip: [u8; 4], mask: [u8; 4], ifindex: u32) -> Arc<Iface> {
    fake_iface_dual(name, Some((ip, mask)), None, ifindex)
}

fn fake_iface_v6(name: &str, ip: Ipv6Addr, prefix_len: u8, ifindex: u32) -> Arc<Iface> {
    fake_iface_dual(name, None, Some((ip, prefix_len)), ifindex)
}

fn fake_iface_dual(
    name: &str,
    v4: Option<([u8; 4], [u8; 4])>,
    v6: Option<(Ipv6Addr, u8)>,
    ifindex: u32,
) -> Arc<Iface> {
    use std::sync::OnceLock;
    static RT: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    let rt = RT.get_or_init(|| {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("test runtime")
    });

    let socket = |bind: &str| {
        let std_sock = std::net::UdpSocket::bind(bind).unwrap();
        std_sock.set_nonblocking(true).unwrap();
        rt.block_on(async { tokio::net::UdpSocket::from_std(std_sock).unwrap() })
    };

    let v4 = v4.map(|(ip, mask)| {
        let addr = Ipv4Addr::from(ip);
        let mask = Ipv4Addr::from(mask);
        let net = Ipv4Addr::from(u32::from(addr) & u32::from(mask));
        IfaceV4 {
            addr,
            mask,
            net,
            send: socket("127.0.0.1:0"),
        }
    });
    let v6 = v6.map(|(addr, prefix_len)| IfaceV6 {
        addr,
        prefix_len,
        net: ipv6_net(addr, prefix_len),
        scope_id: ifindex,
        send: socket("[::1]:0"),
    });

    Arc::new(Iface {
        name: name.into(),
        ifindex,
        v4,
        v6,
    })
}

fn host(name: &str) -> Name {
    Name::from_str(name).unwrap()
}

// --------------------------------------------------------------------
// config
// --------------------------------------------------------------------

#[test]
fn config_minimal_uses_all_defaults() {
    let r = Resolved::parse(r#"interfaces = ["eth0"]"#).unwrap();
    assert_eq!(r.interfaces, vec!["eth0".to_string()]);
    assert!(r.repeat, "repeat defaults to true");
    assert!(r.answer_from_cache, "cache responses default to true");
    assert!(r.hostname.is_none());
    assert_eq!(r.browse, vec!["_services._dns-sd._udp.local.".to_string()]);
    assert_eq!(r.browse_interval_secs, 60);
    assert_eq!(r.cache_tick_secs, 5);
    assert!(r.services.is_empty());
    assert!(r.blacklist.is_empty());
    assert!(r.whitelist.is_empty());
}

#[test]
fn config_full_round_trip() {
    let toml = r#"
interfaces           = ["br-lan", "br-iot"]
repeat               = false
answer_from_cache    = false
blacklist            = ["10.0.0.0/8"]
hostname             = "router"
browse               = ["_http._tcp.local."]
browse_interval_secs = 30
cache_tick_secs      = 10

[[service]]
name    = "Admin"
service = "_http._tcp.local."
port    = 80
txt     = ["path=/"]
host    = "router.local."
"#;
    let r = Resolved::parse(toml).unwrap();
    assert_eq!(r.interfaces.len(), 2);
    assert!(!r.repeat);
    assert!(!r.answer_from_cache);
    assert_eq!(r.hostname.as_deref(), Some("router"));
    assert_eq!(r.browse_interval_secs, 30);
    assert_eq!(r.cache_tick_secs, 10);
    assert_eq!(r.services.len(), 1);
    assert_eq!(r.services[0].name, "Admin");
    assert_eq!(r.services[0].port, 80);
    assert_eq!(r.services[0].txt, vec!["path=/".to_string()]);
    assert_eq!(r.blacklist.len(), 1);
}

#[test]
fn config_filter_allow_source_blacklist() {
    let r = Resolved::parse(
        r#"
interfaces = ["eth0"]
blacklist  = ["10.0.0.0/8", "192.168.5.0/24"]
"#,
    )
    .unwrap();
    assert!(r.allow_source(Ipv4Addr::new(8, 8, 8, 8)));
    assert!(!r.allow_source(Ipv4Addr::new(10, 1, 2, 3)));
    assert!(!r.allow_source(Ipv4Addr::new(192, 168, 5, 50)));
    assert!(r.allow_source(Ipv4Addr::new(192, 168, 6, 1)));
}

#[test]
fn config_filter_allow_source_whitelist() {
    let r = Resolved::parse(
        r#"
interfaces = ["eth0"]
whitelist  = ["192.168.1.0/24"]
"#,
    )
    .unwrap();
    assert!(r.allow_source(Ipv4Addr::new(192, 168, 1, 100)));
    assert!(!r.allow_source(Ipv4Addr::new(192, 168, 2, 100)));
}

#[test]
fn config_filter_no_filters_allows_all() {
    let r = Resolved::parse(r#"interfaces = ["eth0"]"#).unwrap();
    assert!(r.allow_source(Ipv4Addr::new(1, 1, 1, 1)));
    assert!(r.allow_source(Ipv4Addr::new(255, 255, 255, 254)));
    assert!(r.allow_source(Ipv6Addr::LOCALHOST));
}

#[test]
fn config_filter_allow_source_ipv6_blacklist() {
    let r = Resolved::parse(
        r#"
interfaces = ["eth0"]
blacklist  = ["fe80::/10", "2001:db8:1::/48"]
"#,
    )
    .unwrap();
    assert!(!r.allow_source(Ipv6Addr::from(
        0xfe80_0000_0000_0000_0000_0000_0000_0001u128
    )));
    assert!(!r.allow_source(Ipv6Addr::from(
        0x2001_0db8_0001_0000_0000_0000_0000_1234u128
    )));
    assert!(r.allow_source(Ipv6Addr::from(
        0x2001_0db8_0002_0000_0000_0000_0000_1234u128
    )));
}

#[test]
fn config_filter_allow_source_mixed_whitelist() {
    let r = Resolved::parse(
        r#"
interfaces = ["eth0"]
whitelist  = ["192.168.1.0/24", "fd00::/8"]
"#,
    )
    .unwrap();
    assert!(r.allow_source(Ipv4Addr::new(192, 168, 1, 50)));
    assert!(r.allow_source(Ipv6Addr::from(
        0xfd00_0000_0000_0000_0000_0000_0000_0001u128
    )));
    assert!(!r.allow_source(Ipv4Addr::new(10, 0, 0, 1)));
    assert!(!r.allow_source(Ipv6Addr::LOCALHOST));
}

#[test]
fn parse_subnet_handles_zero_mask() {
    let s = parse_subnet("0.0.0.0/0").unwrap();
    assert!(s.matches(Ipv4Addr::new(1, 2, 3, 4)));
    assert!(s.matches(Ipv4Addr::new(254, 254, 254, 254)));
}

#[test]
fn parse_subnet_handles_full_mask() {
    let s = parse_subnet("10.0.0.5/32").unwrap();
    assert!(s.matches(Ipv4Addr::new(10, 0, 0, 5)));
    assert!(!s.matches(Ipv4Addr::new(10, 0, 0, 6)));
}

#[test]
fn parse_subnet_handles_ipv6_masks() {
    let any = parse_subnet("::/0").unwrap();
    assert!(any.matches(Ipv6Addr::LOCALHOST));
    assert!(any.matches(Ipv6Addr::from(
        0x2001_0db8_0000_0000_0000_0000_0000_0001u128
    )));

    let exact = parse_subnet("fd00::1/128").unwrap();
    assert!(exact.matches(Ipv6Addr::from(
        0xfd00_0000_0000_0000_0000_0000_0000_0001u128
    )));
    assert!(!exact.matches(Ipv6Addr::from(
        0xfd00_0000_0000_0000_0000_0000_0000_0002u128
    )));
}

#[test]
fn parse_subnet_rejects_garbage() {
    assert!(parse_subnet("not/a/subnet").is_err());
    assert!(parse_subnet("10.0.0.0").is_err());
    assert!(parse_subnet("10.0.0.0/abc").is_err());
    assert!(parse_subnet("10.0.0.0/40").is_err());
    assert!(parse_subnet("999.0.0.0/8").is_err());
}

// --------------------------------------------------------------------
// cache
// --------------------------------------------------------------------

fn a_record(name: &str, ttl: u32, ip: [u8; 4]) -> Record {
    Record::from_rdata(host(name), ttl, RData::A(A(Ipv4Addr::from(ip))))
}

fn aaaa_record(name: &str, ttl: u32, ip: Ipv6Addr) -> Record {
    Record::from_rdata(host(name), ttl, RData::AAAA(AAAA(ip)))
}

#[test]
fn cache_insert_then_lookup() {
    let c = Cache::new();
    c.insert(a_record("foo.local.", 60, [1, 2, 3, 4]));
    let hits = c.lookup(&host("foo.local."), RecordType::A);
    assert_eq!(hits.len(), 1);
}

#[test]
fn cache_distinct_rdata_kept_separately() {
    let c = Cache::new();
    c.insert(a_record("foo.local.", 60, [1, 2, 3, 4]));
    c.insert(a_record("foo.local.", 60, [5, 6, 7, 8]));
    assert_eq!(c.len(), 2);
    let hits = c.lookup(&host("foo.local."), RecordType::A);
    assert_eq!(hits.len(), 2);
}

#[test]
fn cache_ttl_zero_is_goodbye() {
    let c = Cache::new();
    c.insert(a_record("foo.local.", 60, [1, 2, 3, 4]));
    assert_eq!(c.len(), 1);
    c.insert(a_record("foo.local.", 0, [1, 2, 3, 4]));
    assert_eq!(c.len(), 0);
    assert!(c.is_empty());
}

#[test]
fn cache_evict_expired_removes_dead_records() {
    let c = Cache::new();
    c.insert(a_record("foo.local.", 1, [1, 2, 3, 4]));
    c.insert(a_record("bar.local.", 60, [1, 2, 3, 4]));
    std::thread::sleep(Duration::from_millis(1100));
    let evicted = c.evict_expired();
    assert_eq!(evicted, 1);
    assert_eq!(c.len(), 1);
}

#[test]
fn cache_snapshot_returns_all() {
    let c = Cache::new();
    c.insert(a_record("a.local.", 60, [1, 2, 3, 4]));
    c.insert(a_record("b.local.", 60, [5, 6, 7, 8]));
    assert_eq!(c.snapshot().len(), 2);
}

#[test]
fn cache_lookup_filters_by_type() {
    let c = Cache::new();
    c.insert(a_record("foo.local.", 60, [1, 2, 3, 4]));
    let hits = c.lookup(&host("foo.local."), RecordType::AAAA);
    assert!(hits.is_empty());
}

#[test]
fn cache_lookup_any_returns_all_types_for_name() {
    let c = Cache::new();
    c.insert(a_record("foo.local.", 60, [1, 2, 3, 4]));
    c.insert(aaaa_record("foo.local.", 60, Ipv6Addr::LOCALHOST));
    let hits = c.lookup(&host("foo.local."), RecordType::ANY);
    assert_eq!(hits.len(), 2);
}

#[test]
fn cache_aaaa_records_are_distinct_from_a() {
    let c = Cache::new();
    c.insert(a_record("foo.local.", 60, [1, 2, 3, 4]));
    c.insert(aaaa_record("foo.local.", 60, Ipv6Addr::LOCALHOST));

    assert_eq!(c.lookup(&host("foo.local."), RecordType::A).len(), 1);
    assert_eq!(c.lookup(&host("foo.local."), RecordType::AAAA).len(), 1);
    assert_eq!(c.lookup(&host("foo.local."), RecordType::ANY).len(), 2);
}

#[test]
fn cache_lookup_from_other_ifaces_excludes_arrival_iface() {
    let c = Cache::new();
    c.insert_from(a_record("iot.local.", 60, [192, 168, 20, 50]), Some(20));

    let trusted_hits = c.lookup_from_other_ifaces(&host("iot.local."), RecordType::A, 10);
    assert_eq!(trusted_hits.len(), 1);

    let iot_hits = c.lookup_from_other_ifaces(&host("iot.local."), RecordType::A, 20);
    assert!(iot_hits.is_empty());
}

#[test]
fn cache_lookup_aaaa_from_other_ifaces() {
    let c = Cache::new();
    c.insert_from(aaaa_record("iot.local.", 60, Ipv6Addr::LOCALHOST), Some(20));

    let trusted_hits = c.lookup_from_other_ifaces(&host("iot.local."), RecordType::AAAA, 10);
    assert_eq!(trusted_hits.len(), 1);

    let iot_hits = c.lookup_from_other_ifaces(&host("iot.local."), RecordType::AAAA, 20);
    assert!(iot_hits.is_empty());
}

#[test]
fn cache_lookup_ignores_records_without_source_iface_for_cross_iface_answers() {
    let c = Cache::new();
    c.insert(a_record("unknown.local.", 60, [1, 2, 3, 4]));

    let hits = c.lookup_from_other_ifaces(&host("unknown.local."), RecordType::A, 10);
    assert!(hits.is_empty());
}

#[test]
fn cache_lookup_returns_remaining_ttl() {
    let c = Cache::new();
    c.insert(a_record("foo.local.", 60, [1, 2, 3, 4]));
    let hits = c.lookup(&host("foo.local."), RecordType::A);
    assert_eq!(hits.len(), 1);
    assert!(hits[0].ttl <= 60);
    assert!(hits[0].ttl > 0);
}

#[test]
fn cache_max_ttl_caps_stored_ttl() {
    let c = Cache::with_capacity_and_max_ttl(100, Some(60));
    c.insert(a_record("foo.local.", 4500, [1, 2, 3, 4]));
    let hits = c.lookup(&host("foo.local."), RecordType::A);
    assert_eq!(hits.len(), 1);
    assert!(
        hits[0].ttl <= 60,
        "TTL should be capped, got {}",
        hits[0].ttl
    );
}

#[test]
fn cache_max_ttl_preserves_ttl_below_cap() {
    let c = Cache::with_capacity_and_max_ttl(100, Some(300));
    c.insert(a_record("foo.local.", 120, [1, 2, 3, 4]));
    let hits = c.lookup(&host("foo.local."), RecordType::A);
    assert_eq!(hits.len(), 1);
    assert!(hits[0].ttl <= 120, "TTL below cap should be preserved");
}

// --------------------------------------------------------------------
// services & responder logic (Published::answer)
// --------------------------------------------------------------------

fn build_published(host_name: &str, ifaces: &[Arc<Iface>]) -> services::Published {
    let svcs = vec![
        ServiceConfig {
            name: "Admin".into(),
            service: "_http._tcp.local.".into(),
            port: 80,
            txt: vec!["path=/".into()],
            host: None,
        },
        ServiceConfig {
            name: "SSH".into(),
            service: "_ssh._tcp.local.".into(),
            port: 22,
            txt: vec![],
            host: None,
        },
    ];
    services::build(host(host_name), &svcs, ifaces).expect("build")
}

#[test]
fn services_build_emits_host_a_per_iface() {
    let ifs = vec![
        fake_iface("eth0", [10, 0, 0, 1], [255, 255, 255, 0], 1),
        fake_iface("eth1", [192, 168, 1, 1], [255, 255, 255, 0], 2),
    ];
    let p = build_published("router.local.", &ifs);
    assert_eq!(p.host_a.len(), 2);
    assert_eq!(p.services.len(), 2);
}

#[test]
fn services_build_emits_host_aaaa_per_ipv6_iface() {
    let ip6_a = Ipv6Addr::from(0xfe80_0000_0000_0000_0000_0000_0000_0001u128);
    let ip6_b = Ipv6Addr::from(0xfe80_0000_0000_0000_0000_0000_0000_0002u128);
    let ifs = vec![
        fake_iface_v6("eth0", ip6_a, 64, 1),
        fake_iface_v6("eth1", ip6_b, 64, 2),
    ];
    let p = build_published("router.local.", &ifs);
    assert!(p.host_a.is_empty());
    assert_eq!(p.host_aaaa.len(), 2);
    assert!(p.host_aaaa.iter().all(|r| r.mdns_cache_flush));
}

#[test]
fn services_build_with_mixed_ipv4_ipv6_ifaces() {
    let ip6 = Ipv6Addr::from(0xfe80_0000_0000_0000_0000_0000_0000_0001u128);
    let ifs = vec![
        fake_iface("eth0", [10, 0, 0, 1], [255, 255, 255, 0], 1),
        fake_iface_v6("eth1", ip6, 64, 2),
        fake_iface_dual(
            "eth2",
            Some(([192, 168, 1, 1], [255, 255, 255, 0])),
            Some((
                Ipv6Addr::from(0xfe80_0000_0000_0000_0000_0000_0000_0002u128),
                64,
            )),
            3,
        ),
    ];
    let p = build_published("router.local.", &ifs);
    assert_eq!(p.host_a.len(), 2);
    assert_eq!(p.host_aaaa.len(), 2);
}

#[test]
fn services_answer_any_for_hostname_returns_all_a() {
    let ifs = vec![fake_iface("eth0", [10, 0, 0, 1], [255, 255, 255, 0], 1)];
    let p = build_published("router.local.", &ifs);
    let ans = p.answer(&host("router.local."), RecordType::ANY);
    assert!(ans.iter().any(|r| r.record_type() == RecordType::A));
}

#[test]
fn services_answer_aaaa_query_returns_only_aaaa() {
    let ip6 = Ipv6Addr::from(0xfe80_0000_0000_0000_0000_0000_0000_0001u128);
    let ifs = vec![fake_iface_v6("eth0", ip6, 64, 1)];
    let p = build_published("router.local.", &ifs);
    let ans = p.answer(&host("router.local."), RecordType::AAAA);
    assert_eq!(ans.len(), 1);
    assert_eq!(ans[0].record_type(), RecordType::AAAA);
}

#[test]
fn services_answer_a_query_returns_only_a() {
    let ifs = vec![fake_iface("eth0", [10, 0, 0, 1], [255, 255, 255, 0], 1)];
    let p = build_published("router.local.", &ifs);
    let ans = p.answer(&host("router.local."), RecordType::A);
    assert_eq!(ans.len(), 1);
    assert_eq!(ans[0].record_type(), RecordType::A);
}

#[test]
fn services_answer_ptr_for_service_type_returns_instance() {
    let ifs = vec![fake_iface("eth0", [10, 0, 0, 1], [255, 255, 255, 0], 1)];
    let p = build_published("router.local.", &ifs);
    let ans = p.answer(&host("_http._tcp.local."), RecordType::PTR);
    assert_eq!(ans.len(), 1);
    assert_eq!(ans[0].record_type(), RecordType::PTR);
    if let RData::PTR(PTR(name)) = &ans[0].data {
        let s = name.to_string().to_ascii_lowercase();
        assert!(s.contains("admin"), "got {s}");
        assert!(s.contains("_http._tcp.local."), "got {s}");
    } else {
        panic!("expected PTR rdata");
    }
}

#[test]
fn services_answer_ptr_for_meta_returns_service_types() {
    let ifs = vec![fake_iface("eth0", [10, 0, 0, 1], [255, 255, 255, 0], 1)];
    let p = build_published("router.local.", &ifs);
    let meta = host("_services._dns-sd._udp.local.");
    let ans = p.answer(&meta, RecordType::PTR);
    // One PTR per published service (HTTP + SSH).
    assert_eq!(ans.len(), 2);
}

#[test]
fn services_answer_srv_and_txt_for_instance() {
    let ifs = vec![fake_iface("eth0", [10, 0, 0, 1], [255, 255, 255, 0], 1)];
    let p = build_published("router.local.", &ifs);
    let inst = host("Admin._http._tcp.local.");
    let srv = p.answer(&inst, RecordType::SRV);
    assert_eq!(srv.len(), 1);
    if let RData::SRV(srv_rdata) = &srv[0].data {
        assert_eq!(srv_rdata.port, 80);
    } else {
        panic!("expected SRV");
    }
    let txt = p.answer(&inst, RecordType::TXT);
    assert_eq!(txt.len(), 1);
    if let RData::TXT(txt_rdata) = &txt[0].data {
        let entries: Vec<String> = txt_rdata
            .txt_data
            .iter()
            .map(|s| String::from_utf8_lossy(s).into_owned())
            .collect();
        assert!(entries.iter().any(|s| s == "path=/"));
    } else {
        panic!("expected TXT");
    }
}

#[test]
fn services_empty_txt_emits_zero_length_string() {
    // RFC 6763 §6.1: a TXT with no key=value still has one zero-length
    // string element. The "SSH" service in build_published has empty txt.
    let ifs = vec![fake_iface("eth0", [10, 0, 0, 1], [255, 255, 255, 0], 1)];
    let p = build_published("router.local.", &ifs);
    let inst = host("SSH._ssh._tcp.local.");
    let txt = p.answer(&inst, RecordType::TXT);
    assert_eq!(txt.len(), 1);
    if let RData::TXT(t) = &txt[0].data {
        let parts: Vec<&[u8]> = t.txt_data.iter().map(|b| b.as_ref()).collect();
        assert_eq!(parts.len(), 1);
        assert!(parts[0].is_empty());
    } else {
        panic!("expected TXT");
    }
}

#[test]
fn services_unrelated_query_returns_nothing() {
    let ifs = vec![fake_iface("eth0", [10, 0, 0, 1], [255, 255, 255, 0], 1)];
    let p = build_published("router.local.", &ifs);
    let ans = p.answer(&host("nowhere.local."), RecordType::ANY);
    assert!(ans.is_empty());
}

#[test]
fn services_host_a_for_filters_by_address() {
    let ifs = vec![
        fake_iface("eth0", [10, 0, 0, 1], [255, 255, 255, 0], 1),
        fake_iface("eth1", [192, 168, 1, 1], [255, 255, 255, 0], 2),
    ];
    let p = build_published("router.local.", &ifs);
    let only = p.host_a_for(Ipv4Addr::new(10, 0, 0, 1));
    assert_eq!(only.len(), 1);
    if let RData::A(A(a)) = &only[0].data {
        assert_eq!(*a, Ipv4Addr::new(10, 0, 0, 1));
    } else {
        panic!("expected A");
    }
    // An address that belongs to no iface returns nothing.
    assert!(p.host_a_for(Ipv4Addr::new(8, 8, 8, 8)).is_empty());
}

#[test]
fn services_host_aaaa_for_filters_by_address() {
    let ip6_a = Ipv6Addr::from(0xfe80_0000_0000_0000_0000_0000_0000_0001u128);
    let ip6_b = Ipv6Addr::from(0xfe80_0000_0000_0000_0000_0000_0000_0002u128);
    let ifs = vec![
        fake_iface_v6("eth0", ip6_a, 64, 1),
        fake_iface_v6("eth1", ip6_b, 64, 2),
    ];
    let p = build_published("router.local.", &ifs);
    let only = p.host_aaaa_for(ip6_a);
    assert_eq!(only.len(), 1);
    if let RData::AAAA(AAAA(a)) = &only[0].data {
        assert_eq!(*a, ip6_a);
    } else {
        panic!("expected AAAA");
    }
    assert!(p.host_aaaa_for(Ipv6Addr::LOCALHOST).is_empty());
}

#[test]
fn services_goodbye_zeroes_every_ttl() {
    let ifs = vec![fake_iface("eth0", [10, 0, 0, 1], [255, 255, 255, 0], 1)];
    let p = build_published("router.local.", &ifs);
    let g = services::goodbye(&p);
    assert!(!g.is_empty());
    assert!(g.iter().all(|r| r.ttl == 0));
}

#[test]
fn services_resolve_hostname_uses_explicit_override() {
    let n = services::resolve_hostname(&Some("custom".into()));
    assert_eq!(n.to_string(), "custom.local.");
}

#[test]
fn services_resolve_hostname_strips_trailing_domain() {
    let n = services::resolve_hostname(&Some("router.lan.example".into()));
    // bare label only
    assert_eq!(n.to_string(), "router.local.");
}

// --------------------------------------------------------------------
// repeater
// --------------------------------------------------------------------

fn datagram(src: [u8; 4], ifindex: Option<u32>) -> Datagram {
    Datagram {
        data: vec![0u8; 8], // payload contents irrelevant for these tests
        source: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::from(src), 5353)),
        family: IpFamily::V4,
        recv_ifindex: ifindex,
    }
}

fn datagram_v6(src: Ipv6Addr, ifindex: Option<u32>) -> Datagram {
    Datagram {
        data: vec![0u8; 8],
        source: SocketAddr::V6(SocketAddrV6::new(src, 5353, 0, ifindex.unwrap_or(0))),
        family: IpFamily::V6,
        recv_ifindex: ifindex,
    }
}

#[test]
fn repeater_identify_recv_iface_via_pktinfo() {
    let ifs = vec![
        fake_iface("eth0", [10, 0, 0, 1], [255, 255, 255, 0], 5),
        fake_iface("eth1", [192, 168, 1, 1], [255, 255, 255, 0], 7),
    ];
    let pkt = datagram([10, 0, 0, 99], Some(7));
    // ifindex wins over subnet match.
    assert_eq!(repeater::identify_recv_iface(&pkt, &ifs), Some(1));
}

#[test]
fn repeater_identify_recv_iface_via_subnet_fallback() {
    let ifs = vec![
        fake_iface("eth0", [10, 0, 0, 1], [255, 255, 255, 0], 5),
        fake_iface("eth1", [192, 168, 1, 1], [255, 255, 255, 0], 7),
    ];
    // No PKTINFO; source belongs to eth1's subnet.
    let pkt = datagram([192, 168, 1, 50], None);
    assert_eq!(repeater::identify_recv_iface(&pkt, &ifs), Some(1));
}

#[test]
fn repeater_identify_recv_iface_ipv6_link_local_requires_pktinfo() {
    // Every interface's link-local address is in fe80::/64, so a subnet match
    // cannot disambiguate the arrival link for a link-local source — without a
    // PKTINFO ifindex we must NOT guess (mis-attributing to the first iface
    // enables cross-link reflection). With a matching ifindex it resolves.
    let ip6_a = Ipv6Addr::from(0xfe80_0000_0000_0000_0000_0000_0000_0001u128);
    let ip6_b = Ipv6Addr::from(0xfe80_0000_0000_0000_0000_0000_0000_0002u128);
    let ifs = vec![
        fake_iface_v6("eth0", ip6_a, 64, 5),
        fake_iface_v6("eth1", ip6_b, 64, 7),
    ];
    let src = Ipv6Addr::from(0xfe80_0000_0000_0000_0000_0000_0000_0050u128);
    assert!(
        repeater::identify_recv_iface(&datagram_v6(src, None), &ifs).is_none(),
        "link-local v6 source without PKTINFO must not be guessed"
    );
    assert_eq!(
        repeater::identify_recv_iface(&datagram_v6(src, Some(7)), &ifs),
        Some(1),
        "PKTINFO ifindex still resolves the arrival iface"
    );
}

#[test]
fn repeater_forward_targets_skip_recv_iface() {
    let ifs = vec![
        fake_iface("eth0", [10, 0, 0, 1], [255, 255, 255, 0], 5),
        fake_iface("eth1", [192, 168, 1, 1], [255, 255, 255, 0], 7),
    ];
    let src = Ipv4Addr::new(10, 0, 0, 99).into();
    assert_eq!(repeater::forward_targets(Some(0), src, &ifs), vec![1]);
}

#[test]
fn repeater_forward_targets_unidentified_offlink_is_empty() {
    // Ingress unknown and the source is on no monitored subnet (e.g. an
    // off-link unicast to :5353): do not blindly reflect to every interface.
    let ifs = vec![
        fake_iface("eth0", [10, 0, 0, 1], [255, 255, 255, 0], 5),
        fake_iface("eth1", [192, 168, 1, 1], [255, 255, 255, 0], 7),
    ];
    let off_link = Ipv4Addr::new(8, 8, 8, 8).into();
    assert!(repeater::forward_targets(None, off_link, &ifs).is_empty());
}

#[test]
fn repeater_forward_targets_unidentified_onlink_skips_source_subnet() {
    // Ingress unknown but source is on a monitored subnet: forward to the
    // other interfaces (the legitimate subnet-fallback path).
    let ifs = vec![
        fake_iface("eth0", [10, 0, 0, 1], [255, 255, 255, 0], 5),
        fake_iface("eth1", [192, 168, 1, 1], [255, 255, 255, 0], 7),
    ];
    let on_eth0 = Ipv4Addr::new(10, 0, 0, 50).into();
    assert_eq!(repeater::forward_targets(None, on_eth0, &ifs), vec![1]);
}

#[test]
fn repeater_identify_recv_iface_unknown_subnet_returns_none() {
    let ifs = vec![fake_iface("eth0", [10, 0, 0, 1], [255, 255, 255, 0], 5)];
    let pkt = datagram([8, 8, 8, 8], None);
    assert!(repeater::identify_recv_iface(&pkt, &ifs).is_none());
}

#[test]
fn repeater_identify_recv_iface_unknown_ifindex_falls_back_to_subnet() {
    let ifs = vec![fake_iface("eth0", [10, 0, 0, 1], [255, 255, 255, 0], 5)];
    // PKTINFO points at iface that we don't manage, but source matches eth0.
    let pkt = datagram([10, 0, 0, 50], Some(99));
    assert_eq!(repeater::identify_recv_iface(&pkt, &ifs), Some(0));
}

#[test]
fn iface_contains_uses_mask() {
    let ifs = [fake_iface("eth0", [10, 1, 0, 1], [255, 255, 0, 0], 1)];
    assert!(ifs[0].contains(Ipv4Addr::new(10, 1, 99, 250).into()));
    assert!(!ifs[0].contains(Ipv4Addr::new(10, 2, 0, 1).into()));
}

#[test]
fn iface_contains_uses_ipv6_prefix() {
    let ip6 = Ipv6Addr::from(0xfe80_0000_0000_0001_0000_0000_0000_0001u128);
    let iface = fake_iface_v6("eth0", ip6, 64, 1);
    assert!(iface.contains(Ipv6Addr::from(0xfe80_0000_0000_0001_0000_0000_0000_0050u128).into()));
    assert!(!iface.contains(Ipv6Addr::from(0xfe80_0000_0000_0002_0000_0000_0000_0050u128).into()));
}

#[test]
fn rfc6762_ipv6_multicast_address_is_ff02_fb() {
    assert_eq!(MDNS_ADDR_V6, Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0xfb));
}

// --------------------------------------------------------------------
// wire format sanity
// --------------------------------------------------------------------

#[test]
fn wire_message_round_trips_through_hickory() {
    let mut q = Query::new();
    q.set_name(host("router.local."))
        .set_query_type(RecordType::A)
        .set_query_class(DNSClass::IN);
    let mut msg = Message::new(0, MessageType::Query, OpCode::Query);
    msg.add_query(q);
    let bytes = msg.to_vec().expect("encode");

    let parsed = Message::from_vec(&bytes).expect("decode");
    assert_eq!(parsed.metadata.message_type, MessageType::Query);
    assert_eq!(parsed.queries.len(), 1);
    assert_eq!(parsed.queries[0].query_type(), RecordType::A);
    assert_eq!(parsed.queries[0].name(), &host("router.local."));
}

#[test]
fn wire_response_with_full_dnssd_set_round_trips() {
    let h = host("router.local.");
    let inst = host("Admin._http._tcp.local.");
    let svc_type = host("_http._tcp.local.");
    let meta = host("_services._dns-sd._udp.local.");

    let a = Record::from_rdata(h.clone(), 120, RData::A(A(Ipv4Addr::new(10, 0, 0, 1))));
    let aaaa = Record::from_rdata(
        h.clone(),
        120,
        RData::AAAA(AAAA(Ipv6Addr::from(
            0xfe80_0000_0000_0000_0000_0000_0000_0001u128,
        ))),
    );
    let ptr_inst = Record::from_rdata(svc_type.clone(), 4500, RData::PTR(PTR(inst.clone())));
    let ptr_meta = Record::from_rdata(meta, 4500, RData::PTR(PTR(svc_type)));
    let srv = Record::from_rdata(inst.clone(), 120, RData::SRV(SRV::new(0, 0, 80, h.clone())));
    let txt = Record::from_rdata(inst, 4500, RData::TXT(TXT::new(vec!["path=/".into()])));

    let mut msg = Message::new(0, MessageType::Response, OpCode::Query);
    msg.metadata.authoritative = true;
    for r in [&a, &aaaa, &ptr_inst, &ptr_meta, &srv, &txt] {
        msg.add_answer(r.clone());
    }

    let bytes = msg.to_vec().expect("encode response");
    let parsed = Message::from_vec(&bytes).expect("decode response");
    assert_eq!(parsed.metadata.message_type, MessageType::Response);
    assert!(parsed.metadata.authoritative);
    assert_eq!(parsed.answers.len(), 6);
    assert!(parsed
        .answers
        .iter()
        .any(|r| r.record_type() == RecordType::AAAA));
}
