//! Records the daemon publishes (advertises) on every interface.
//!
//! Two categories:
//!  * **Host records**: `<hostname>.local.` A/AAAA records for each
//!    interface's own IPs. Reported in response to ANY/A/AAAA queries for
//!    the hostname.
//!  * **Service records**: DNS-SD instances declared in the config. Each
//!    instance produces:
//!      - `<service>` PTR \u2192 `<instance>.<service>`
//!      - `_services._dns-sd._udp.local.` PTR \u2192 `<service>` (RFC 6763 \u00a79)
//!      - `<instance>.<service>` SRV \u2192 host:port
//!      - `<instance>.<service>` TXT \u2192 key=value records

use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::sync::Arc;

use hickory_proto::rr::rdata::{A, AAAA, PTR, SRV, TXT};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use thiserror::Error;

use crate::config::ServiceConfig;
use crate::iface::Iface;

#[derive(Debug, Error)]
pub enum ServiceError {
    #[error("invalid service type {0}: {1}")]
    BadServiceType(String, hickory_proto::ProtoError),
    #[error("invalid instance name {0}: {1}")]
    BadInstanceName(String, hickory_proto::ProtoError),
    #[error("compose instance {0}.{1}: {2}")]
    BadInstanceCompose(String, String, hickory_proto::ProtoError),
    #[error("invalid host override {0}: {1}")]
    BadHost(String, hickory_proto::ProtoError),
    #[error("internal: {0}")]
    Internal(hickory_proto::ProtoError),
}

/// All records published by the daemon, pre-built at startup.
#[allow(dead_code)]
pub struct Published {
    pub hostname: Name,
    /// `<hostname>.local. IN A <iface_ip>` records (one per interface).
    pub host_a: Vec<Record>,
    /// `<hostname>.local. IN AAAA <iface_ip>` records (one per IPv6 interface).
    pub host_aaaa: Vec<Record>,
    pub services: Vec<ServiceRecords>,
}

pub struct ServiceRecords {
    pub instance_name: Name, // e.g. "Router Admin._http._tcp.local."
    pub service_type: Name,  // e.g. "_http._tcp.local."
    pub ptr_type_to_instance: Record,
    pub ptr_meta_to_type: Record, // _services._dns-sd._udp.local. PTR <type>
    pub srv: Record,
    pub txt: Record,
}

const TTL_HOST: u32 = 120;
const TTL_SERVICE: u32 = 4500; // DNS-SD recommended

/// Resolve hostname: explicit override, system hostname, or "router".
pub fn resolve_hostname(explicit: &Option<String>) -> Name {
    let raw = explicit
        .clone()
        .or_else(|| {
            nix::unistd::gethostname()
                .ok()
                .and_then(|os| os.into_string().ok())
        })
        .unwrap_or_else(|| "router".to_string());

    let bare = raw.split('.').next().unwrap_or("router");
    Name::from_str(&format!("{bare}.local."))
        .unwrap_or_else(|_| Name::from_str("router.local.").expect("static name parses"))
}

/// Parse and validate every service-derived `Name` without binding any
/// sockets. Used by `--check` so configuration mistakes (bad instance
/// label, malformed service type, illegal host override) surface before
/// runtime startup, where `build` would otherwise be the first to call
/// `Name::from_str`.
pub fn validate(hostname: &Name, services: &[ServiceConfig]) -> Result<(), ServiceError> {
    let _ = hostname; // already validated by `resolve_hostname`
    Name::from_str("_services._dns-sd._udp.local.").map_err(ServiceError::Internal)?;
    for sc in services {
        let svc_type = Name::from_str(&sc.service)
            .map_err(|e| ServiceError::BadServiceType(sc.service.clone(), e))?;
        // RFC 6763 §4.1.1: an instance label is an arbitrary UTF-8 string
        // (1–63 octets), NOT a host-name-style restricted label, so use
        // `from_labels` rather than `from_str`. Otherwise spaces, slashes,
        // etc. would be rejected.
        let instance_label = Name::from_labels(vec![sc.name.as_bytes()])
            .map_err(|e| ServiceError::BadInstanceName(sc.name.clone(), e))?;
        instance_label.append_name(&svc_type).map_err(|e| {
            ServiceError::BadInstanceCompose(sc.name.clone(), sc.service.clone(), e)
        })?;
        if let Some(h) = &sc.host {
            Name::from_str(h).map_err(|e| ServiceError::BadHost(h.clone(), e))?;
        }
    }
    Ok(())
}

pub fn build(
    hostname: Name,
    services: &[ServiceConfig],
    ifaces: &[Arc<Iface>],
) -> Result<Published, ServiceError> {
    let host_a = ifaces
        .iter()
        .filter_map(|i| i.addr_v4())
        .map(|addr| {
            // Host A is a unique record (RFC 6762 §10.2): set cache-flush.
            let mut r = Record::from_rdata(hostname.clone(), TTL_HOST, RData::A(A(addr)));
            r.mdns_cache_flush = true;
            r
        })
        .collect();

    let host_aaaa = ifaces
        .iter()
        .filter_map(|i| i.addr_v6())
        .map(|addr| {
            let mut r = Record::from_rdata(hostname.clone(), TTL_HOST, RData::AAAA(AAAA(addr)));
            r.mdns_cache_flush = true;
            r
        })
        .collect();

    let mut svc_recs = Vec::with_capacity(services.len());
    let meta = Name::from_str("_services._dns-sd._udp.local.").map_err(ServiceError::Internal)?;
    for sc in services {
        let svc_type = Name::from_str(&sc.service)
            .map_err(|e| ServiceError::BadServiceType(sc.service.clone(), e))?;
        // RFC 6763 §4.1.1: instance label is arbitrary UTF-8.
        let instance_label = Name::from_labels(vec![sc.name.as_bytes()])
            .map_err(|e| ServiceError::BadInstanceName(sc.name.clone(), e))?;
        // <instance>.<service>
        let instance_name = instance_label.append_name(&svc_type).map_err(|e| {
            ServiceError::BadInstanceCompose(sc.name.clone(), sc.service.clone(), e)
        })?;

        let target = match &sc.host {
            Some(h) => Name::from_str(h).map_err(|e| ServiceError::BadHost(h.clone(), e))?,
            None => hostname.clone(),
        };

        // PTR records are *shared*: cache-flush bit MUST NOT be set
        // (RFC 6762 §10.2). Multiple instances may legitimately share
        // the same service-type PTR name.
        let ptr_type_to_instance = Record::from_rdata(
            svc_type.clone(),
            TTL_SERVICE,
            RData::PTR(PTR(instance_name.clone())),
        );

        let ptr_meta =
            Record::from_rdata(meta.clone(), TTL_SERVICE, RData::PTR(PTR(svc_type.clone())));

        // SRV is a *unique* record — only one SRV per instance name.
        let mut srv = Record::from_rdata(
            instance_name.clone(),
            TTL_HOST,
            RData::SRV(SRV::new(0, 0, sc.port, target)),
        );
        srv.mdns_cache_flush = true;

        let txt_data = if sc.txt.is_empty() {
            // RFC 6763 §6.1: empty TXT is a single zero-length string.
            TXT::new(vec![String::new()])
        } else {
            TXT::new(sc.txt.clone())
        };
        // TXT is a *unique* record (one TXT per instance name).
        let mut txt = Record::from_rdata(instance_name.clone(), TTL_SERVICE, RData::TXT(txt_data));
        txt.mdns_cache_flush = true;

        svc_recs.push(ServiceRecords {
            instance_name,
            service_type: svc_type,
            ptr_type_to_instance,
            ptr_meta_to_type: ptr_meta,
            srv,
            txt,
        });
    }

    Ok(Published {
        hostname,
        host_a,
        host_aaaa,
        services: svc_recs,
    })
}

impl Published {
    /// Return all answer records that match `(qname, qtype)` per RFC 6762
    /// \u00a76. `qtype = ANY` matches any record type.
    pub fn answer(&self, qname: &Name, qtype: RecordType) -> Vec<Record> {
        let any = qtype == RecordType::ANY;
        let mut out = Vec::new();

        // Host A records
        if any || qtype == RecordType::A {
            for r in &self.host_a {
                if &r.name == qname {
                    out.push(r.clone());
                }
            }
        }
        if any || qtype == RecordType::AAAA {
            for r in &self.host_aaaa {
                if &r.name == qname {
                    out.push(r.clone());
                }
            }
        }

        for s in &self.services {
            if (any || qtype == RecordType::PTR) && qname == &s.service_type {
                out.push(s.ptr_type_to_instance.clone());
            }
            if (any || qtype == RecordType::PTR) && qname == &s.ptr_meta_to_type.name {
                out.push(s.ptr_meta_to_type.clone());
            }
            if (any || qtype == RecordType::SRV) && qname == &s.instance_name {
                out.push(s.srv.clone());
            }
            if (any || qtype == RecordType::TXT) && qname == &s.instance_name {
                out.push(s.txt.clone());
            }
        }
        out
    }

    /// Filter `host_a` records whose address belongs to the interface that
    /// will transmit the response. Avoids advertising an iface's IP on a
    /// different link.
    pub fn host_a_for(&self, addr: Ipv4Addr) -> Vec<Record> {
        self.host_a
            .iter()
            .filter(|r| matches!(&r.data, RData::A(A(a)) if *a == addr))
            .cloned()
            .collect()
    }

    /// IPv6 equivalent of [`Published::host_a_for`].
    pub fn host_aaaa_for(&self, addr: Ipv6Addr) -> Vec<Record> {
        self.host_aaaa
            .iter()
            .filter(|r| matches!(&r.data, RData::AAAA(AAAA(a)) if *a == addr))
            .cloned()
            .collect()
    }

    /// Host records that belong to `iface`, across both address families.
    pub fn host_records_for_iface(&self, iface: &Iface) -> Vec<Record> {
        let mut out = Vec::new();
        if let Some(addr) = iface.addr_v4() {
            out.extend(self.host_a_for(addr));
        }
        if let Some(addr) = iface.addr_v6() {
            out.extend(self.host_aaaa_for(addr));
        }
        out
    }

    /// All records that are *unique* (cache-flush bit set) and therefore
    /// candidates for probing per RFC 6762 §8.1. The host A on each iface
    /// is collected lazily by `unique_for_iface` below; this returns the
    /// service-instance unique records (SRV, TXT) which are the same on
    /// every interface.
    pub fn unique_service_records(&self) -> Vec<Record> {
        let mut out = Vec::new();
        for s in &self.services {
            out.push(s.srv.clone());
            out.push(s.txt.clone());
        }
        out
    }

    /// All unique records to advertise on `iface`: its iface-specific host
    /// A/AAAA records plus all service-instance SRV/TXT records.
    pub fn unique_for_iface(&self, iface: &Iface) -> Vec<Record> {
        let mut out = self.host_records_for_iface(iface);
        out.extend(self.unique_service_records());
        out
    }
}

/// Build "goodbye" records (TTL=0) for graceful shutdown (RFC 6762 \u00a710.1).
pub fn goodbye(p: &Published) -> Vec<Record> {
    let mut out = Vec::new();
    let zero = |mut r: Record| {
        r.ttl = 0;
        r
    };
    out.extend(p.host_a.iter().cloned().map(zero));
    out.extend(p.host_aaaa.iter().cloned().map(zero));
    for s in &p.services {
        out.push(zero(s.ptr_type_to_instance.clone()));
        out.push(zero(s.srv.clone()));
        out.push(zero(s.txt.clone()));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ServiceConfig;
    use crate::iface::{ipv6_net, IfaceV4, IfaceV6};

    fn test_socket(addr: &str) -> tokio::net::UdpSocket {
        // We only need the address fields for these tests; build a synthetic
        // Iface using a dummy UDP socket.
        let std_sock = std::net::UdpSocket::bind(addr).unwrap();
        std_sock.set_nonblocking(true).unwrap();
        tokio::net::UdpSocket::from_std(std_sock).unwrap()
    }

    fn fake_iface(name: &str, ip: [u8; 4]) -> Arc<Iface> {
        let addr = Ipv4Addr::from(ip);
        Arc::new(Iface {
            name: name.into(),
            ifindex: 0,
            v4: Some(IfaceV4 {
                addr,
                mask: Ipv4Addr::new(255, 255, 255, 0),
                net: Ipv4Addr::from([ip[0], ip[1], ip[2], 0]),
                send: test_socket("127.0.0.1:0"),
            }),
            v6: None,
        })
    }

    fn fake_dual_iface(name: &str, ip: [u8; 4], ip6: Ipv6Addr) -> Arc<Iface> {
        let addr = Ipv4Addr::from(ip);
        Arc::new(Iface {
            name: name.into(),
            ifindex: 0,
            v4: Some(IfaceV4 {
                addr,
                mask: Ipv4Addr::new(255, 255, 255, 0),
                net: Ipv4Addr::from([ip[0], ip[1], ip[2], 0]),
                send: test_socket("127.0.0.1:0"),
            }),
            v6: Some(IfaceV6 {
                addr: ip6,
                prefix_len: 64,
                net: ipv6_net(ip6, 64),
                scope_id: 1,
                send: test_socket("[::1]:0"),
            }),
        })
    }

    #[tokio::test]
    async fn build_publishes_host_a_and_services() {
        let host = Name::from_str("router.local.").unwrap();
        let svcs = vec![ServiceConfig {
            name: "Admin".into(),
            service: "_http._tcp.local.".into(),
            port: 80,
            txt: vec!["path=/".into()],
            host: None,
        }];
        let ifs = vec![fake_iface("eth0", [10, 0, 0, 1])];
        let p = build(host.clone(), &svcs, &ifs).unwrap();
        assert_eq!(p.host_a.len(), 1);
        assert!(p.host_aaaa.is_empty());
        assert_eq!(p.services.len(), 1);

        // ANY query for hostname returns A
        let ans = p.answer(&host, RecordType::ANY);
        assert!(ans.iter().any(|r| r.record_type() == RecordType::A));

        // PTR query for service type returns instance pointer
        let svc_type = Name::from_str("_http._tcp.local.").unwrap();
        let ans = p.answer(&svc_type, RecordType::PTR);
        assert_eq!(ans.len(), 1);
    }

    #[tokio::test]
    async fn build_publishes_host_aaaa() {
        let host = Name::from_str("router.local.").unwrap();
        let ip6 = Ipv6Addr::from(0xfe80_0000_0000_0000_0000_0000_0000_0001u128);
        let ifs = vec![fake_dual_iface("eth0", [10, 0, 0, 1], ip6)];
        let p = build(host.clone(), &[], &ifs).unwrap();

        assert_eq!(p.host_a.len(), 1);
        assert_eq!(p.host_aaaa.len(), 1);
        assert!(p.host_aaaa[0].mdns_cache_flush);

        let aaaa = p.answer(&host, RecordType::AAAA);
        assert_eq!(aaaa.len(), 1);
        assert_eq!(aaaa[0].record_type(), RecordType::AAAA);
        let any = p.answer(&host, RecordType::ANY);
        assert!(any.iter().any(|r| r.record_type() == RecordType::A));
        assert!(any.iter().any(|r| r.record_type() == RecordType::AAAA));
    }

    #[tokio::test]
    async fn goodbye_zeroes_ttl() {
        let host = Name::from_str("r.local.").unwrap();
        let ifs = vec![fake_iface("eth0", [10, 0, 0, 1])];
        let p = build(host, &[], &ifs).unwrap();
        let g = goodbye(&p);
        assert!(g.iter().all(|r| r.ttl == 0));
    }
}
