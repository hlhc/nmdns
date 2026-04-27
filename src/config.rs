//! TOML configuration file parsing.
//!
//! See [`Resolved`] for the public type. The unexported `RawConfig` is the
//! shape `serde` deserializes; [`Resolved::parse`] turns it into the
//! validated, post-processed type used by the rest of the daemon.
//!
//! **IPv4-only.** All address-bearing config keys (`blacklist`,
//! `whitelist`) must be IPv4 CIDRs; IPv6 support is on the roadmap but
//! not yet wired through the socket layer.

use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("read config {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("parse config: {0}")]
    Parse(#[from] toml::de::Error),
    #[error("invalid subnet {0}: {1}")]
    BadSubnet(String, &'static str),
    #[error("config requires at least one interface")]
    NoInterfaces,
    #[error("blacklist and whitelist are mutually exclusive")]
    BlackAndWhite,
}

/// Raw TOML shape; produced by serde, then post-validated into [`Resolved`].
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    interfaces: Vec<String>,
    #[serde(default = "default_true")]
    repeat: bool,
    #[serde(default = "default_true")]
    answer_from_cache: bool,
    #[serde(default)]
    blacklist: Vec<String>,
    #[serde(default)]
    whitelist: Vec<String>,
    #[serde(default)]
    hostname: Option<String>,
    #[serde(default = "default_browse")]
    browse: Vec<String>,
    #[serde(default = "default_browse_secs")]
    browse_interval_secs: u64,
    #[serde(default = "default_cache_tick")]
    cache_tick_secs: u64,
    #[serde(default = "default_max_cache_entries")]
    max_cache_entries: usize,
    #[serde(default, rename = "service")]
    services: Vec<ServiceConfig>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceConfig {
    /// Instance name shown to users, e.g. "Router Admin".
    pub name: String,
    /// Service type, e.g. "_http._tcp.local.".
    pub service: String,
    /// TCP/UDP port.
    pub port: u16,
    /// TXT record key=value entries.
    #[serde(default)]
    pub txt: Vec<String>,
    /// Override the hostname this service points at. Defaults to the daemon
    /// hostname.
    #[serde(default)]
    pub host: Option<String>,
}

fn default_true() -> bool {
    true
}
fn default_browse_secs() -> u64 {
    60
}
fn default_browse() -> Vec<String> {
    vec!["_services._dns-sd._udp.local.".to_string()]
}
fn default_cache_tick() -> u64 {
    5
}
fn default_max_cache_entries() -> usize {
    crate::cache::DEFAULT_MAX_ENTRIES
}

/// IPv4 CIDR-style subnet (used for blacklist/whitelist filters).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Subnet {
    pub addr: Ipv4Addr,
    pub mask: Ipv4Addr,
    pub net: Ipv4Addr,
}

impl Subnet {
    pub fn matches(&self, ip: Ipv4Addr) -> bool {
        (u32::from(ip) & u32::from(self.mask)) == u32::from(self.net)
    }
}

pub fn parse_subnet(s: &str) -> Result<Subnet, ConfigError> {
    // IPv6 not supported yet; reject obvious IPv6 literals up front so the
    // error message is helpful instead of "bad address".
    if s.contains(':') {
        return Err(ConfigError::BadSubnet(
            s.to_string(),
            "IPv6 not supported (IPv4 CIDR only)",
        ));
    }
    let (addr_s, mask_s) = s
        .split_once('/')
        .ok_or_else(|| ConfigError::BadSubnet(s.to_string(), "missing /"))?;
    let addr: Ipv4Addr = addr_s
        .parse()
        .map_err(|_| ConfigError::BadSubnet(s.to_string(), "bad IPv4 address"))?;
    let bits: u32 = mask_s
        .parse()
        .map_err(|_| ConfigError::BadSubnet(s.to_string(), "bad mask"))?;
    if bits > 32 {
        return Err(ConfigError::BadSubnet(s.to_string(), "mask > 32"));
    }
    let mask_u = if bits == 0 {
        0
    } else {
        0xFFFF_FFFFu32 << (32 - bits)
    };
    let mask = Ipv4Addr::from(mask_u);
    let net = Ipv4Addr::from(u32::from(addr) & mask_u);
    Ok(Subnet { addr, mask, net })
}

/// Validated runtime configuration.
#[derive(Debug)]
pub struct Resolved {
    pub interfaces: Vec<String>,
    pub repeat: bool,
    pub answer_from_cache: bool,
    pub hostname: Option<String>,
    pub browse: Vec<String>,
    pub browse_interval_secs: u64,
    pub cache_tick_secs: u64,
    pub max_cache_entries: usize,
    pub services: Vec<ServiceConfig>,
    pub blacklist: Vec<Subnet>,
    pub whitelist: Vec<Subnet>,
}

impl Resolved {
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let body = std::fs::read_to_string(path).map_err(|e| ConfigError::Io {
            path: path.to_path_buf(),
            source: e,
        })?;
        Self::parse(&body)
    }

    /// Parse and validate a TOML document into a [`Resolved`] config.
    ///
    /// Service-instance names are deliberately *not* string-validated
    /// here (DNS-SD allows spaces and other punctuation per RFC 6763
    /// §4.1.1). They are validated as DNS labels later, in
    /// [`crate::services::build`].
    pub fn parse(body: &str) -> Result<Self, ConfigError> {
        let raw: RawConfig = toml::from_str(body)?;
        if raw.interfaces.is_empty() {
            return Err(ConfigError::NoInterfaces);
        }
        if !raw.blacklist.is_empty() && !raw.whitelist.is_empty() {
            return Err(ConfigError::BlackAndWhite);
        }
        let blacklist = raw
            .blacklist
            .iter()
            .map(|s| parse_subnet(s))
            .collect::<Result<_, _>>()?;
        let whitelist = raw
            .whitelist
            .iter()
            .map(|s| parse_subnet(s))
            .collect::<Result<_, _>>()?;
        Ok(Resolved {
            interfaces: raw.interfaces,
            repeat: raw.repeat,
            answer_from_cache: raw.answer_from_cache,
            hostname: raw.hostname,
            browse: raw.browse,
            browse_interval_secs: raw.browse_interval_secs,
            cache_tick_secs: raw.cache_tick_secs,
            max_cache_entries: raw.max_cache_entries,
            services: raw.services,
            blacklist,
            whitelist,
        })
    }

    /// Returns true if `ip` is allowed by the configured filters.
    pub fn allow_source(&self, ip: Ipv4Addr) -> bool {
        if !self.whitelist.is_empty() {
            self.whitelist.iter().any(|s| s.matches(ip))
        } else {
            !self.blacklist.iter().any(|s| s.matches(ip))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_subnet_ok() {
        let s = parse_subnet("10.0.0.5/8").unwrap();
        assert_eq!(s.net, Ipv4Addr::new(10, 0, 0, 0));
        assert!(s.matches(Ipv4Addr::new(10, 1, 2, 3)));
        assert!(!s.matches(Ipv4Addr::new(11, 0, 0, 1)));
    }

    #[test]
    fn parse_subnet_zero_means_any() {
        let s = parse_subnet("0.0.0.0/0").unwrap();
        assert!(s.matches(Ipv4Addr::new(8, 8, 8, 8)));
    }

    #[test]
    fn parse_subnet_rejects_bad() {
        assert!(parse_subnet("10.0.0.0").is_err());
        assert!(parse_subnet("999.0.0.0/24").is_err());
        assert!(parse_subnet("10.0.0.0/33").is_err());
    }

    #[test]
    fn config_minimal() {
        let r = Resolved::parse(r#"interfaces = ["eth0"]"#).unwrap();
        assert_eq!(r.interfaces, vec!["eth0"]);
        assert!(r.repeat);
        assert!(r.answer_from_cache);
        assert_eq!(r.browse, vec!["_services._dns-sd._udp.local."]);
        assert!(r.services.is_empty());
    }

    #[test]
    fn config_full() {
        let body = r#"
            interfaces = ["br-lan", "br-iot"]
            blacklist  = ["192.168.5.0/24"]
            hostname   = "router"
            browse     = ["_http._tcp.local."]

            [[service]]
            name = "Admin"
            service = "_http._tcp.local."
            port = 80
            txt = ["path=/"]
        "#;
        let r = Resolved::parse(body).unwrap();
        assert_eq!(r.blacklist.len(), 1);
        assert_eq!(r.services.len(), 1);
        assert_eq!(r.services[0].port, 80);
    }

    #[test]
    fn config_rejects_no_interfaces() {
        let r = Resolved::parse("interfaces = []");
        assert!(matches!(r, Err(ConfigError::NoInterfaces)));
    }

    #[test]
    fn config_rejects_black_and_white() {
        let body = r#"
            interfaces = ["eth0"]
            blacklist = ["10.0.0.0/8"]
            whitelist = ["192.168.0.0/16"]
        "#;
        assert!(matches!(
            Resolved::parse(body),
            Err(ConfigError::BlackAndWhite)
        ));
    }

    #[test]
    fn config_rejects_ipv6_cidr() {
        let r = parse_subnet("::1/128");
        assert!(matches!(r, Err(ConfigError::BadSubnet(_, _))));
    }
}
