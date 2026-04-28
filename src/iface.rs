//! Per-interface mDNS socket setup and IO.
//!
//! Architecture:
//!
//!   * One shared IPv4 receive socket bound to `0.0.0.0:5353` when any
//!     monitored interface has IPv4, joined to `224.0.0.251` on each IPv4
//!     interface, with `IP_PKTINFO` enabled.
//!   * One shared IPv6 receive socket bound to `[::]:5353` when any monitored
//!     interface has IPv6, joined to `ff02::fb` on each IPv6 interface, with
//!     `IPV6_PKTINFO` enabled.
//!   * Per-interface send sockets for each address family the interface can
//!     use. Multicast egress is pinned to the configured interface.

use std::io::{self, IoSliceMut};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::os::fd::{AsRawFd, RawFd};
use std::sync::Arc;

use nix::ifaddrs::getifaddrs;
use nix::net::if_::if_nametoindex;
use nix::sys::socket::{
    recvmsg, setsockopt, sockopt, ControlMessageOwned, MsgFlags, SockaddrIn, SockaddrIn6,
};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::io::unix::AsyncFd;
use tokio::net::UdpSocket;

pub const MDNS_ADDR_V4: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
pub const MDNS_ADDR_V6: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0x00fb);
pub const MDNS_PORT: u16 = 5353;
pub const MDNS_SOCKADDR_V4: SocketAddrV4 = SocketAddrV4::new(MDNS_ADDR_V4, MDNS_PORT);
pub const MDNS_SOCKADDR_V6: SocketAddrV6 = SocketAddrV6::new(MDNS_ADDR_V6, MDNS_PORT, 0, 0);
pub const MAX_PACKET: usize = 9000; // jumbo-frame safe

/// Backward-compatible names for the IPv4 mDNS address and socket address.
pub const MDNS_ADDR: Ipv4Addr = MDNS_ADDR_V4;
pub const MDNS_SOCKADDR: SocketAddrV4 = MDNS_SOCKADDR_V4;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IpFamily {
    V4,
    V6,
}

#[derive(Debug)]
pub struct IfaceV4 {
    pub addr: Ipv4Addr,
    pub mask: Ipv4Addr,
    pub net: Ipv4Addr,
    /// Per-interface send socket, bound to `addr:5353`.
    pub send: UdpSocket,
}

#[derive(Debug)]
pub struct IfaceV6 {
    pub addr: Ipv6Addr,
    pub prefix_len: u8,
    pub net: Ipv6Addr,
    pub scope_id: u32,
    /// Per-interface send socket, bound to `[addr%scope]:5353`.
    pub send: UdpSocket,
}

/// Static description of one of our interfaces.
#[derive(Debug)]
pub struct Iface {
    pub name: String,
    pub ifindex: u32,
    pub v4: Option<IfaceV4>,
    pub v6: Option<IfaceV6>,
}

impl Iface {
    pub fn addr_v4(&self) -> Option<Ipv4Addr> {
        self.v4.as_ref().map(|v4| v4.addr)
    }

    pub fn addr_v6(&self) -> Option<Ipv6Addr> {
        self.v6.as_ref().map(|v6| v6.addr)
    }

    pub fn has_addr(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(ip) => self.addr_v4() == Some(ip),
            IpAddr::V6(ip) => self.addr_v6() == Some(ip),
        }
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(ip) => self
                .v4
                .as_ref()
                .is_some_and(|v4| (u32::from(ip) & u32::from(v4.mask)) == u32::from(v4.net)),
            IpAddr::V6(ip) => self
                .v6
                .as_ref()
                .is_some_and(|v6| ipv6_net(ip, v6.prefix_len) == v6.net),
        }
    }

    pub fn families(&self) -> impl Iterator<Item = IpFamily> + '_ {
        [
            self.v4.as_ref().map(|_| IpFamily::V4),
            self.v6.as_ref().map(|_| IpFamily::V6),
        ]
        .into_iter()
        .flatten()
    }

    /// Send `bytes` to the mDNS multicast address for `family` out of this
    /// interface's matching send socket.
    pub async fn send_mdns_on(&self, family: IpFamily, bytes: &[u8]) -> io::Result<usize> {
        match family {
            IpFamily::V4 => {
                let Some(v4) = &self.v4 else {
                    return Err(io::Error::new(
                        io::ErrorKind::NotFound,
                        format!("interface {} has no IPv4 socket", self.name),
                    ));
                };
                v4.send.send_to(bytes, MDNS_SOCKADDR_V4).await
            }
            IpFamily::V6 => {
                let Some(v6) = &self.v6 else {
                    return Err(io::Error::new(
                        io::ErrorKind::NotFound,
                        format!("interface {} has no IPv6 socket", self.name),
                    ));
                };
                let scope_id = if v6.scope_id == 0 {
                    self.ifindex
                } else {
                    v6.scope_id
                };
                let dst = SocketAddrV6::new(MDNS_ADDR_V6, MDNS_PORT, 0, scope_id);
                v6.send.send_to(bytes, dst).await
            }
        }
    }

    /// Send `bytes` on every address family supported by this interface.
    /// Returns the number of successful sends.
    pub async fn send_mdns_all(&self, bytes: &[u8]) -> io::Result<usize> {
        let mut sent = 0usize;
        let mut last_err = None;
        for family in self.families() {
            match self.send_mdns_on(family, bytes).await {
                Ok(_) => sent += 1,
                Err(e) => last_err = Some(e),
            }
        }
        if sent > 0 {
            Ok(sent)
        } else {
            Err(last_err.unwrap_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("interface {} has no send sockets", self.name),
                )
            }))
        }
    }

    /// Compatibility wrapper for callers that should send on every supported
    /// family but only care that at least one multicast send succeeded.
    pub async fn send_mdns(&self, bytes: &[u8]) -> io::Result<usize> {
        self.send_mdns_all(bytes).await.map(|_| bytes.len())
    }
}

/// Shared receive sockets, wrapped for async IO.
pub struct RecvSocket {
    v4: Option<AsyncFd<Socket>>,
    v6: Option<AsyncFd<Socket>>,
}

/// A datagram with metadata extracted from ancillary data.
#[derive(Debug)]
pub struct Datagram {
    pub data: Vec<u8>,
    pub source: SocketAddr,
    pub family: IpFamily,
    pub recv_ifindex: Option<u32>,
}

#[derive(Debug, Clone, Copy)]
struct IfaceAddrV4 {
    addr: Ipv4Addr,
    mask: Ipv4Addr,
    net: Ipv4Addr,
}

#[derive(Debug, Clone, Copy)]
struct IfaceAddrV6 {
    addr: Ipv6Addr,
    prefix_len: u8,
    net: Ipv6Addr,
    scope_id: u32,
}

/// Look up an interface's usable IPv4 and IPv6 mDNS addresses.
fn iface_addrs(
    ifname: &str,
    ifindex: u32,
) -> io::Result<(Option<IfaceAddrV4>, Option<IfaceAddrV6>)> {
    let addrs = getifaddrs().map_err(io::Error::from)?;
    let mut found_v4: Option<IfaceAddrV4> = None;
    let mut found_v6: Option<IfaceAddrV6> = None;

    for ifa in addrs {
        if ifa.interface_name != ifname {
            continue;
        }

        if found_v4.is_none() {
            if let Some(addr) = ifa.address.as_ref().and_then(|s| s.as_sockaddr_in()) {
                let ip = addr.ip();
                let mask = ifa
                    .netmask
                    .as_ref()
                    .and_then(|s| s.as_sockaddr_in().map(|si| si.ip()))
                    .unwrap_or_else(|| Ipv4Addr::new(255, 255, 255, 0));
                found_v4 = Some(IfaceAddrV4 {
                    addr: ip,
                    mask,
                    net: Ipv4Addr::from(u32::from(ip) & u32::from(mask)),
                });
            }
        }

        if found_v6.is_none() {
            if let Some(addr) = ifa.address.as_ref().and_then(|s| s.as_sockaddr_in6()) {
                let ip = addr.ip();
                if !is_unicast_link_local_v6(ip) {
                    continue;
                }
                let prefix_len = ifa
                    .netmask
                    .as_ref()
                    .and_then(|s| s.as_sockaddr_in6().map(|si| ipv6_prefix_len(si.ip())))
                    .unwrap_or(64);
                let scope_id = if addr.scope_id() == 0 {
                    ifindex
                } else {
                    addr.scope_id()
                };
                found_v6 = Some(IfaceAddrV6 {
                    addr: ip,
                    prefix_len,
                    net: ipv6_net(ip, prefix_len),
                    scope_id,
                });
            }
        }

        if found_v4.is_some() && found_v6.is_some() {
            break;
        }
    }

    Ok((found_v4, found_v6))
}

fn is_unicast_link_local_v6(addr: Ipv6Addr) -> bool {
    let first = addr.segments()[0];
    (first & 0xffc0) == 0xfe80
}

fn ipv6_prefix_len(mask: Ipv6Addr) -> u8 {
    let mut bits = 0u8;
    for byte in mask.octets() {
        if byte == 0xff {
            bits += 8;
        } else {
            bits += byte.leading_ones() as u8;
            break;
        }
    }
    bits
}

pub fn ipv6_net(addr: Ipv6Addr, prefix_len: u8) -> Ipv6Addr {
    let addr = u128::from_be_bytes(addr.octets());
    let mask = if prefix_len == 0 {
        0
    } else {
        u128::MAX << (128 - prefix_len)
    };
    Ipv6Addr::from(addr & mask)
}

/// Build the shared IPv4 receive socket bound to `0.0.0.0:5353`.
fn build_recv_socket_v4() -> io::Result<Socket> {
    let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    sock.set_reuse_address(true)?;
    #[cfg(any(target_os = "macos", target_os = "freebsd"))]
    {
        let _ = sock.set_reuse_port(true);
    }
    let bind = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, MDNS_PORT);
    sock.bind(&bind.into())?;
    sock.set_multicast_loop_v4(true)?;
    sock.set_nonblocking(true)?;

    setsockopt(&sock, sockopt::Ipv4PacketInfo, &true).map_err(io::Error::from)?;
    Ok(sock)
}

/// Build the shared IPv6 receive socket bound to `[::]:5353`.
fn build_recv_socket_v6() -> io::Result<Socket> {
    let sock = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
    sock.set_only_v6(true)?;
    sock.set_reuse_address(true)?;
    #[cfg(any(target_os = "macos", target_os = "freebsd"))]
    {
        let _ = sock.set_reuse_port(true);
    }
    let bind = SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, MDNS_PORT, 0, 0);
    sock.bind(&bind.into())?;
    sock.set_multicast_loop_v6(true)?;
    sock.set_nonblocking(true)?;

    setsockopt(&sock, sockopt::Ipv6RecvPacketInfo, &true).map_err(io::Error::from)?;
    Ok(sock)
}

/// Build a per-interface IPv4 send socket bound to `iface_addr:5353`.
fn build_send_socket_v4(name: &str, addr: Ipv4Addr) -> io::Result<Socket> {
    let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;

    #[cfg(target_os = "linux")]
    {
        let _ = name;
        sock.bind_device(Some(name.as_bytes()))?;
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = name;
    }

    sock.set_reuse_address(true)?;
    #[cfg(any(target_os = "macos", target_os = "freebsd"))]
    {
        let _ = sock.set_reuse_port(true);
    }

    let bind = SocketAddrV4::new(addr, MDNS_PORT);
    sock.bind(&bind.into())?;
    sock.set_multicast_if_v4(&addr)?;
    sock.set_multicast_loop_v4(true)?;
    sock.set_multicast_ttl_v4(255)?;
    sock.set_nonblocking(true)?;
    Ok(sock)
}

/// Build a per-interface IPv6 send socket bound to `[iface_addr%scope]:5353`.
fn build_send_socket_v6(
    name: &str,
    addr: Ipv6Addr,
    ifindex: u32,
    scope_id: u32,
) -> io::Result<Socket> {
    let sock = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
    sock.set_only_v6(true)?;

    #[cfg(target_os = "linux")]
    {
        let _ = name;
        sock.bind_device(Some(name.as_bytes()))?;
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = name;
    }

    sock.set_reuse_address(true)?;
    #[cfg(any(target_os = "macos", target_os = "freebsd"))]
    {
        let _ = sock.set_reuse_port(true);
    }

    let bind = SocketAddrV6::new(addr, MDNS_PORT, 0, scope_id);
    sock.bind(&bind.into())?;
    sock.set_multicast_if_v6(ifindex)?;
    sock.set_multicast_loop_v6(true)?;
    sock.set_multicast_hops_v6(255)?;
    sock.set_unicast_hops_v6(255)?;
    sock.set_nonblocking(true)?;
    Ok(sock)
}

/// Build the receive sockets and one [`Iface`] per interface name.
pub fn setup(ifnames: &[String]) -> io::Result<(RecvSocket, Vec<Arc<Iface>>)> {
    let mut discovered = Vec::with_capacity(ifnames.len());
    let mut have_v4 = false;
    let mut have_v6 = false;

    for name in ifnames {
        let ifindex = if_nametoindex(name.as_str()).map_err(io::Error::from)?;
        let (v4, v6) = iface_addrs(name, ifindex)?;
        if v4.is_none() && v6.is_none() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("no IPv4 or link-local IPv6 address for interface {name}"),
            ));
        }
        have_v4 |= v4.is_some();
        have_v6 |= v6.is_some();
        discovered.push((name.clone(), ifindex, v4, v6));
    }

    let recv_v4 = if have_v4 {
        Some(build_recv_socket_v4()?)
    } else {
        None
    };
    let recv_v6 = if have_v6 {
        Some(build_recv_socket_v6()?)
    } else {
        None
    };
    let mut ifaces = Vec::with_capacity(discovered.len());

    for (name, ifindex, v4_meta, v6_meta) in discovered {
        let v4 = if let Some(meta) = v4_meta {
            let send = build_send_socket_v4(&name, meta.addr)?;
            if let Some(recv) = &recv_v4 {
                let _ = recv.leave_multicast_v4(&MDNS_ADDR_V4, &meta.addr);
                recv.join_multicast_v4(&MDNS_ADDR_V4, &meta.addr)?;
            }
            let send_std: std::net::UdpSocket = send.into();
            Some(IfaceV4 {
                addr: meta.addr,
                mask: meta.mask,
                net: meta.net,
                send: UdpSocket::from_std(send_std)?,
            })
        } else {
            None
        };

        let v6 = if let Some(meta) = v6_meta {
            let send = build_send_socket_v6(&name, meta.addr, ifindex, meta.scope_id)?;
            if let Some(recv) = &recv_v6 {
                let _ = recv.leave_multicast_v6(&MDNS_ADDR_V6, ifindex);
                recv.join_multicast_v6(&MDNS_ADDR_V6, ifindex)?;
            }
            let send_std: std::net::UdpSocket = send.into();
            Some(IfaceV6 {
                addr: meta.addr,
                prefix_len: meta.prefix_len,
                net: meta.net,
                scope_id: meta.scope_id,
                send: UdpSocket::from_std(send_std)?,
            })
        } else {
            None
        };

        tracing::info!(
            ifname = %name,
            ifindex = ifindex,
            addr_v4 = ?v4.as_ref().map(|v4| v4.addr),
            addr_v6 = ?v6.as_ref().map(|v6| v6.addr),
            "interface ready"
        );

        ifaces.push(Arc::new(Iface {
            name,
            ifindex,
            v4,
            v6,
        }));
    }

    Ok((
        RecvSocket {
            v4: recv_v4.map(AsyncFd::new).transpose()?,
            v6: recv_v6.map(AsyncFd::new).transpose()?,
        },
        ifaces,
    ))
}

impl RecvSocket {
    /// Wait for, and read, the next datagram. Returns the payload, source
    /// address, address family, and receiving interface index when provided.
    pub async fn recv(&self) -> io::Result<Datagram> {
        match (&self.v4, &self.v6) {
            (Some(v4), Some(v6)) => tokio::select! {
                r = recv_one(v4, IpFamily::V4) => r,
                r = recv_one(v6, IpFamily::V6) => r,
            },
            (Some(v4), None) => recv_one(v4, IpFamily::V4).await,
            (None, Some(v6)) => recv_one(v6, IpFamily::V6).await,
            (None, None) => Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "no receive sockets configured",
            )),
        }
    }
}

async fn recv_one(inner: &AsyncFd<Socket>, family: IpFamily) -> io::Result<Datagram> {
    loop {
        let mut guard = inner.readable().await?;
        let result = guard.try_io(|sock| match family {
            IpFamily::V4 => do_recvmsg_v4(sock.get_ref().as_raw_fd()),
            IpFamily::V6 => do_recvmsg_v6(sock.get_ref().as_raw_fd()),
        });
        match result {
            Ok(Ok(d)) => return Ok(d),
            Ok(Err(e)) => return Err(e),
            Err(_would_block) => continue,
        }
    }
}

fn do_recvmsg_v4(fd: RawFd) -> io::Result<Datagram> {
    let mut buf = vec![0u8; MAX_PACKET];
    let mut cmsg = vec![0u8; 256];
    let mut iov = [IoSliceMut::new(&mut buf)];

    let msg = recvmsg::<SockaddrIn>(fd, &mut iov, Some(&mut cmsg), MsgFlags::empty())
        .map_err(io::Error::from)?;

    let size = msg.bytes;
    let source = match msg.address {
        Some(sa) => SocketAddr::V4(SocketAddrV4::new(sa.ip(), sa.port())),
        None => return Err(io::Error::new(io::ErrorKind::InvalidData, "no source addr")),
    };

    let mut recv_ifindex = None;
    if let Ok(iter) = msg.cmsgs() {
        for c in iter {
            if let ControlMessageOwned::Ipv4PacketInfo(p) = c {
                recv_ifindex = Some(p.ipi_ifindex as u32);
            }
        }
    }

    buf.truncate(size);
    Ok(Datagram {
        data: buf,
        source,
        family: IpFamily::V4,
        recv_ifindex,
    })
}

fn do_recvmsg_v6(fd: RawFd) -> io::Result<Datagram> {
    let mut buf = vec![0u8; MAX_PACKET];
    let mut cmsg = vec![0u8; 256];
    let mut iov = [IoSliceMut::new(&mut buf)];

    let msg = recvmsg::<SockaddrIn6>(fd, &mut iov, Some(&mut cmsg), MsgFlags::empty())
        .map_err(io::Error::from)?;

    let size = msg.bytes;
    let source = match msg.address {
        Some(sa) => SocketAddr::V6(SocketAddrV6::new(
            sa.ip(),
            sa.port(),
            sa.flowinfo(),
            sa.scope_id(),
        )),
        None => return Err(io::Error::new(io::ErrorKind::InvalidData, "no source addr")),
    };

    let mut recv_ifindex = None;
    if let Ok(iter) = msg.cmsgs() {
        for c in iter {
            if let ControlMessageOwned::Ipv6PacketInfo(p) = c {
                recv_ifindex = Some(p.ipi6_ifindex as u32);
            }
        }
    }

    buf.truncate(size);
    Ok(Datagram {
        data: buf,
        source,
        family: IpFamily::V6,
        recv_ifindex,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv6_net_applies_prefix() {
        let addr = Ipv6Addr::from(0xfe80_0000_0000_0001_1234_5678_9abc_def0u128);
        assert_eq!(
            ipv6_net(addr, 64),
            Ipv6Addr::from(0xfe80_0000_0000_0001_0000_0000_0000_0000u128)
        );
        assert_eq!(ipv6_net(addr, 0), Ipv6Addr::UNSPECIFIED);
        assert_eq!(ipv6_net(addr, 128), addr);
    }

    #[test]
    fn ipv6_mdns_multicast_constant_is_ff02_fb() {
        assert_eq!(MDNS_ADDR_V6, Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0xfb));
        assert_eq!(MDNS_SOCKADDR_V6.port(), MDNS_PORT);
    }

    #[test]
    #[ignore = "requires a real IPv6-capable interface and UDP/5353 privileges"]
    fn ignored_real_ipv6_multicast_socket_setup() {
        let Ok(ifname) = std::env::var("NMDNS_IPV6_TEST_IFACE") else {
            eprintln!("set NMDNS_IPV6_TEST_IFACE to run this socket smoke test");
            return;
        };
        let (_recv, ifaces) = setup(&[ifname]).expect("real IPv6 multicast setup");
        assert!(
            ifaces.iter().any(|iface| iface.v6.is_some()),
            "configured interface should have a usable link-local IPv6 address"
        );
    }
}
