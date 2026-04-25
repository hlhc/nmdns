//! Per-interface mDNS socket setup and IO.
//!
//! Architecture:
//!
//!   * One **shared receive socket** bound to `0.0.0.0:5353`, joined to
//!     `224.0.0.251` on every monitored interface, with `IP_PKTINFO` enabled
//!     so we know which interface received each packet.
//!   * One **per-interface send socket** bound to that interface's address,
//!     used to send outbound multicast/unicast on a specific link.
//!
//! The receive socket is wrapped in [`tokio::io::unix::AsyncFd`] so we can use
//! `nix::sys::socket::recvmsg` (needed to read `IP_PKTINFO` ancillary data)
//! while remaining async.

use std::io::{self, IoSliceMut};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::os::fd::{AsRawFd, RawFd};
use std::sync::Arc;

use nix::ifaddrs::getifaddrs;
use nix::net::if_::if_nametoindex;
use nix::sys::socket::{recvmsg, setsockopt, sockopt, ControlMessageOwned, MsgFlags, SockaddrIn};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::io::unix::AsyncFd;
use tokio::net::UdpSocket;

pub const MDNS_ADDR: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
pub const MDNS_PORT: u16 = 5353;
pub const MDNS_SOCKADDR: SocketAddrV4 = SocketAddrV4::new(MDNS_ADDR, MDNS_PORT);
pub const MAX_PACKET: usize = 9000; // jumbo-frame safe

/// Static description of one of our interfaces.
#[derive(Debug)]
pub struct Iface {
    pub name: String,
    pub ifindex: u32,
    pub addr: Ipv4Addr,
    pub mask: Ipv4Addr,
    pub net: Ipv4Addr,
    /// Per-interface send socket, bound to `addr:5353`. Multicast IF is set
    /// to this interface so outgoing multicast egresses on the right link.
    pub send: UdpSocket,
}

impl Iface {
    pub fn contains(&self, ip: Ipv4Addr) -> bool {
        (u32::from(ip) & u32::from(self.mask)) == u32::from(self.net)
    }

    /// Send `bytes` to the mDNS multicast address (`224.0.0.251:5353`)
    /// out of this interface's send socket.
    pub async fn send_mdns(&self, bytes: &[u8]) -> io::Result<usize> {
        self.send.send_to(bytes, MDNS_SOCKADDR).await
    }
}

/// One shared receive socket, wrapped for async IO.
pub struct RecvSocket {
    inner: AsyncFd<Socket>,
}

/// A datagram with metadata extracted from ancillary data.
#[derive(Debug)]
pub struct Datagram {
    pub data: Vec<u8>,
    pub source: SocketAddrV4,
    pub recv_ifindex: Option<u32>,
}

/// Look up an interface's primary IPv4 address and netmask.
fn iface_addr_mask(ifname: &str) -> io::Result<(Ipv4Addr, Ipv4Addr)> {
    let addrs = getifaddrs().map_err(io::Error::from)?;
    let mut found_addr: Option<Ipv4Addr> = None;
    let mut found_mask: Option<Ipv4Addr> = None;
    for ifa in addrs {
        if ifa.interface_name != ifname {
            continue;
        }
        let a = ifa
            .address
            .and_then(|s| s.as_sockaddr_in().map(|si| si.ip()));
        if let Some(a) = a {
            if found_addr.is_none() {
                found_addr = Some(a);
                found_mask = ifa
                    .netmask
                    .and_then(|s| s.as_sockaddr_in().map(|si| si.ip()));
            }
        }
    }
    match (found_addr, found_mask) {
        (Some(a), Some(m)) => Ok((a, m)),
        (Some(a), None) => Ok((a, Ipv4Addr::new(255, 255, 255, 0))),
        _ => Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("no IPv4 address for interface {ifname}"),
        )),
    }
}

/// Build the shared receive socket bound to `0.0.0.0:5353`.
fn build_recv_socket() -> io::Result<Socket> {
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

    // Ancillary data: receiving ifindex via IP_PKTINFO.
    setsockopt(&sock, sockopt::Ipv4PacketInfo, &true).map_err(io::Error::from)?;
    Ok(sock)
}

/// Build a per-interface send socket bound to `iface_addr:5353`.
fn build_send_socket(name: &str, addr: Ipv4Addr) -> io::Result<Socket> {
    let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;

    #[cfg(target_os = "linux")]
    {
        let _ = name; // bind_device used below
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
    // RFC 6762 §11: TTL=255 on outgoing mDNS.
    sock.set_multicast_ttl_v4(255)?;
    sock.set_nonblocking(true)?;
    Ok(sock)
}

/// Build the receive socket and one [`Iface`] per interface name.
pub fn setup(ifnames: &[String]) -> io::Result<(RecvSocket, Vec<Arc<Iface>>)> {
    let recv = build_recv_socket()?;
    let mut ifaces = Vec::with_capacity(ifnames.len());

    for name in ifnames {
        let (addr, mask) = iface_addr_mask(name)?;
        let net = Ipv4Addr::from(u32::from(addr) & u32::from(mask));
        let ifindex = if_nametoindex(name.as_str()).map_err(io::Error::from)?;

        let send = build_send_socket(name, addr)?;

        // Drop-then-add multicast membership to recover from driver
        // wedges where a join silently fails after the link flaps
        // (avahi/mdnsd workaround).
        let _ = recv.leave_multicast_v4(&MDNS_ADDR, &addr);
        recv.join_multicast_v4(&MDNS_ADDR, &addr)?;

        let send_std: std::net::UdpSocket = send.into();
        let send = UdpSocket::from_std(send_std)?;

        tracing::info!(
            ifname = %name,
            addr = %addr,
            mask = %mask,
            net = %net,
            ifindex = ifindex,
            "interface ready"
        );

        ifaces.push(Arc::new(Iface {
            name: name.clone(),
            ifindex,
            addr,
            mask,
            net,
            send,
        }));
    }

    Ok((
        RecvSocket {
            inner: AsyncFd::new(recv)?,
        },
        ifaces,
    ))
}

impl RecvSocket {
    /// Wait for, and read, the next datagram. Returns the payload, source
    /// address, and the receiving interface index (when the kernel provided
    /// it via IP_PKTINFO).
    pub async fn recv(&self) -> io::Result<Datagram> {
        loop {
            let mut guard = self.inner.readable().await?;
            // Use try_io so AsyncFd correctly clears the readiness flag if
            // the underlying syscall returns WouldBlock.
            let result = guard.try_io(|sock| do_recvmsg(sock.get_ref().as_raw_fd()));
            match result {
                Ok(Ok(d)) => return Ok(d),
                Ok(Err(e)) => return Err(e),
                Err(_would_block) => continue,
            }
        }
    }
}

fn do_recvmsg(fd: RawFd) -> io::Result<Datagram> {
    let mut buf = vec![0u8; MAX_PACKET];
    let mut cmsg = vec![0u8; 256];
    let mut iov = [IoSliceMut::new(&mut buf)];

    let msg = recvmsg::<SockaddrIn>(fd, &mut iov, Some(&mut cmsg), MsgFlags::empty())
        .map_err(io::Error::from)?;

    let size = msg.bytes;
    let source = match msg.address {
        Some(sa) => SocketAddrV4::new(sa.ip(), sa.port()),
        None => return Err(io::Error::new(io::ErrorKind::InvalidData, "no source addr")),
    };

    let mut recv_ifindex = None;
    if let Ok(iter) = msg.cmsgs() {
        for c in iter {
            if let ControlMessageOwned::Ipv4PacketInfo(p) = c {
                recv_ifindex = Some(p.ipi_ifindex);
            }
        }
    }

    buf.truncate(size);
    Ok(Datagram {
        data: buf,
        source,
        recv_ifindex,
    })
}
