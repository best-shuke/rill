//! Linux kernel TCP termination through a packet-level port NAT. UDP and
//! ICMP still use lwIP (`system` currently has the same meaning as `mixed`).

#[cfg(target_os = "linux")]
mod nat;
#[cfg(any(target_os = "linux", test))]
mod packet;
mod stream;

pub(super) use stream::accept_tcp;

#[cfg(target_os = "linux")]
pub(super) use nat::Lease;
#[cfg(not(target_os = "linux"))]
pub(super) struct Lease;

/// What a packet's TCP checksum field holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(
    not(target_os = "linux"),
    allow(dead_code, reason = "rewrites belong to the Linux backend")
)]
pub(in crate::tun) enum TcpChecksum {
    /// A complete checksum: every rewritten word updates it (RFC 1624).
    Full,
    /// CHECKSUM_PARTIAL — a virtio-net `NEEDS_CSUM` frame, which every GSO
    /// super-packet is: the field holds the folded, *uncomplemented*
    /// pseudo-header sum, and whoever completes it (the kernel segmenting
    /// the frame, or delivering it locally) sums the TCP header — ports
    /// included — on top. Only address words update the field.
    Partial,
}

#[derive(Debug, PartialEq, Eq)]
#[cfg_attr(
    not(target_os = "linux"),
    allow(dead_code, reason = "rewrite outcomes belong to the Linux backend")
)]
pub(super) enum Dispatch {
    ToStack,
    ToDevice,
    Drop,
}

#[cfg(target_os = "linux")]
pub(super) use linux::System;

#[cfg(target_os = "linux")]
mod linux {
    use std::io;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use ipnet::{Ipv4Net, Ipv6Net};
    use parking_lot::Mutex;
    use tokio::net::{TcpListener, TcpSocket, TcpStream};

    use super::nat::{Flow, Lease, Nat, Side};
    use super::packet::{Parsed, TcpPacket};
    use super::{Dispatch, TcpChecksum};

    struct Endpoint {
        listener: TcpListener,
        local: SocketAddr,
        peer: IpAddr,
    }

    pub(in crate::tun) struct System {
        v4: Endpoint,
        v6: Option<Endpoint>,
        table: Arc<Mutex<Nat>>,
    }

    impl System {
        pub async fn new(
            enabled: bool,
            v4: Ipv4Net,
            v6: Option<Ipv6Net>,
            device: &str,
        ) -> io::Result<Option<Arc<Self>>> {
            if !enabled {
                return Ok(None);
            }
            let peer4 = peer_v4(v4)?;
            let v4 = Endpoint::bind(v4.addr().into(), peer4.into(), device).await?;
            let v6 = match v6 {
                Some(net) => {
                    let peer = peer_v6(net)?;
                    Some(Endpoint::bind(net.addr().into(), peer.into(), device).await?)
                }
                None => None,
            };
            tracing::info!(
                "tun system: kernel TCP on {}, NAT peer {}",
                v4.local,
                v4.peer
            );
            Ok(Some(Arc::new(Self {
                v4,
                v6,
                table: Arc::new(Mutex::new(Nat::new())),
            })))
        }

        /// The single ingress hook: rewritten packets go straight back
        /// into the device; everything else retains the existing pump.
        /// `p` is one IP packet — or, on an offload device, a whole GSO
        /// super-packet, which only needs its headers rewritten — whose
        /// TCP checksum field holds what `csum` says.
        pub fn dispatch(&self, p: &mut [u8], csum: TcpChecksum) -> Dispatch {
            let packet = match TcpPacket::parse(p) {
                Parsed::Tcp(packet) => packet,
                Parsed::Other => return Dispatch::ToStack,
                Parsed::Invalid => return Dispatch::Drop,
            };
            let endpoint = if packet.src.is_ipv4() {
                &self.v4
            } else {
                let Some(v6) = &self.v6 else {
                    return Dispatch::Drop;
                };
                v6
            };
            let mut table = self.table.lock();
            let now = Instant::now();
            table.expire(now);
            if packet.src == endpoint.local && packet.dst.ip() == endpoint.peer {
                let Some(flow) = table.reverse(packet.dst.port(), now) else {
                    return Dispatch::Drop;
                };
                // NAT ports are shared across families. A packet must
                // match the original family's listener as well as port.
                if flow.src.is_ipv4() != packet.src.is_ipv4() {
                    return Dispatch::Drop;
                }
                if packet.fin || packet.rst {
                    let port = packet.dst.port();
                    table.note_close(port, Side::Listener, packet.fin, packet.rst, now);
                }
                packet.rewrite(p, flow.dst, flow.src, csum);
            } else {
                let flow = Flow {
                    src: packet.src,
                    dst: packet.dst,
                };
                let Some(port) = table.port(flow, packet.syn && !packet.ack, now) else {
                    return Dispatch::Drop;
                };
                if packet.fin || packet.rst {
                    table.note_close(port, Side::Client, packet.fin, packet.rst, now);
                }
                packet.rewrite(
                    p,
                    SocketAddr::new(endpoint.peer, port),
                    endpoint.local,
                    csum,
                );
            }
            Dispatch::ToDevice
        }

        pub async fn accept(&self) -> io::Result<(TcpStream, Flow, Lease)> {
            loop {
                let accepted = tokio::select! {
                    accepted = self.v4.listener.accept() => accepted,
                    accepted = async {
                        match &self.v6 {
                            Some(v6) => v6.listener.accept().await,
                            None => std::future::pending().await,
                        }
                    } => accepted,
                    () = tokio::time::sleep(Duration::from_secs(1)) => {
                        self.table.lock().expire(Instant::now());
                        continue;
                    }
                };
                let (stream, peer) = accepted?;
                let expected = if peer.is_ipv4() {
                    self.v4.peer
                } else {
                    self.v6.as_ref().expect("IPv6 listener accepted").peer
                };
                if peer.ip() != expected {
                    continue;
                }
                let Some((flow, lease)) = Nat::accept(&self.table, peer.port()) else {
                    continue;
                };
                stream.set_nodelay(true)?;
                return Ok((stream, flow, lease));
            }
        }
    }

    impl Endpoint {
        async fn bind(ip: IpAddr, peer: IpAddr, device: &str) -> io::Result<Self> {
            let socket = if ip.is_ipv4() {
                TcpSocket::new_v4()?
            } else {
                TcpSocket::new_v6()?
            };
            // Accepted sockets inherit this binding. In global mode the
            // process's outbound binding belongs to physical interfaces;
            // these sockets must instead reply through the TUN.
            socket.bind_device(Some(device.as_bytes()))?;
            // Fresh IPv6 addresses may still be tentative during DAD.
            // Keep this bounded by the listener's startup timeout.
            let mut attempts = 0;
            loop {
                match socket.bind(SocketAddr::new(ip, 0)) {
                    Err(e)
                        if ip.is_ipv6()
                            && e.kind() == io::ErrorKind::AddrNotAvailable
                            && attempts < 30 =>
                    {
                        attempts += 1;
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                    result => {
                        result?;
                        break;
                    }
                }
            }
            let listener = socket.listen(4096)?;
            Ok(Self {
                local: listener.local_addr()?,
                listener,
                peer,
            })
        }
    }

    fn peer_v4(net: Ipv4Net) -> io::Result<Ipv4Addr> {
        // A+1 normally; if A is the final usable host, use A-1. /31
        // point-to-point prefixes have two usable hosts (RFC 3021).
        let addr = u32::from(net.addr());
        for candidate in [addr.checked_add(1), addr.checked_sub(1)]
            .into_iter()
            .flatten()
        {
            let peer = Ipv4Addr::from(candidate);
            if net.contains(&peer)
                && (net.prefix_len() >= 31 || (peer != net.network() && peer != net.broadcast()))
            {
                return Ok(peer);
            }
        }
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "tun system: inet4-address needs a second usable host in its prefix",
        ))
    }

    fn peer_v6(net: Ipv6Net) -> io::Result<Ipv6Addr> {
        let addr = u128::from(net.addr());
        for candidate in [addr.checked_add(1), addr.checked_sub(1)]
            .into_iter()
            .flatten()
        {
            let peer = Ipv6Addr::from(candidate);
            if net.contains(&peer) && (net.prefix_len() >= 127 || peer != net.network()) {
                return Ok(peer);
            }
        }
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "tun system: inet6-address needs a second usable host in its prefix",
        ))
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn nat_peer_stays_in_prefix() {
            for (net, want) in [
                ("172.19.0.1/30", "172.19.0.2"),
                ("172.19.0.2/30", "172.19.0.1"),
                ("10.0.0.0/31", "10.0.0.1"),
            ] {
                assert_eq!(peer_v4(net.parse().unwrap()).unwrap().to_string(), want);
            }
            assert!(peer_v4("10.0.0.1/32".parse().unwrap()).is_err());
            assert_eq!(
                peer_v6("fd00::1/126".parse().unwrap()).unwrap().to_string(),
                "fd00::2"
            );
            assert!(peer_v6("fd00::1/128".parse().unwrap()).is_err());
            assert_eq!(
                peer_v6("fd00::1/127".parse().unwrap()).unwrap().to_string(),
                "fd00::"
            );
        }
    }
}

// Keep the pump/accept integration identical on every platform; only
// Linux has a kernel backend until the other platforms can be tested.
#[cfg(not(target_os = "linux"))]
pub(super) struct System;

#[cfg(not(target_os = "linux"))]
impl System {
    pub async fn new(
        enabled: bool,
        _: ipnet::Ipv4Net,
        _: Option<ipnet::Ipv6Net>,
        _: &str,
    ) -> std::io::Result<Option<std::sync::Arc<Self>>> {
        if enabled {
            tracing::warn!("tun.stack: system/mixed is implemented only on Linux; using lwip");
        }
        Ok(None)
    }

    pub fn dispatch(&self, _: &mut [u8], _: TcpChecksum) -> Dispatch {
        Dispatch::ToStack
    }
}
