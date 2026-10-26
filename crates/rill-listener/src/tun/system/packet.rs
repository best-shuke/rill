//! Validated TCP headers and RFC 1624 checksum updates. No payload copies.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use super::TcpChecksum;

#[derive(Debug, Clone, Copy)]
pub(super) struct TcpPacket {
    pub src: SocketAddr,
    pub dst: SocketAddr,
    pub syn: bool,
    pub ack: bool,
    pub fin: bool,
    pub rst: bool,
    tcp: usize,
}

pub(super) enum Parsed {
    Tcp(TcpPacket),
    Other,
    Invalid,
}

fn word(p: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([p[at], p[at + 1]])
}

impl TcpPacket {
    pub fn parse(p: &[u8]) -> Parsed {
        let (src, dst, tcp, len) = match p.first().map(|b| b >> 4) {
            Some(4) if p.len() >= 20 => {
                let ihl = usize::from(p[0] & 15) * 4;
                let len = usize::from(word(p, 2));
                if ihl < 20 || len < ihl || len > p.len() {
                    return Parsed::Invalid;
                }
                if p[9] != 6 {
                    return Parsed::Other;
                }
                // Never NAT an incomplete segment, including a non-first
                // fragment whose bytes would otherwise look like ports.
                if word(p, 6) & 0x3fff != 0 {
                    return Parsed::Invalid;
                }
                (
                    IpAddr::V4(Ipv4Addr::new(p[12], p[13], p[14], p[15])),
                    IpAddr::V4(Ipv4Addr::new(p[16], p[17], p[18], p[19])),
                    ihl,
                    len,
                )
            }
            Some(6) if p.len() >= 40 => {
                let len = 40 + usize::from(word(p, 4));
                if len > p.len() || len == 40 {
                    return Parsed::Invalid;
                }
                let mut next = p[6];
                let mut tcp = 40;
                let mut untranslated = false;
                // Hop-by-hop / destination options do not change the
                // pseudo-header. Routing/AH cannot be rewritten safely,
                // but their non-TCP traffic still belongs to lwIP.
                while matches!(next, 0 | 43 | 51 | 60) {
                    if tcp + 2 > len {
                        return Parsed::Invalid;
                    }
                    let ah = next == 51;
                    untranslated |= next == 43 || ah;
                    next = p[tcp];
                    tcp += if ah {
                        (usize::from(p[tcp + 1]) + 2) * 4
                    } else {
                        (usize::from(p[tcp + 1]) + 1) * 8
                    };
                    if tcp > len {
                        return Parsed::Invalid;
                    }
                }
                if next == 44 {
                    // Fragment header's next-header is present even in
                    // non-first fragments. Preserve ordinary UDP/ICMP
                    // fragmentation, never send fragmented TCP to lwIP.
                    return if tcp + 8 <= len && matches!(p[tcp], 17 | 58 | 59) {
                        Parsed::Other
                    } else {
                        Parsed::Invalid
                    };
                }
                if next != 6 {
                    return Parsed::Other;
                }
                if untranslated {
                    return Parsed::Invalid;
                }
                (
                    IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&p[8..24]).unwrap())),
                    IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&p[24..40]).unwrap())),
                    tcp,
                    len,
                )
            }
            _ => return Parsed::Invalid,
        };
        if tcp + 20 > len {
            return Parsed::Invalid;
        }
        let header = usize::from(p[tcp + 12] >> 4) * 4;
        if header < 20 || tcp + header > len {
            return Parsed::Invalid;
        }
        Parsed::Tcp(Self {
            src: SocketAddr::new(src, word(p, tcp)),
            dst: SocketAddr::new(dst, word(p, tcp + 2)),
            syn: p[tcp + 13] & 2 != 0,
            fin: p[tcp + 13] & 1 != 0,
            rst: p[tcp + 13] & 4 != 0,
            ack: p[tcp + 13] & 16 != 0,
            tcp,
        })
    }

    /// Only addresses and ports change; sequence numbers, TCP options
    /// (including MSS), payload and flags belong to the two kernels.
    pub fn rewrite(self, p: &mut [u8], src: SocketAddr, dst: SocketAddr, csum: TcpChecksum) {
        let mut tcp_sum = word(p, self.tcp + 16);
        // A partial sum is the uncomplemented value RFC 1624 updates in
        // complemented form: P' = P + ~m + m' = ~replace(~P, m, m').
        let pseudo = |sum: u16, old: u16, new: u16| match csum {
            TcpChecksum::Full => replace(sum, old, new),
            TcpChecksum::Partial => !replace(!sum, old, new),
        };
        match (src.ip(), dst.ip()) {
            (IpAddr::V4(src), IpAddr::V4(dst)) => {
                let mut ip_sum = word(p, 10);
                for (at, bytes) in [(12, src.octets()), (16, dst.octets())] {
                    for (i, pair) in bytes.as_chunks::<2>().0.iter().enumerate() {
                        let at = at + i * 2;
                        let new = u16::from_be_bytes([pair[0], pair[1]]);
                        ip_sum = replace(ip_sum, word(p, at), new);
                        tcp_sum = pseudo(tcp_sum, word(p, at), new);
                        p[at..at + 2].copy_from_slice(pair);
                    }
                }
                p[10..12].copy_from_slice(&ip_sum.to_be_bytes());
            }
            (IpAddr::V6(src), IpAddr::V6(dst)) => {
                for (at, bytes) in [(8, src.octets()), (24, dst.octets())] {
                    for (i, pair) in bytes.as_chunks::<2>().0.iter().enumerate() {
                        let at = at + i * 2;
                        let new = u16::from_be_bytes([pair[0], pair[1]]);
                        tcp_sum = pseudo(tcp_sum, word(p, at), new);
                        p[at..at + 2].copy_from_slice(pair);
                    }
                }
            }
            _ => unreachable!("NAT endpoints must have the packet's address family"),
        }
        for (at, new) in [(self.tcp, src.port()), (self.tcp + 2, dst.port())] {
            if csum == TcpChecksum::Full {
                tcp_sum = replace(tcp_sum, word(p, at), new);
            }
            p[at..at + 2].copy_from_slice(&new.to_be_bytes());
        }
        p[self.tcp + 16..self.tcp + 18].copy_from_slice(&tcp_sum.to_be_bytes());
    }
}

fn replace(checksum: u16, old: u16, new: u16) -> u16 {
    let mut sum = u32::from(!checksum) + u32::from(!old) + u32::from(new);
    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Independent full Internet checksum, including odd payload lengths.
    fn checksum(bytes: &[u8]) -> u16 {
        let mut sum = 0u64;
        for c in bytes.chunks(2) {
            sum += u64::from(c[0]) * 256 + u64::from(*c.get(1).unwrap_or(&0));
        }
        while sum > 65535 {
            sum = (sum & 65535) + (sum >> 16);
        }
        !(sum as u16)
    }

    fn tcp_checksum(p: &[u8], tcp: usize) -> u16 {
        let len = (p.len() - tcp) as u32;
        let mut pseudo = Vec::new();
        if p[0] >> 4 == 4 {
            pseudo.extend_from_slice(&p[12..20]);
            pseudo.extend_from_slice(&[0, 6]);
            pseudo.extend_from_slice(&(len as u16).to_be_bytes());
        } else {
            pseudo.extend_from_slice(&p[8..40]);
            pseudo.extend_from_slice(&len.to_be_bytes());
            pseudo.extend_from_slice(&[0, 0, 0, 6]);
        }
        pseudo.extend_from_slice(&p[tcp..]);
        checksum(&pseudo)
    }

    pub(super) fn packet(v6: bool, flags: u8, options: bool) -> Vec<u8> {
        let ip = if v6 {
            40
        } else if options {
            24
        } else {
            20
        };
        let tcp = if options { 32 } else { 20 };
        let mut p = vec![0; ip + tcp + 7];
        let len = p.len();
        if v6 {
            p[0] = 0x60;
            p[4..6].copy_from_slice(&((len - 40) as u16).to_be_bytes());
            p[6] = 6;
            p[7] = 64;
            p[8..24].copy_from_slice(&"fd00::1234".parse::<Ipv6Addr>().unwrap().octets());
            p[24..40].copy_from_slice(&"2001:db8::abcd".parse::<Ipv6Addr>().unwrap().octets());
        } else {
            p[0] = 0x40 | (ip / 4) as u8;
            p[2..4].copy_from_slice(&(len as u16).to_be_bytes());
            p[8] = 64;
            p[9] = 6;
            p[12..20].copy_from_slice(&[10, 0, 0, 7, 198, 18, 1, 2]);
            let sum = checksum(&p[..ip]);
            p[10..12].copy_from_slice(&sum.to_be_bytes());
        }
        p[ip..ip + 4].copy_from_slice(&[0xaa, 0xbb, 0x01, 0xbb]);
        p[ip + 12] = (tcp / 4) as u8 * 16;
        p[ip + 13] = flags;
        if options {
            p[ip + 20..ip + 32].copy_from_slice(&[2, 4, 5, 180, 1, 1, 8, 6, 1, 2, 3, 4]);
        }
        p[ip + tcp..].copy_from_slice(b"payload");
        let sum = tcp_checksum(&p, ip);
        p[ip + 16..ip + 18].copy_from_slice(&sum.to_be_bytes());
        p
    }

    #[test]
    fn rewrites_match_full_checksums_and_roundtrip() {
        for v6 in [false, true] {
            for flags in [2, 0x12, 0x10, 0x11, 4, 0x14] {
                for options in [false, true] {
                    let original = packet(v6, flags, options);
                    let mut p = original.clone();
                    let Parsed::Tcp(header) = TcpPacket::parse(&p) else {
                        panic!()
                    };
                    assert_eq!(header.syn, flags & 2 != 0);
                    assert_eq!(header.ack, flags & 16 != 0);
                    assert_eq!(header.fin, flags & 1 != 0);
                    assert_eq!(header.rst, flags & 4 != 0);
                    let (src, dst) = if v6 {
                        ("[fd01::2]:65535", "[fd01::1]:12345")
                    } else {
                        ("172.19.0.2:65535", "172.19.0.1:12345")
                    };
                    header.rewrite(
                        &mut p,
                        src.parse().unwrap(),
                        dst.parse().unwrap(),
                        TcpChecksum::Full,
                    );
                    assert_eq!(tcp_checksum(&p, header.tcp), 0);
                    if !v6 {
                        assert_eq!(checksum(&p[..header.tcp]), 0);
                    }
                    assert_eq!(&p[header.tcp + 20..], &original[header.tcp + 20..]);
                    let Parsed::Tcp(nat) = TcpPacket::parse(&p) else {
                        panic!()
                    };
                    assert_eq!(nat.src, src.parse().unwrap());
                    assert_eq!(nat.dst, dst.parse().unwrap());
                    assert_eq!(p[header.tcp + 13], flags);
                    nat.rewrite(&mut p, header.src, header.dst, TcpChecksum::Full);
                    assert_eq!(p, original);
                }
            }
        }
    }

    /// The folded, uncomplemented pseudo-header sum a CHECKSUM_PARTIAL
    /// frame carries (what Linux's `__tcp_v4_send_check` stores).
    fn pseudo_partial(p: &[u8], tcp: usize) -> u16 {
        let mut zeroed = p.to_vec();
        zeroed[tcp..].fill(0);
        // The pseudo header plus all-zero TCP bytes sums to the pseudo
        // header alone.
        !tcp_checksum(&zeroed, tcp)
    }

    /// Finish a partial checksum the way the kernel does: sum the TCP
    /// header and payload on top of the stored pseudo-header sum.
    fn complete(p: &mut [u8], tcp: usize) {
        let initial = word(p, tcp + 16);
        p[tcp + 16..tcp + 18].fill(0);
        let mut sum = u64::from(initial);
        for c in p[tcp..].chunks(2) {
            sum += u64::from(c[0]) * 256 + u64::from(*c.get(1).unwrap_or(&0));
        }
        while sum > 65535 {
            sum = (sum & 65535) + (sum >> 16);
        }
        p[tcp + 16..tcp + 18].copy_from_slice(&(!(sum as u16)).to_be_bytes());
    }

    #[test]
    fn partial_checksum_rewrite_completes_to_a_valid_checksum() {
        for v6 in [false, true] {
            for options in [false, true] {
                let mut p = packet(v6, 0x10, options);
                let Parsed::Tcp(header) = TcpPacket::parse(&p) else {
                    panic!()
                };
                let partial = pseudo_partial(&p, header.tcp);
                p[header.tcp + 16..header.tcp + 18].copy_from_slice(&partial.to_be_bytes());
                let (src, dst) = if v6 {
                    ("[fd01::2]:40000", "[fd01::1]:443")
                } else {
                    ("172.19.0.2:40000", "172.19.0.1:443")
                };
                header.rewrite(
                    &mut p,
                    src.parse().unwrap(),
                    dst.parse().unwrap(),
                    TcpChecksum::Partial,
                );
                assert_eq!(
                    word(&p, header.tcp + 16),
                    pseudo_partial(&p, header.tcp),
                    "the field stays the new pseudo-header sum"
                );
                complete(&mut p, header.tcp);
                assert_eq!(tcp_checksum(&p, header.tcp), 0);
                if !v6 {
                    assert_eq!(checksum(&p[..header.tcp]), 0);
                }
            }
        }
    }

    #[test]
    fn malformed_and_fragmented_packets_are_safe() {
        for v6 in [false, true] {
            let p = packet(v6, 2, true);
            for len in 0..p.len() {
                assert!(matches!(TcpPacket::parse(&p[..len]), Parsed::Invalid));
            }
        }
        for fragment in [0x2000u16, 1, 0x2001] {
            let mut p = packet(false, 2, false);
            p[6..8].copy_from_slice(&fragment.to_be_bytes());
            assert!(matches!(TcpPacket::parse(&p), Parsed::Invalid));
        }
        let mut p = packet(false, 2, false);
        p[32] = 0xf0;
        assert!(matches!(TcpPacket::parse(&p), Parsed::Invalid));
        p[9] = 17;
        assert!(matches!(TcpPacket::parse(&p), Parsed::Other));
    }

    #[test]
    fn ipv6_extension_headers() {
        let mut p = packet(true, 0x12, true);
        p.splice(40..40, [6, 0, 0, 0, 0, 0, 0, 0]);
        let len = (p.len() - 40) as u16;
        p[4..6].copy_from_slice(&len.to_be_bytes());
        p[6] = 60;
        let Parsed::Tcp(header) = TcpPacket::parse(&p) else {
            panic!()
        };
        header.rewrite(
            &mut p,
            "[fd01::2]:1024".parse().unwrap(),
            "[fd01::1]:5678".parse().unwrap(),
            TcpChecksum::Full,
        );
        assert_eq!(tcp_checksum(&p, 48), 0);
        for unsupported in [43, 44, 51] {
            p[6] = unsupported;
            assert!(matches!(TcpPacket::parse(&p), Parsed::Invalid));
        }
        p[6] = 44;
        for transport in [17, 58] {
            p[40] = transport;
            assert!(matches!(TcpPacket::parse(&p), Parsed::Other));
        }
        p[6] = 50;
        assert!(matches!(TcpPacket::parse(&p), Parsed::Other));
    }

    #[test]
    fn rfc1624_zero_boundary() {
        assert_eq!(replace(0xdd2f, 0x5555, 0x3285), 0);
    }

    #[test]
    fn arbitrary_short_headers_never_panic() {
        let mut seed = 1u64;
        for len in 0..128 {
            for version in [4, 6] {
                for _ in 0..32 {
                    let mut p = vec![0; len];
                    for byte in &mut p {
                        seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
                        *byte = (seed >> 32) as u8;
                    }
                    if let Some(first) = p.first_mut() {
                        *first = (*first & 15) | version << 4;
                    }
                    let _ = TcpPacket::parse(&p);
                }
            }
        }
    }
}
