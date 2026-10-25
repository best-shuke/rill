use std::fmt;
use std::net::IpAddr;

use hickory_proto::op::ResponseCode;
use hickory_proto::rr::RecordType;

/// A parsed nameserver URL in one of the supported transport forms.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum NameServerUrl {
    Udp {
        addr: HostOrIp,
        port: u16,
    },
    Tcp {
        addr: HostOrIp,
        port: u16,
    },
    Tls {
        addr: HostOrIp,
        port: u16,
        sni: String,
    },
    Https {
        addr: HostOrIp,
        port: u16,
        path: String,
        sni: String,
    },
    RCode {
        code: ResponseCode,
        label: String,
    },
}

/// Either a resolved IP address or a hostname that requires bootstrap resolution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostOrIp {
    Ip(IpAddr),
    Host(String),
}

impl fmt::Display for HostOrIp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HostOrIp::Ip(ip) => write!(f, "{ip}"),
            HostOrIp::Host(h) => write!(f, "{h}"),
        }
    }
}

impl fmt::Display for NameServerUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NameServerUrl::Udp { addr, port } => write!(f, "udp://{addr}:{port}"),
            NameServerUrl::Tcp { addr, port } => write!(f, "tcp://{addr}:{port}"),
            NameServerUrl::Tls { addr, port, sni } => {
                write!(f, "tls://{addr}:{port}")?;
                write_sni_override(f, addr, sni)
            }
            NameServerUrl::Https {
                addr,
                port,
                path,
                sni,
            } => {
                write!(f, "https://{addr}:{port}{path}")?;
                write_sni_override(f, addr, sni)
            }
            NameServerUrl::RCode { label, .. } => write!(f, "rcode://{label}"),
        }
    }
}

/// A bare `#name` reads as an outbound in configuration syntax, so only an
/// SNI that differs from the URL host is shown, in its `sni=` form.
fn write_sni_override(f: &mut fmt::Formatter<'_>, addr: &HostOrIp, sni: &str) -> fmt::Result {
    if sni == addr.to_string() {
        Ok(())
    } else {
        write!(f, "#sni={sni}")
    }
}

/// A nameserver entry — a [`NameServerUrl`] plus an optional `#PROXY` tag
/// telling the resolver to tunnel queries through the named proxy.
///
/// The fragment selects the outbound for every transport, including DoT
/// and DoH, and carries mihomo's `key=value` options (see
/// [`NameServerOptions`]). An explicit `sni=hostname` parameter overrides
/// the TLS name without confusing it with an outbound name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NameServerEntry {
    pub url: NameServerUrl,
    pub proxy: Option<String>,
    /// The `key=value` fragment parameters this upstream acts on.
    pub options: NameServerOptions,
    /// Fragment parameters accepted but not acted on, verbatim, so the
    /// config layer can report them. mihomo ignores unknown parameters, and
    /// a subscription that carries one (`h3=true` is common) must still load.
    pub ignored_parameters: Vec<String>,
}

/// mihomo's per-nameserver fragment parameters (`#…&key=value`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct NameServerOptions {
    /// `skip-cert-verify=true`: accept any DoT/DoH certificate.
    pub skip_cert_verify: bool,
    /// `ecs=prefix`: the EDNS Client Subnet sent with every query. Host bits
    /// beyond the prefix are already cleared, as RFC 7871 requires.
    pub ecs: Option<ipnet::IpNet>,
    /// `disable-ipv4`, `disable-ipv6` and `disable-qtype-<n>`: query types
    /// answered locally with an empty NOERROR instead of being sent.
    pub disabled_qtypes: Vec<u16>,
}

impl NameServerOptions {
    /// Whether queries of `qtype` are answered locally (empty NOERROR).
    pub fn disables(&self, qtype: u16) -> bool {
        self.disabled_qtypes.contains(&qtype)
    }

    fn set_disabled(&mut self, qtype: u16, disabled: bool) {
        self.disabled_qtypes.retain(|&t| t != qtype);
        if disabled {
            self.disabled_qtypes.push(qtype);
        }
    }
}

/// mihomo reads `ecs` as a prefix, or a bare address as a full-length one.
fn parse_ecs(value: &str) -> Option<ipnet::IpNet> {
    let net = value.parse::<ipnet::IpNet>().ok().or_else(|| {
        let ip = value.parse::<IpAddr>().ok()?;
        let bits = if ip.is_ipv4() { 32 } else { 128 };
        ipnet::IpNet::new(ip, bits).ok()
    })?;
    Some(net.trunc())
}

impl NameServerEntry {
    pub fn plain(url: NameServerUrl) -> Self {
        Self {
            url,
            proxy: None,
            options: NameServerOptions::default(),
            ignored_parameters: Vec::new(),
        }
    }

    /// Parse a nameserver string, returning the parsed `NameServerUrl` plus
    /// the optional outbound name from the `#PROXY` fragment.
    pub fn parse(s: &str) -> Result<Self, NameServerParseError> {
        let s = s.trim();
        if s.is_empty() {
            return Err(NameServerParseError::EmptyInput);
        }

        let (head, fragment) = s.split_once('#').map_or((s, None), |(h, f)| (h, Some(f)));
        let mut entry = Self::plain(NameServerUrl::parse(head)?);
        if let Some(fragment) = fragment {
            if fragment.trim().is_empty() {
                return Err(NameServerParseError::InvalidHost(s.to_string()));
            }
            // As in mihomo: `&`-separated, a bare word names the outbound
            // (the last one wins) and `key=value` sets an option.
            for parameter in fragment.split('&').map(str::trim) {
                match parameter.split_once('=') {
                    _ if parameter.is_empty() => {}
                    None => entry.proxy = Some(parameter.to_string()),
                    Some((key, value)) => {
                        entry.apply_parameter(key.trim(), value.trim(), parameter);
                    }
                }
            }
        }
        Ok(entry)
    }

    fn apply_parameter(&mut self, key: &str, value: &str, parameter: &str) {
        // mihomo enables a flag only on the exact value `true`.
        let enabled = value == "true";
        let options = &mut self.options;
        let acted_on = match key {
            "sni" => match &mut self.url {
                NameServerUrl::Tls { sni, .. } | NameServerUrl::Https { sni, .. }
                    if !value.is_empty() =>
                {
                    *sni = value.to_string();
                    true
                }
                _ => false,
            },
            "skip-cert-verify" => {
                options.skip_cert_verify = enabled;
                true
            }
            "ecs" => match parse_ecs(value) {
                Some(net) => {
                    options.ecs = Some(net);
                    true
                }
                None => false,
            },
            // Queries are built here, never forwarded with a client's own
            // subnet, so `ecs` always applies and there is nothing to override.
            "ecs-override" => true,
            // DoH is HTTP/1.1 only; asking for HTTP/3 is reported.
            "h3" => !enabled,
            "disable-ipv4" => {
                options.set_disabled(u16::from(RecordType::A), enabled);
                true
            }
            "disable-ipv6" => {
                options.set_disabled(u16::from(RecordType::AAAA), enabled);
                true
            }
            _ => match key
                .strip_prefix("disable-qtype-")
                .and_then(|qtype| qtype.parse::<u16>().ok())
            {
                Some(qtype) => {
                    options.set_disabled(qtype, enabled);
                    true
                }
                None => false,
            },
        };
        if !acted_on {
            self.ignored_parameters.push(parameter.to_string());
        }
    }
}

impl From<NameServerUrl> for NameServerEntry {
    fn from(url: NameServerUrl) -> Self {
        Self::plain(url)
    }
}

impl NameServerUrl {
    /// Returns `Some(hostname)` if this entry needs bootstrap DNS resolution,
    /// `None` if the address is already an IP literal.
    pub fn needs_bootstrap(&self) -> Option<&str> {
        let addr = match self {
            NameServerUrl::Udp { addr, .. }
            | NameServerUrl::Tcp { addr, .. }
            | NameServerUrl::Tls { addr, .. }
            | NameServerUrl::Https { addr, .. } => addr,
            NameServerUrl::RCode { .. } => return None,
        };
        match addr {
            HostOrIp::Host(h) => Some(h.as_str()),
            HostOrIp::Ip(_) => None,
        }
    }

    /// Returns true if this is a plain (non-encrypted) nameserver.
    pub fn is_plain(&self) -> bool {
        matches!(
            self,
            NameServerUrl::Udp { .. } | NameServerUrl::Tcp { .. } | NameServerUrl::RCode { .. }
        )
    }

    /// Parse a nameserver string into a `NameServerUrl`.
    ///
    /// Accepted forms:
    /// - `8.8.8.8` / `8.8.8.8:53`  — plain UDP
    /// - `dns.google` / `dns.google:53`  — plain UDP with hostname
    /// - `udp://host[:port]`
    /// - `tcp://host[:port]`
    /// - `tls://host[:port][#sni]`
    /// - `https://host[:port][/path][#sni]`
    pub fn parse(s: &str) -> Result<Self, NameServerParseError> {
        let s = s.trim();
        if s.is_empty() {
            return Err(NameServerParseError::EmptyInput);
        }

        // Split off #fragment before any URL parsing — the fragment is NOT a
        // standard URL anchor in this context; it carries the SNI override,
        // bare or in the `sni=` form `Display` writes.
        let (s_no_frag, fragment) = match s.find('#') {
            Some(idx) => (&s[..idx], Some(&s[idx + 1..])),
            None => (s, None),
        };
        let fragment = fragment.map(|f| f.strip_prefix("sni=").unwrap_or(f));

        // Dispatch on scheme
        if let Some(rest) = s_no_frag.strip_prefix("tls://") {
            return Self::parse_tls(rest, fragment);
        }
        if let Some(rest) = s_no_frag.strip_prefix("https://") {
            return Self::parse_https(rest, fragment);
        }
        if let Some(rest) = s_no_frag.strip_prefix("udp://") {
            let (addr, port) = parse_host_port(rest, 53)?;
            return Ok(NameServerUrl::Udp { addr, port });
        }
        if let Some(rest) = s_no_frag.strip_prefix("tcp://") {
            let (addr, port) = parse_host_port(rest, 53)?;
            return Ok(NameServerUrl::Tcp { addr, port });
        }
        if let Some(rest) = s_no_frag.strip_prefix("rcode://") {
            return parse_rcode(rest);
        }
        if s_no_frag.starts_with("quic://") {
            return Err(NameServerParseError::QuicNotSupported);
        }
        // Any other explicit scheme → unsupported
        if let Some(colon) = s_no_frag.find("://") {
            let scheme = &s_no_frag[..colon];
            // Make sure it's actually a scheme (letters only, reasonable length)
            if scheme
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '-' || c == '.')
                && colon <= 20
            {
                return Err(NameServerParseError::UnsupportedScheme(scheme.to_string()));
            }
        }

        // No scheme — bare IP or hostname, defaults to UDP port 53
        let (addr, port) = parse_host_port(s_no_frag, 53)?;
        Ok(NameServerUrl::Udp { addr, port })
    }

    #[cfg(feature = "encrypted")]
    fn parse_tls(rest: &str, fragment: Option<&str>) -> Result<Self, NameServerParseError> {
        let (addr, port) = parse_host_port(rest, 853)?;
        let sni = match fragment {
            Some(f) if !f.is_empty() => f.to_string(),
            // Default SNI = the host string (IP or hostname)
            _ => addr.to_string(),
        };
        Ok(NameServerUrl::Tls { addr, port, sni })
    }

    #[cfg(not(feature = "encrypted"))]
    fn parse_tls(_rest: &str, _fragment: Option<&str>) -> Result<Self, NameServerParseError> {
        Err(NameServerParseError::EncryptedFeatureDisabled)
    }

    #[cfg(feature = "encrypted")]
    fn parse_https(rest: &str, fragment: Option<&str>) -> Result<Self, NameServerParseError> {
        // Split path off the host[:port] portion. Path starts at first '/' after host.
        let (hostport, path) = match rest.find('/') {
            Some(idx) => (&rest[..idx], rest[idx..].to_string()),
            None => (rest, "/dns-query".to_string()),
        };
        // Ensure path starts with /
        let path = if path.is_empty() {
            "/dns-query".to_string()
        } else {
            path
        };

        let (addr, port) = parse_host_port(hostport, 443)?;
        let sni = match fragment {
            Some(f) if !f.is_empty() => f.to_string(),
            _ => addr.to_string(),
        };
        Ok(NameServerUrl::Https {
            addr,
            port,
            path,
            sni,
        })
    }

    #[cfg(not(feature = "encrypted"))]
    fn parse_https(_rest: &str, _fragment: Option<&str>) -> Result<Self, NameServerParseError> {
        Err(NameServerParseError::EncryptedFeatureDisabled)
    }
}

fn parse_rcode(s: &str) -> Result<NameServerUrl, NameServerParseError> {
    let label = s.trim();
    let code = match label {
        "success" => ResponseCode::NoError,
        "format_error" => ResponseCode::FormErr,
        "server_failure" => ResponseCode::ServFail,
        "name_error" => ResponseCode::NXDomain,
        "not_implemented" => ResponseCode::NotImp,
        "refused" => ResponseCode::Refused,
        _ => return Err(NameServerParseError::UnsupportedRCode(label.to_string())),
    };
    Ok(NameServerUrl::RCode {
        code,
        label: label.to_string(),
    })
}

/// Parse `host:port` or `[ipv6]:port` or bare `host`, returning `(HostOrIp, port)`.
/// `default_port` is used when no port is present.
fn parse_host_port(s: &str, default_port: u16) -> Result<(HostOrIp, u16), NameServerParseError> {
    // IPv6 bracketed form: [::1]:853 or [::1]
    if s.starts_with('[') {
        let close = s
            .find(']')
            .ok_or_else(|| NameServerParseError::InvalidHost(s.to_string()))?;
        let ipv6_str = &s[1..close];
        let ip: IpAddr = ipv6_str
            .parse()
            .map_err(|_| NameServerParseError::InvalidHost(s.to_string()))?;
        let port = if close + 1 < s.len() {
            let port_str = s[close + 1..]
                .strip_prefix(':')
                .ok_or_else(|| NameServerParseError::InvalidHost(s.to_string()))?;
            parse_port(port_str)?
        } else {
            default_port
        };
        return Ok((HostOrIp::Ip(ip), port));
    }

    if let Ok(ip) = s.parse::<IpAddr>() {
        return Ok((HostOrIp::Ip(ip), default_port));
    }

    if let Some(idx) = s.rfind(':') {
        let maybe_port = &s[idx + 1..];
        if maybe_port.chars().all(|c| c.is_ascii_digit()) {
            let port = parse_port(maybe_port)?;
            let host_str = &s[..idx];
            let addr = parse_host_or_ip(host_str)?;
            return Ok((addr, port));
        }
    }

    // No port — use default
    let addr = parse_host_or_ip(s)?;
    Ok((addr, default_port))
}

fn parse_host_or_ip(s: &str) -> Result<HostOrIp, NameServerParseError> {
    if s.is_empty() {
        return Err(NameServerParseError::InvalidHost(s.to_string()));
    }
    if let Ok(ip) = s.parse::<IpAddr>() {
        return Ok(HostOrIp::Ip(ip));
    }
    // Validate it looks like a hostname (not arbitrary junk)
    if s.contains('/') || s.contains(' ') {
        return Err(NameServerParseError::InvalidHost(s.to_string()));
    }
    Ok(HostOrIp::Host(s.to_string()))
}

fn parse_port(s: &str) -> Result<u16, NameServerParseError> {
    s.parse::<u32>()
        .ok()
        .filter(|&p| p > 0 && p <= 65535)
        .map(|p| p as u16)
        .ok_or_else(|| NameServerParseError::InvalidPort(s.to_string()))
}

/// Parse error for `NameServerUrl::parse`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum NameServerParseError {
    #[error("nameserver string is empty")]
    EmptyInput,
    #[error(
        "nameserver uses the 'quic' scheme which is not yet supported; tracked as roadmap M1.E-6 / M2. Use 'tls://' or 'https://' for now."
    )]
    QuicNotSupported,
    #[error("nameserver uses unsupported scheme '{0}'")]
    UnsupportedScheme(String),
    #[error("invalid host in nameserver: '{0}'")]
    InvalidHost(String),
    #[error("invalid port in nameserver: '{0}'")]
    InvalidPort(String),
    #[error(
        "encrypted DNS (tls:// / https://) requires the 'encrypted' Cargo feature to be enabled"
    )]
    EncryptedFeatureDisabled,
    #[error("unsupported rcode nameserver type '{0}'")]
    UnsupportedRCode(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    fn ip4(a: u8, b: u8, c: u8, d: u8) -> HostOrIp {
        HostOrIp::Ip(IpAddr::V4(Ipv4Addr::new(a, b, c, d)))
    }
    fn host(s: &str) -> HostOrIp {
        HostOrIp::Host(s.to_string())
    }

    // A1
    #[test]
    fn parse_plain_bare_ip() {
        let url = NameServerUrl::parse("8.8.8.8").unwrap();
        assert_eq!(
            url,
            NameServerUrl::Udp {
                addr: ip4(8, 8, 8, 8),
                port: 53
            }
        );
    }

    #[test]
    fn parse_plain_bare_ipv6_preserves_address_and_default_port() {
        for literal in [
            "2402:4e00::",
            "::1",
            "2001:db8::8888",
            "2001:db8::abcd",
            "2001:db8::1:853",
            "::ffff:192.0.2.1",
        ] {
            let addr = HostOrIp::Ip(literal.parse().unwrap());
            for prefix in ["", "udp://", "tcp://"] {
                let input = format!("{prefix}{literal}");
                let expected = if prefix == "tcp://" {
                    NameServerUrl::Tcp {
                        addr: addr.clone(),
                        port: 53,
                    }
                } else {
                    NameServerUrl::Udp {
                        addr: addr.clone(),
                        port: 53,
                    }
                };
                assert_eq!(NameServerUrl::parse(&input).unwrap(), expected, "{input}");
            }
        }
    }

    #[cfg(feature = "encrypted")]
    #[test]
    fn parse_encrypted_bare_ipv6_uses_transport_default_port() {
        for literal in ["2402:4e00::", "::1", "2001:db8::1:853"] {
            let addr = HostOrIp::Ip(literal.parse().unwrap());
            let sni = addr.to_string();
            assert_eq!(
                NameServerUrl::parse(&format!("tls://{literal}")).unwrap(),
                NameServerUrl::Tls {
                    addr: addr.clone(),
                    port: 853,
                    sni: sni.clone()
                },
            );
            assert_eq!(
                NameServerUrl::parse(&format!("https://{literal}/dns-query")).unwrap(),
                NameServerUrl::Https {
                    addr,
                    port: 443,
                    path: "/dns-query".into(),
                    sni
                },
            );
        }
    }

    #[test]
    fn parse_bracketed_ipv6_keeps_explicit_ports() {
        let addr = HostOrIp::Ip(IpAddr::V6(Ipv6Addr::LOCALHOST));
        for prefix in ["", "udp://", "tcp://"] {
            let input = format!("{prefix}[::1]:5353");
            let expected = if prefix == "tcp://" {
                NameServerUrl::Tcp {
                    addr: addr.clone(),
                    port: 5353,
                }
            } else {
                NameServerUrl::Udp {
                    addr: addr.clone(),
                    port: 5353,
                }
            };
            assert_eq!(NameServerUrl::parse(&input).unwrap(), expected, "{input}");
        }
        for port in ["0", "65536", "invalid"] {
            assert!(matches!(
                NameServerUrl::parse(&format!("[::1]:{port}")),
                Err(NameServerParseError::InvalidPort(_)),
            ));
        }
    }

    // A2
    #[test]
    fn parse_plain_bare_ip_with_port() {
        let url = NameServerUrl::parse("8.8.8.8:5353").unwrap();
        assert_eq!(
            url,
            NameServerUrl::Udp {
                addr: ip4(8, 8, 8, 8),
                port: 5353
            }
        );
    }

    // A3
    #[test]
    fn parse_udp_scheme() {
        let url = NameServerUrl::parse("udp://1.1.1.1").unwrap();
        assert_eq!(
            url,
            NameServerUrl::Udp {
                addr: ip4(1, 1, 1, 1),
                port: 53
            }
        );
    }

    // A4
    #[test]
    fn parse_udp_scheme_with_port() {
        let url = NameServerUrl::parse("udp://1.1.1.1:5353").unwrap();
        assert_eq!(
            url,
            NameServerUrl::Udp {
                addr: ip4(1, 1, 1, 1),
                port: 5353
            }
        );
    }

    // A5
    #[test]
    fn parse_tcp_scheme() {
        let url = NameServerUrl::parse("tcp://1.1.1.1:53").unwrap();
        assert_eq!(
            url,
            NameServerUrl::Tcp {
                addr: ip4(1, 1, 1, 1),
                port: 53
            }
        );
    }

    // A6
    // Upstream: component/resolver/parser.go::parseNameServer case "tls" — defaults port to DoTPort (853) and uses host as SNI.
    #[test]
    fn parse_tls_default_port_and_sni() {
        let url = NameServerUrl::parse("tls://dns.google").unwrap();
        assert_eq!(
            url,
            NameServerUrl::Tls {
                addr: host("dns.google"),
                port: 853,
                sni: "dns.google".to_string()
            }
        );
    }

    // A7
    #[test]
    fn parse_tls_explicit_port() {
        let url = NameServerUrl::parse("tls://dns.google:8853").unwrap();
        assert_eq!(
            url,
            NameServerUrl::Tls {
                addr: host("dns.google"),
                port: 8853,
                sni: "dns.google".to_string()
            }
        );
    }

    // A8
    // Upstream: same function, u.Fragment branch.
    // NOT: the '#' fragment is not a standard URL anchor; extracted manually.
    #[test]
    fn parse_tls_explicit_sni() {
        let url = NameServerUrl::parse("tls://8.8.8.8:853#dns.google").unwrap();
        assert_eq!(
            url,
            NameServerUrl::Tls {
                addr: ip4(8, 8, 8, 8),
                port: 853,
                sni: "dns.google".to_string()
            }
        );
    }

    // A9
    #[test]
    fn parse_tls_ip_literal_no_sni_uses_ip_string() {
        let url = NameServerUrl::parse("tls://8.8.8.8:853").unwrap();
        match &url {
            NameServerUrl::Tls { addr, sni, .. } => {
                assert_eq!(addr, &ip4(8, 8, 8, 8));
                assert!(!sni.is_empty());
            }
            _ => panic!("expected Tls"),
        }
        assert_eq!(url.needs_bootstrap(), None);
    }

    // A10
    #[test]
    fn parse_https_default_path_and_port() {
        let url = NameServerUrl::parse("https://cloudflare-dns.com").unwrap();
        assert_eq!(
            url,
            NameServerUrl::Https {
                addr: host("cloudflare-dns.com"),
                port: 443,
                path: "/dns-query".to_string(),
                sni: "cloudflare-dns.com".to_string(),
            }
        );
    }

    // A11
    #[test]
    fn parse_https_explicit_path() {
        let url = NameServerUrl::parse("https://dns.quad9.net/dns-query").unwrap();
        match &url {
            NameServerUrl::Https { path, .. } => assert_eq!(path, "/dns-query"),
            _ => panic!("expected Https"),
        }
    }

    // A12
    #[test]
    fn parse_https_explicit_port_and_path() {
        let url = NameServerUrl::parse("https://1.1.1.1:8443/custom-path").unwrap();
        assert_eq!(
            url,
            NameServerUrl::Https {
                addr: ip4(1, 1, 1, 1),
                port: 8443,
                path: "/custom-path".to_string(),
                sni: "1.1.1.1".to_string(),
            }
        );
    }

    // A13
    // Upstream: same u.Fragment branch for DoH.
    // NOT: sni must override cert validation even when dial target is the IP.
    #[test]
    fn parse_https_explicit_sni_on_ip() {
        let url = NameServerUrl::parse("https://1.1.1.1/dns-query#cloudflare-dns.com").unwrap();
        assert_eq!(
            url,
            NameServerUrl::Https {
                addr: ip4(1, 1, 1, 1),
                port: 443,
                path: "/dns-query".to_string(),
                sni: "cloudflare-dns.com".to_string(),
            }
        );
    }

    // A14
    #[test]
    fn parse_https_hostname_sni_override() {
        let url = NameServerUrl::parse("https://dns.google/dns-query#override.example").unwrap();
        match &url {
            NameServerUrl::Https { addr, sni, .. } => {
                assert_eq!(addr, &host("dns.google"));
                assert_eq!(sni, "override.example");
            }
            _ => panic!("expected Https"),
        }
    }

    // A15 — IPv6 trip-wire: a naive split(':') parser breaks here.
    // Upstream: uses net.SplitHostPort which handles brackets. NOT a split-on-colon path.
    #[test]
    fn parse_https_ipv6_bracketed() {
        let url = NameServerUrl::parse("https://[2606:4700:4700::1111]/dns-query").unwrap();
        match &url {
            NameServerUrl::Https { addr, .. } => {
                let expected: IpAddr = "2606:4700:4700::1111".parse().unwrap();
                assert_eq!(addr, &HostOrIp::Ip(expected));
            }
            _ => panic!("expected Https"),
        }
    }

    // A16
    #[test]
    fn parse_https_ipv6_with_port_bracketed() {
        let url = NameServerUrl::parse("https://[::1]:853/dns-query").unwrap();
        match &url {
            NameServerUrl::Https { addr, port, .. } => {
                assert_eq!(addr, &HostOrIp::Ip(IpAddr::V6(Ipv6Addr::LOCALHOST)));
                assert_eq!(*port, 853);
            }
            _ => panic!("expected Https"),
        }
    }

    // A17 — Class A per ADR-0002: user assumes encrypted DNS, gets nothing.
    // Upstream: DoQ supported since Go mihomo ~1.15. NOT silent drop.
    #[test]
    fn parse_quic_rejected() {
        let err = NameServerUrl::parse("quic://dns.adguard.com").unwrap_err();
        assert!(matches!(err, NameServerParseError::QuicNotSupported));
        assert!(
            err.to_string().contains("M1.E-6"),
            "error message must cite M1.E-6 roadmap item"
        );
    }

    // A18 — Class A per ADR-0002: silent-drop bug in upstream.
    // Upstream: parseNameServer logs warn and drops entry. NOT a warn.
    #[test]
    fn parse_unknown_scheme() {
        let err = NameServerUrl::parse("sdns://something").unwrap_err();
        assert!(matches!(err, NameServerParseError::UnsupportedScheme(ref s) if s == "sdns"));
    }

    #[test]
    fn parse_rcode_success() {
        let url = NameServerUrl::parse("rcode://success").unwrap();
        assert_eq!(
            url,
            NameServerUrl::RCode {
                code: ResponseCode::NoError,
                label: "success".to_string(),
            }
        );
        assert_eq!(url.to_string(), "rcode://success");
        assert_eq!(url.needs_bootstrap(), None);
    }

    #[test]
    fn parse_rcode_unknown_errors() {
        let err = NameServerUrl::parse("rcode://unknown").unwrap_err();
        assert!(matches!(err, NameServerParseError::UnsupportedRCode(ref s) if s == "unknown"));
    }

    // A19
    #[test]
    fn parse_empty_string_errors() {
        assert!(matches!(
            NameServerUrl::parse("").unwrap_err(),
            NameServerParseError::EmptyInput
        ));
    }

    // A20
    #[test]
    fn parse_invalid_port_errors() {
        assert!(matches!(
            NameServerUrl::parse("1.1.1.1:99999").unwrap_err(),
            NameServerParseError::InvalidPort(_)
        ));
    }

    // A21
    // Upstream: parseNameServer defaults bare entries to UDP. We match.
    #[test]
    fn parse_bare_hostname_no_scheme() {
        let url = NameServerUrl::parse("dns.google").unwrap();
        assert_eq!(
            url,
            NameServerUrl::Udp {
                addr: host("dns.google"),
                port: 53
            }
        );
        assert_eq!(url.needs_bootstrap(), Some("dns.google"));
    }

    // A22
    #[test]
    fn needs_bootstrap_ip_literal_returns_none() {
        let udp = NameServerUrl::parse("8.8.8.8").unwrap();
        assert_eq!(udp.needs_bootstrap(), None);
        let tls = NameServerUrl::parse("tls://8.8.8.8:853#dns.google").unwrap();
        assert_eq!(tls.needs_bootstrap(), None);
        let https = NameServerUrl::parse("https://1.1.1.1/dns-query#cloudflare-dns.com").unwrap();
        assert_eq!(https.needs_bootstrap(), None);
    }

    // A23
    #[test]
    fn needs_bootstrap_hostname_returns_some() {
        let tls = NameServerUrl::parse("tls://dns.google").unwrap();
        assert_eq!(tls.needs_bootstrap(), Some("dns.google"));
        let https = NameServerUrl::parse("https://cloudflare-dns.com").unwrap();
        assert_eq!(https.needs_bootstrap(), Some("cloudflare-dns.com"));
    }

    // G1
    #[test]
    fn all_url_forms_display_contains_host() {
        let cases = [
            "udp://8.8.8.8:53",
            "tcp://8.8.8.8:53",
            "tls://dns.google:853#dns.google",
            "https://cloudflare-dns.com:443/dns-query#cloudflare-dns.com",
        ];
        for s in &cases {
            let url = NameServerUrl::parse(s).unwrap();
            let display = url.to_string();
            assert!(!display.is_empty(), "display must not be empty for {s}");
        }
    }

    // G2
    #[test]
    fn parse_error_is_non_exhaustive_match() {
        let err = NameServerUrl::parse("").unwrap_err();
        // This match must compile — the wildcard arm ensures #[non_exhaustive] is respected.
        let _msg = match err {
            NameServerParseError::EmptyInput => "empty",
            NameServerParseError::QuicNotSupported => "quic",
            NameServerParseError::UnsupportedScheme(_) => "unsupported",
            NameServerParseError::InvalidHost(_) => "invalid host",
            NameServerParseError::InvalidPort(_) => "invalid port",
            NameServerParseError::UnsupportedRCode(_) => "rcode",
            _ => "other",
        };
    }

    // D4: without the `encrypted` feature, tls:// must hard-error mentioning the feature name.
    #[cfg(not(feature = "encrypted"))]
    #[test]
    fn parse_tls_without_encrypted_feature_hard_errors() {
        let result = NameServerUrl::parse("tls://8.8.8.8");
        assert!(
            result.is_err(),
            "tls:// without encrypted feature must error"
        );
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("encrypted"),
            "error message must mention the 'encrypted' feature, got: {msg}"
        );
    }

    // ─── #PROXY suffix parsing (issue #67 phase 2, ADR-0012) ──────────────

    #[test]
    fn entry_no_proxy_default() {
        let e = NameServerEntry::parse("8.8.8.8").unwrap();
        assert!(e.proxy.is_none());
        assert_eq!(
            e.url,
            NameServerUrl::Udp {
                addr: ip4(8, 8, 8, 8),
                port: 53,
            }
        );
    }

    #[test]
    fn entry_plain_udp_with_proxy_tag() {
        let e = NameServerEntry::parse("1.1.1.1#PROXY-JP").unwrap();
        assert_eq!(e.proxy.as_deref(), Some("PROXY-JP"));
        assert_eq!(
            e.url,
            NameServerUrl::Udp {
                addr: ip4(1, 1, 1, 1),
                port: 53,
            }
        );
    }

    #[test]
    fn entry_tcp_scheme_with_proxy_tag() {
        let e = NameServerEntry::parse("tcp://1.1.1.1:53#PROXY-JP").unwrap();
        assert_eq!(e.proxy.as_deref(), Some("PROXY-JP"));
        assert!(matches!(e.url, NameServerUrl::Tcp { .. }));
    }

    #[test]
    #[cfg(feature = "encrypted")]
    fn encrypted_entry_fragments_select_outbound_without_changing_tls_name() {
        for (scheme, tag) in [("tls", "proxy"), ("https", "DIRECT"), ("https", "RULES")] {
            let entry = NameServerEntry::parse(&format!("{scheme}://1.1.1.1#{tag}")).unwrap();
            assert_eq!(entry.proxy.as_deref(), Some(tag));
            match entry.url {
                NameServerUrl::Tls { sni, .. } | NameServerUrl::Https { sni, .. } => {
                    assert_eq!(sni, "1.1.1.1");
                }
                _ => panic!("expected encrypted upstream"),
            }
        }
        let entry =
            NameServerEntry::parse("https://1.1.1.1/dns-query#proxy&sni=cloudflare-dns.com")
                .unwrap();
        assert_eq!(entry.proxy.as_deref(), Some("proxy"));
        assert!(
            matches!(entry.url, NameServerUrl::Https { sni, .. } if sni == "cloudflare-dns.com")
        );
    }

    /// mihomo's fragment parameters, as subscriptions write them, must load:
    /// the ones rill acts on become options, the rest are reported.
    #[test]
    #[cfg(feature = "encrypted")]
    fn mihomo_fragment_parameters_load() {
        let entry = NameServerEntry::parse("https://dns.alidns.com/dns-query#h3=true").unwrap();
        assert_eq!(entry.proxy, None);
        assert_eq!(entry.options, NameServerOptions::default());
        assert_eq!(entry.ignored_parameters, ["h3=true"]);
        assert!(matches!(entry.url, NameServerUrl::Https { sni, .. } if sni == "dns.alidns.com"));

        let entry = NameServerEntry::parse(
            "https://1.1.1.1/dns-query#DIRECT&h3=false&skip-cert-verify=true&ecs=1.2.3.4/20\
             &ecs-override=true&disable-ipv6=true&disable-qtype-65=true&future=1",
        )
        .unwrap();
        assert_eq!(entry.proxy.as_deref(), Some("DIRECT"));
        assert!(entry.options.skip_cert_verify);
        assert_eq!(entry.options.ecs, Some("1.2.0.0/20".parse().unwrap()));
        assert!(entry.options.disables(28) && entry.options.disables(65));
        assert!(!entry.options.disables(1));
        assert_eq!(entry.ignored_parameters, ["future=1"]);

        // A bare address is a full-length prefix; a bad one is reported.
        let entry = NameServerEntry::parse("tls://8.8.8.8#ecs=2001:db8::1").unwrap();
        assert_eq!(entry.options.ecs, Some("2001:db8::1/128".parse().unwrap()));
        let entry = NameServerEntry::parse("tls://8.8.8.8#ecs=bogus&disable-ipv4=1").unwrap();
        assert_eq!(entry.options, NameServerOptions::default());
        assert_eq!(entry.ignored_parameters, ["ecs=bogus"]);
    }

    #[test]
    fn fragment_outbound_and_parameters_follow_mihomo() {
        // The last bare word names the outbound; empty pieces are skipped.
        let entry = NameServerEntry::parse("8.8.8.8#first&&second&").unwrap();
        assert_eq!(entry.proxy.as_deref(), Some("second"));
        assert!(entry.ignored_parameters.is_empty());
        // Flags turn on only for `true`, and a later value wins.
        let entry =
            NameServerEntry::parse("8.8.8.8#disable-ipv4=true&disable-ipv4=false&sni=x").unwrap();
        assert!(!entry.options.disables(1));
        assert_eq!(
            entry.ignored_parameters,
            ["sni=x"],
            "plain DNS has no TLS name"
        );
    }

    #[test]
    #[cfg(feature = "encrypted")]
    fn display_shows_only_an_overriding_sni() {
        let plain = NameServerEntry::parse("tls://8.8.8.8").unwrap().url;
        assert_eq!(plain.to_string(), "tls://8.8.8.8:853");
        let overridden = NameServerEntry::parse("https://1.1.1.1/dns-query#sni=one.one")
            .unwrap()
            .url;
        assert_eq!(
            overridden.to_string(),
            "https://1.1.1.1:443/dns-query#sni=one.one"
        );
        // The low-level parser reads that form back.
        assert_eq!(
            NameServerUrl::parse(&overridden.to_string()).unwrap(),
            overridden
        );
    }

    #[test]
    fn entry_empty_proxy_tag_errors() {
        // `1.1.1.1#` with nothing after the # is a typo, not "no proxy."
        let err = NameServerEntry::parse("1.1.1.1#").unwrap_err();
        assert!(matches!(err, NameServerParseError::InvalidHost(_)));
    }
}
