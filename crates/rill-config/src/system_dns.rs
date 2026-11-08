//! mihomo nameserver spellings that do not name one server: `system`,
//! `system://`, `dhcp://<interface>` and `quic://`.
//!
//! They are rewritten into plain entries before the DNS section is parsed,
//! so a config written for mihomo loads instead of failing on one line:
//!
//! - `system` / `system://` become the resolvers the OS is configured with
//!   (`/etc/resolv.conf` on Unix).
//! - `dhcp://<interface>` asks the interface's DHCP server in mihomo; here
//!   it becomes the system resolvers too, which on a DHCP-configured host
//!   are the ones the DHCP server handed out.
//! - `quic://` (DNS over QUIC) becomes `tls://` (DNS over TLS) to the same
//!   host on port 853, which DoQ providers serve as well.
//! - `sdns://` (DNSCrypt stamps, which mihomo does not speak either) is
//!   dropped.
//!
//! A `#…` fragment (outbound, parameters) is kept on every rewritten entry.

use crate::raw::{RawDns, RawNspValue};
use std::net::{IpAddr, SocketAddr};
use tracing::{info, warn};

/// The resolvers the operating system is configured with, port 53.
///
/// Unix reads `/etc/resolv.conf`; elsewhere, or when it lists none, two
/// public resolvers stand in.
pub(crate) fn system_nameservers() -> Vec<SocketAddr> {
    let mut out = Vec::new();
    #[cfg(unix)]
    if let Ok(contents) = std::fs::read_to_string("/etc/resolv.conf") {
        out = parse_resolv_conf(&contents);
    }
    if out.is_empty() {
        out.push(SocketAddr::from(([1, 1, 1, 1], 53)));
        out.push(SocketAddr::from(([8, 8, 8, 8], 53)));
    }
    out
}

/// `nameserver` lines of a resolv.conf; scoped IPv6 addresses (`%zone`)
/// are left out, since a nameserver URL cannot carry the zone.
pub(crate) fn parse_resolv_conf(contents: &str) -> Vec<SocketAddr> {
    let mut out = Vec::new();
    for line in contents.lines() {
        let Some(rest) = line.trim().strip_prefix("nameserver") else {
            continue;
        };
        let token = rest.split_whitespace().next().unwrap_or("");
        if let Ok(ip) = token.parse::<IpAddr>() {
            let addr = SocketAddr::new(ip, 53);
            if !out.contains(&addr) {
                out.push(addr);
            }
        }
    }
    out
}

/// Rewrite one nameserver list; `system` is the system resolver list.
fn normalize_list(list: &[String], field: &str, system: &[SocketAddr]) -> Vec<String> {
    let mut out = Vec::with_capacity(list.len());
    for entry in list {
        let trimmed = entry.trim();
        let (head, fragment) = match trimmed.split_once('#') {
            Some((h, f)) => (h, Some(f)),
            None => (trimmed, None),
        };
        let suffix = fragment.map(|f| format!("#{f}")).unwrap_or_default();
        let lower = head.to_ascii_lowercase();
        if lower == "system" || lower.starts_with("system://") || lower.starts_with("dhcp://") {
            if lower.starts_with("dhcp://") {
                info!(
                    "dns.{field}: '{trimmed}' uses the system resolvers ({}) — rill does not \
                     query DHCP for them",
                    system
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join(", ")
                );
            }
            for addr in system {
                let addr = addr.to_string();
                let rewritten = format!("{addr}{suffix}");
                if !out.contains(&rewritten) {
                    out.push(rewritten);
                }
            }
        } else if let Some(rest) = head
            .strip_prefix("quic://")
            .or_else(|| head.strip_prefix("QUIC://"))
        {
            let host = strip_port(rest);
            warn!(
                "dns.{field}: DNS over QUIC is not supported; '{trimmed}' is queried over TLS \
                 (tls://{host}:853) instead"
            );
            out.push(format!("tls://{host}{suffix}"));
        } else if lower.starts_with("sdns://") {
            warn!("dns.{field}: DNSCrypt stamps are not supported; '{trimmed}' is ignored");
        } else {
            out.push(entry.clone());
        }
    }
    out
}

/// `host[:port][/path]` → `host` (IPv6 keeps its brackets).
fn strip_port(rest: &str) -> &str {
    let rest = rest.split('/').next().unwrap_or(rest);
    if rest.starts_with('[') {
        return rest.find(']').map_or(rest, |i| &rest[..=i]);
    }
    match rest.rsplit_once(':') {
        Some((host, port)) if port.chars().all(|c| c.is_ascii_digit()) => host,
        _ => rest,
    }
}

fn needs_rewrite(list: Option<&[String]>) -> bool {
    list.into_iter().flatten().any(|s| {
        let lower = s.trim().to_ascii_lowercase();
        lower == "system"
            || lower.starts_with("system#")
            || lower.starts_with("system://")
            || lower.starts_with("dhcp://")
            || lower.starts_with("quic://")
            || lower.starts_with("sdns://")
    })
}

/// The DNS section with every special spelling rewritten, or `None` when
/// there is nothing to rewrite.
pub(crate) fn normalize(dns: &RawDns) -> Option<RawDns> {
    let policy_lists: Vec<&[String]> = dns
        .nameserver_policy
        .iter()
        .flat_map(|m| m.values())
        .map(|v| match v {
            RawNspValue::One(s) => std::slice::from_ref(s),
            RawNspValue::Many(v) => v.as_slice(),
        })
        .collect();
    let any = [
        dns.nameserver.as_deref(),
        dns.fallback.as_deref(),
        dns.default_nameserver.as_deref(),
        dns.proxy_server_nameserver.as_deref(),
        dns.direct_nameserver.as_deref(),
    ]
    .into_iter()
    .chain(policy_lists.into_iter().map(Some))
    .any(needs_rewrite);
    if !any {
        return None;
    }
    let system = system_nameservers();
    let mut out = dns.clone();
    let fix = |list: &mut Option<Vec<String>>, field: &str| {
        if let Some(v) = list.as_mut() {
            *v = normalize_list(v, field, &system);
        }
    };
    fix(&mut out.nameserver, "nameserver");
    fix(&mut out.fallback, "fallback");
    fix(&mut out.default_nameserver, "default-nameserver");
    fix(&mut out.proxy_server_nameserver, "proxy-server-nameserver");
    fix(&mut out.direct_nameserver, "direct-nameserver");
    if let Some(policy) = out.nameserver_policy.as_mut() {
        for value in policy.values_mut() {
            let list = match value {
                RawNspValue::One(s) => vec![s.clone()],
                RawNspValue::Many(v) => v.clone(),
            };
            *value = RawNspValue::Many(normalize_list(&list, "nameserver-policy", &system));
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sys() -> Vec<SocketAddr> {
        vec![
            "192.168.1.1:53".parse().unwrap(),
            "[fd00::1]:53".parse().unwrap(),
        ]
    }

    fn strings(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| (*s).to_string()).collect()
    }

    #[test]
    fn system_and_dhcp_become_the_system_resolvers() {
        let got = normalize_list(
            &strings(&["system", "dhcp://en0", "system://#DIRECT", "8.8.8.8"]),
            "nameserver",
            &sys(),
        );
        assert_eq!(
            got,
            [
                "192.168.1.1:53",
                "[fd00::1]:53",
                "192.168.1.1:53#DIRECT",
                "[fd00::1]:53#DIRECT",
                "8.8.8.8"
            ]
        );
    }

    #[test]
    fn quic_falls_back_to_tls_on_the_same_host() {
        let got = normalize_list(
            &strings(&[
                "quic://dns.adguard.com:784#PROXY",
                "quic://[2606:4700::1111]",
            ]),
            "nameserver",
            &sys(),
        );
        assert_eq!(
            got,
            ["tls://dns.adguard.com#PROXY", "tls://[2606:4700::1111]"]
        );
    }

    #[test]
    fn dnscrypt_stamps_are_dropped() {
        let got = normalize_list(
            &strings(&["sdns://AQcAAAAAAAAA", "1.1.1.1"]),
            "fallback",
            &sys(),
        );
        assert_eq!(got, ["1.1.1.1"]);
    }

    #[test]
    fn resolv_conf_parsing() {
        let got = parse_resolv_conf(
            "# comment\nnameserver 127.0.0.53\nnameserver fe80::1%eth0\nsearch lan\nnameserver 127.0.0.53\n",
        );
        assert_eq!(got, ["127.0.0.53:53".parse::<SocketAddr>().unwrap()]);
    }

    #[test]
    fn untouched_sections_are_not_cloned() {
        let dns: RawDns = serde_yaml::from_str("enable: true\nnameserver: [8.8.8.8]\n").unwrap();
        assert!(normalize(&dns).is_none());
    }
}
