//! IN-TYPE rule — matches on the inbound connection type (`Metadata.conn_type`).
//!
//! upstream: `rules/common/in_type.go`
//!
//! The payload is one type or several joined by `/` (`SOCKS/HTTP`), as in
//! mihomo. `SOCKS` covers SOCKS4 and SOCKS5; `HTTP` covers plain and
//! CONNECT requests (a rill superset: mihomo's `HTTP` is the plain one).
//! Types mihomo knows but rill has no inbound for (`SNELL`, `ANYTLS`, …)
//! parse and never match. Anything else is a parse error, as upstream.

use rill_common::{ConnType, Metadata, Rule, RuleMatchHelper, RuleType};

use crate::adapter::{intern_adapter, Adapter};
use smol_str::SmolStr;

pub struct InTypeRule {
    raw: SmolStr,
    adapter: Adapter,
    /// One bit per `ConnType` discriminant.
    mask: u32,
}

fn bit(t: ConnType) -> u32 {
    1u32 << (t as u32)
}

/// The inbound-type bitmask an IN-TYPE payload compiles to — shared with
/// the compiled rule IR so both paths read the payload the same way.
pub fn in_type_mask(payload: &str) -> Result<u32, String> {
    let mut mask = 0;
    for token in payload.split('/') {
        mask |= token_mask(token.trim())?;
    }
    Ok(mask)
}

/// Whether `mask` (from [`in_type_mask`]) covers `conn_type`.
pub fn in_type_mask_matches(mask: u32, conn_type: ConnType) -> bool {
    mask & bit(conn_type) != 0
}

/// The inbound types one IN-TYPE token stands for (`Ok(0)`: a type rill
/// has no inbound for).
fn token_mask(token: &str) -> Result<u32, String> {
    use ConnType as C;
    Ok(match token.to_ascii_uppercase().as_str() {
        "HTTP" => bit(C::Http) | bit(C::Https),
        "HTTPS" => bit(C::Https),
        "SOCKS" => bit(C::Socks4) | bit(C::Socks5),
        "SOCKS4" => bit(C::Socks4),
        "SOCKS5" => bit(C::Socks5),
        "SHADOWSOCKS" => bit(C::Shadowsocks),
        "VMESS" => bit(C::Vmess),
        "VLESS" => bit(C::Vless),
        "REDIR" => bit(C::Redir),
        "TPROXY" => bit(C::TProxy),
        "TROJAN" => bit(C::Trojan),
        "TUN" => bit(C::Tun),
        "TUNNEL" => bit(C::Tunnel),
        "TUIC" => bit(C::Tuic),
        "HYSTERIA2" => bit(C::Hysteria2),
        "INNER" => bit(C::Inner),
        "SNELL" | "ANYTLS" | "MIERU" | "SUDOKU" | "TRUSTTUNNEL" | "SHADOWQUIC" => 0,
        "" => return Err("IN-TYPE: an inbound type cannot be empty".to_string()),
        other => {
            return Err(format!(
                "unknown IN-TYPE value '{other}'; expected HTTP, HTTPS, SOCKS, SOCKS4, SOCKS5, \
                 SHADOWSOCKS, VMESS, VLESS, REDIR, TPROXY, TROJAN, TUN, TUNNEL, TUIC, HYSTERIA2 \
                 or INNER, alone or joined by '/'"
            ))
        }
    })
}

impl InTypeRule {
    /// Parse the IN-TYPE value string into a rule.
    ///
    /// upstream: `rules/common/in_type.go::NewInType`
    pub fn new(type_str: &str, adapter: &str) -> Result<Self, String> {
        let mask = in_type_mask(type_str)?;
        Ok(Self {
            raw: type_str.to_ascii_uppercase().into(),
            adapter: intern_adapter(adapter),
            mask,
        })
    }
}

impl Rule for InTypeRule {
    fn rule_type(&self) -> RuleType {
        RuleType::InType
    }

    fn match_metadata(&self, metadata: &Metadata, _helper: &RuleMatchHelper) -> bool {
        in_type_mask_matches(self.mask, metadata.conn_type)
    }

    fn adapter(&self) -> &str {
        &self.adapter
    }

    fn payload(&self) -> &str {
        &self.raw
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rill_common::{ConnType, Metadata, RuleMatchHelper};

    fn helper() -> RuleMatchHelper {
        RuleMatchHelper
    }

    fn meta_with_conn(conn_type: ConnType) -> Metadata {
        Metadata {
            conn_type,
            ..Default::default()
        }
    }

    #[test]
    fn in_type_http_matches_http_and_https() {
        let r = InTypeRule::new("HTTP", "DIRECT").unwrap();
        assert!(r.match_metadata(&meta_with_conn(ConnType::Http), &helper()));
        assert!(r.match_metadata(&meta_with_conn(ConnType::Https), &helper()));
    }

    #[test]
    fn in_type_https_matches_only_https() {
        let r = InTypeRule::new("HTTPS", "DIRECT").unwrap();
        assert!(r.match_metadata(&meta_with_conn(ConnType::Https), &helper()));
        assert!(!r.match_metadata(&meta_with_conn(ConnType::Http), &helper()));
    }

    #[test]
    fn in_type_socks5_matches_socks5() {
        let r = InTypeRule::new("SOCKS5", "DIRECT").unwrap();
        assert!(r.match_metadata(&meta_with_conn(ConnType::Socks5), &helper()));
        assert!(!r.match_metadata(&meta_with_conn(ConnType::Http), &helper()));
    }

    #[test]
    fn in_type_tproxy_matches_tproxy() {
        let r = InTypeRule::new("TPROXY", "DIRECT").unwrap();
        assert!(r.match_metadata(&meta_with_conn(ConnType::TProxy), &helper()));
        assert!(!r.match_metadata(&meta_with_conn(ConnType::Http), &helper()));
    }

    #[test]
    fn in_type_unknown_value_hard_errors() {
        // Class A per ADR-0002: upstream: rules/common/inbound.go
        // NOT upstream: unknown IN-TYPE is silently skipped in some versions
        assert!(InTypeRule::new("QUIC", "DIRECT").is_err());
        assert!(InTypeRule::new("HTTP/", "DIRECT").is_err());
    }

    #[test]
    fn in_type_takes_a_slash_separated_list() {
        let r = InTypeRule::new("SOCKS/HTTPS", "DIRECT").unwrap();
        assert!(r.match_metadata(&meta_with_conn(ConnType::Socks4), &helper()));
        assert!(r.match_metadata(&meta_with_conn(ConnType::Socks5), &helper()));
        assert!(r.match_metadata(&meta_with_conn(ConnType::Https), &helper()));
        assert!(!r.match_metadata(&meta_with_conn(ConnType::Http), &helper()));
        assert!(!r.match_metadata(&meta_with_conn(ConnType::Tun), &helper()));
        assert_eq!(r.payload(), "SOCKS/HTTPS");
    }

    #[test]
    fn in_type_types_without_a_rill_inbound_parse_and_never_match() {
        let r = InTypeRule::new("anytls", "DIRECT").unwrap();
        assert!(!r.match_metadata(&meta_with_conn(ConnType::Http), &helper()));
        let r = InTypeRule::new("TUN/MIERU", "DIRECT").unwrap();
        assert!(r.match_metadata(&meta_with_conn(ConnType::Tun), &helper()));
    }
}
