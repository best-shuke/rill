//! Config-parser tests for the `tun:` YAML block (issue #326).
//!
//! These exercise [`rill_config::load_config_from_str`] end-to-end and
//! assert on the resulting `Config.tun` (a [`rill_config::TunConfig`]) —
//! the parser itself (`parse_tun_config`) is exercised through it.
//!
//! # Test plan coverage (T-series)
//!
//! | ID  | Description                                                        |
//! |-----|--------------------------------------------------------------------|
//! | T1  | absent `tun:` → default (disabled)                                 |
//! | T2  | minimal `enable: true` → enabled with defaults                     |
//! | T3  | full section → every typed field lands                             |
//! | T4  | `mtu` below 1280 → hard error                                      |
//! | T5  | invalid `inet4-address` CIDR → hard error                          |
//! | T6  | `dns-hijack: [any:53]` → hijack on                                 |
//! | T7  | `dns-hijack` with only non-53 entries → hijack off (warn-only)     |
//! | T8  | mihomo fields rill accepts (`stack`, `auto-detect-interface`, …) |
//! | T8b | `inet6-address`: only with `ipv6: true` under global routing, where |
//! |     | it defaults to mihomo's; string or list form; invalid → hard error |
//! | T9  | `udp-timeout: 0` → hard error                                      |
//! | T10 | `enable: false` with other fields set → parsed but disabled        |
//! | T16 | `TunConfig` semantic equality — the PUT reconcile diff boundary    |
//! |     | (issue #543): respellings/ignored fields equal, real params not  |
//! | T17 | `global_route_outbound_interface` (the pre-build binding gate,    |
//! |     | issue #695) agrees with the parsed `TunConfig`                     |
//! | T18 | `dns-hijack` transports: `any:53` UDP, `tcp://…:53` TCP            |
//! | T19 | `strict-route`, `route-address`, `route-exclude-address`           |
//! | T20 | FlowBar's injected `tun:` block parses to mihomo's behaviour       |

use std::time::Duration;

use rill_config::load_config_from_str;

async fn expect_load_err(yaml: &str) -> String {
    match load_config_from_str(yaml).await {
        Ok(_) => panic!("expected load_config_from_str to fail, but it succeeded"),
        Err(e) => e.to_string(),
    }
}

// ─── T1: defaults — no tun: block ─────────────────────────────────────────

#[tokio::test]
async fn t1_no_tun_block_yields_default_disabled() {
    let cfg = load_config_from_str("port: 7890\n")
        .await
        .expect("config must load");
    assert!(!cfg.tun.enable, "default tun must be disabled");
    // mihomo's defaults.
    assert_eq!(cfg.tun.mtu, 9000);
    assert_eq!(cfg.tun.inet4_address.to_string(), "198.18.0.1/30");
    assert!(cfg.tun.auto_route, "auto-route defaults on");
    assert_eq!(cfg.tun.route_mode, rill_config::TunRouteMode::Global);
    assert!(!cfg.tun.dns_hijack, "dns-hijack defaults off");
    assert_eq!(
        cfg.tun.max_connections, 256,
        "TUN inherits the global max-connections default"
    );
}

// ─── T2: minimal enable ───────────────────────────────────────────────────

#[tokio::test]
async fn t2_enable_true_with_defaults() {
    let yaml = r#"
tun:
  enable: true
"#;
    let cfg = load_config_from_str(yaml).await.expect("config must load");
    assert!(cfg.tun.enable);
    assert_eq!(cfg.tun.device, None, "device defaults to platform choice");
    assert_eq!(cfg.tun.udp_timeout, Duration::from_secs(60));
}

// ─── T3: full section ─────────────────────────────────────────────────────

#[tokio::test]
async fn t3_full_section_parses_every_field() {
    let yaml = r#"
tun:
  enable: true
  device: rill0
  mtu: 9000
  inet4-address: 198.18.0.1/16
  auto-route: false
  dns-hijack:
    - any:53
  udp-timeout: 120
"#;
    let cfg = load_config_from_str(yaml).await.expect("config must load");
    assert!(cfg.tun.enable);
    assert_eq!(cfg.tun.device.as_deref(), Some("rill0"));
    assert_eq!(cfg.tun.mtu, 9000);
    assert_eq!(cfg.tun.inet4_address.to_string(), "198.18.0.1/16");
    assert!(!cfg.tun.auto_route);
    assert!(cfg.tun.dns_hijack);
    assert_eq!(cfg.tun.udp_timeout, Duration::from_secs(120));
}

// ─── T4: mtu below the userspace-stack minimum ────────────────────────────

#[tokio::test]
async fn t4_mtu_below_1280_errors() {
    let yaml = r#"
tun:
  enable: true
  mtu: 1000
"#;
    let err = expect_load_err(yaml).await;
    assert!(
        err.contains("tun.mtu"),
        "error must name tun.mtu: got {err}"
    );
}

// ─── T5: invalid inet4-address ────────────────────────────────────────────

#[tokio::test]
async fn t5_invalid_inet4_address_errors() {
    let yaml = r#"
tun:
  enable: true
  inet4-address: not-a-cidr
"#;
    let err = expect_load_err(yaml).await;
    assert!(
        err.contains("inet4-address"),
        "error must name inet4-address: got {err}"
    );
}

// ─── T6/T7: dns-hijack entry filtering ────────────────────────────────────

#[tokio::test]
async fn t6_dns_hijack_any_53_enables_hijack() {
    let yaml = r#"
tun:
  enable: true
  dns-hijack:
    - any:53
    - 198.18.0.2:53
"#;
    let cfg = load_config_from_str(yaml).await.expect("config must load");
    assert!(cfg.tun.dns_hijack);
}

#[tokio::test]
async fn t7_dns_hijack_non_53_entries_warn_and_disable() {
    let yaml = r#"
tun:
  enable: true
  dns-hijack:
    - any:5353
"#;
    let cfg = load_config_from_str(yaml).await.expect("config must load");
    assert!(
        !cfg.tun.dns_hijack,
        "non-:53 entries must not enable hijack"
    );
}

// ─── T8: upstream-only fields accepted with a warning ─────────────────────

#[tokio::test]
async fn t8_upstream_only_fields_warn_but_load() {
    let yaml = r#"
tun:
  enable: true
  stack: system
  strict-route: true
  auto-detect-interface: true
  inet6-address: fdfe:dcba:9876::1/126
  endpoint-independent-nat: false
"#;
    let cfg = load_config_from_str(yaml).await.expect("config must load");
    assert!(cfg.tun.enable, "unsupported fields are warn-only");
    assert!(cfg.tun.strict_route, "strict-route is honoured");
}

// ─── T8b: inet6-address (#375) ────────────────────────────────────────────
// Opt-in IPv6 capture for global route mode: string or mihomo list form,
// honoured only under `auto-route: global`, validated everywhere.

#[tokio::test]
async fn t8b_inet6_address_is_honoured_only_in_global_mode() {
    let v6 = |yaml: &str| {
        let yaml = yaml.to_string();
        async move { load_config_from_str(&yaml).await.unwrap().tun.inet6_address }
    };
    let want: ipnet::Ipv6Net = "fdfe:dcba:9876::1/126".parse().unwrap();
    let other: ipnet::Ipv6Net = "fd00::1/64".parse().unwrap();

    // Without `ipv6: true` the device stays IPv4-only in every mode, an
    // explicit address included — mihomo's TUN carries IPv4 only then.
    for tun in [
        "tun:\n  enable: true\n",
        "tun:\n  enable: true\n  auto-route: true\n  inet6-address: fd00::1/64\n",
        "tun:\n  enable: true\n  auto-route: global\n  inet6-address: fd00::1/64\n",
    ] {
        assert_eq!(v6(tun).await, None, "{tun}");
    }

    // `ipv6: true` under global routing: mihomo's default address, or the
    // configured one in scalar or list form (first entry wins).
    let global = "ipv6: true\ntun:\n  enable: true\n";
    assert_eq!(v6(global).await, Some(want));
    assert_eq!(
        v6(&format!("{global}  inet6-address: fd00::1/64\n")).await,
        Some(other)
    );
    assert_eq!(
        v6(&format!("{global}  inet6-address: [fd00::1/64]\n")).await,
        Some(other)
    );
    assert_eq!(
        v6(&format!(
            "{global}  inet6-address:\n    - fd00::1/64\n    - fdfe:dcba:9876::1/126\n"
        ))
        .await,
        Some(other)
    );
    // Empty forms mean "unset", which is the default here.
    assert_eq!(
        v6(&format!("{global}  inet6-address: ''\n")).await,
        Some(want)
    );
    assert_eq!(
        v6(&format!("{global}  inet6-address: []\n")).await,
        Some(want)
    );

    // Fake-IP scope and no routing have no IPv6 to send into the device.
    for mode in ["  auto-route: fake-ip\n", "  auto-route: false\n"] {
        let yaml = format!("{global}{mode}  inet6-address: fd00::1/64\n");
        assert_eq!(v6(&yaml).await, None, "{yaml}");
    }
}

#[tokio::test]
async fn t8b_invalid_inet6_address_errors_in_every_mode() {
    for yaml in [
        "tun:\n  enable: true\n  auto-route: global\n  inet6-address: not-a-cidr\n",
        "tun:\n  enable: true\n  auto-route: global\n  inet6-address: 172.19.0.1/30\n",
        "tun:\n  enable: true\n  auto-route: global\n  inet6-address: [fdfe::1]\n",
        "tun:\n  enable: true\n  auto-route: global\n  inet6-address: 7\n",
        "tun:\n  enable: true\n  inet6-address: not-a-cidr\n",
    ] {
        let err = expect_load_err(yaml).await;
        assert!(err.contains("inet6-address"), "{yaml}: got {err}");
    }
}

// ─── T9: udp-timeout: 0 ───────────────────────────────────────────────────

#[tokio::test]
async fn t9_udp_timeout_zero_errors() {
    let yaml = r#"
tun:
  enable: true
  udp-timeout: 0
"#;
    let err = expect_load_err(yaml).await;
    assert!(
        err.contains("udp-timeout"),
        "error must name udp-timeout: got {err}"
    );
}

// ─── T10: disabled section still validates ────────────────────────────────

#[tokio::test]
async fn t10_disabled_section_parses_fields() {
    let yaml = r#"
tun:
  enable: false
  device: rill0
"#;
    let cfg = load_config_from_str(yaml).await.expect("config must load");
    assert!(!cfg.tun.enable);
    assert_eq!(cfg.tun.device.as_deref(), Some("rill0"));
}

// ─── T11–T14: auto-route modes (#375) ─────────────────────────────────────

#[tokio::test]
async fn t11_auto_route_bool_follows_mihomo() {
    use rill_config::TunRouteMode;

    // mihomo's booleans: true = route everything into the device, false = off.
    let on = load_config_from_str("tun:\n  enable: true\n  auto-route: true\n")
        .await
        .expect("config must load");
    assert!(on.tun.auto_route);
    assert_eq!(on.tun.route_mode, TunRouteMode::Global);

    let off = load_config_from_str("tun:\n  enable: true\n  auto-route: false\n")
        .await
        .expect("config must load");
    assert!(!off.tun.auto_route);

    // Absent → default on, everything routed (mihomo's default).
    let default = load_config_from_str("tun:\n  enable: true\n")
        .await
        .expect("config must load");
    assert!(default.tun.auto_route);
    assert_eq!(default.tun.route_mode, TunRouteMode::Global);
}

#[tokio::test]
async fn t12_auto_route_mode_strings() {
    use rill_config::TunRouteMode;

    let fake = load_config_from_str("tun:\n  enable: true\n  auto-route: fake-ip\n")
        .await
        .expect("config must load");
    assert!(fake.tun.auto_route);
    assert_eq!(fake.tun.route_mode, TunRouteMode::FakeIp);

    let global = load_config_from_str("tun:\n  enable: true\n  auto-route: global\n")
        .await
        .expect("config must load");
    assert!(global.tun.auto_route);
    assert_eq!(global.tun.route_mode, TunRouteMode::Global);
}

#[tokio::test]
async fn t13_auto_route_unknown_mode_is_a_hard_error() {
    let err = expect_load_err("tun:\n  enable: true\n  auto-route: everything\n").await;
    assert!(
        err.contains("auto-route") && err.contains("everything"),
        "error must name the field and the bad value: got {err}"
    );
}

#[tokio::test]
async fn t14_outbound_interface_lands_and_empty_is_none() {
    let yaml = "tun:\n  enable: true\n  auto-route: global\n  outbound-interface: eth0\n";
    let cfg = load_config_from_str(yaml).await.expect("config must load");
    assert_eq!(cfg.tun.outbound_interface.as_deref(), Some("eth0"));

    // Empty string is treated as unset (auto-detect), and setting the field
    // in fake-ip mode is warn-only, not an error.
    let yaml = "tun:\n  enable: true\n  outbound-interface: ''\n";
    let cfg = load_config_from_str(yaml).await.expect("config must load");
    assert_eq!(cfg.tun.outbound_interface, None);
}

// ─── T15: global max-connections applies to TUN ───────────────────────────

#[tokio::test]
async fn t15_global_max_connections_applies_to_tun() {
    let yaml = r#"
max-connections: 32
tun:
  enable: true
"#;
    let cfg = load_config_from_str(yaml).await.expect("config must load");
    assert_eq!(cfg.tun.max_connections, 32);
}

#[tokio::test]
async fn t15b_max_connections_zero_is_unlimited() {
    let yaml = r#"
max-connections: 0
tun:
  enable: true
"#;
    let cfg = load_config_from_str(yaml).await.expect("config must load");
    assert_eq!(cfg.tun.max_connections, 0);
}

// ─── T16: semantic equality — the PUT reconcile diff boundary (issue #543) ──
// `PUT /configs` restarts a running TUN listener when the parsed
// `TunConfig` changes, so respellings/ignored fields must compare equal
// and real parameters must not.

#[tokio::test]
async fn t16_tun_config_semantic_equality_boundary() {
    async fn tun(yaml: &str) -> rill_config::TunConfig {
        load_config_from_str(yaml)
            .await
            .expect("config must load")
            .tun
    }

    let explicit_bool = tun("tun:\n  enable: true\n  auto-route: true\n").await;
    let global_mode = tun("tun:\n  enable: true\n  auto-route: global\n").await;
    let omitted = tun("tun:\n  enable: true\n").await;
    assert_eq!(explicit_bool, global_mode, "`true` ≡ `global` mode");
    assert_eq!(explicit_bool, omitted, "omitted ≡ default global scope");

    let ignored_fields =
        tun("tun:\n  enable: true\n  stack: gvisor\n  auto-detect-interface: true\n").await;
    assert_eq!(
        explicit_bool, ignored_fields,
        "fields with nothing to configure must not change the diff"
    );

    let explicit_mtu = tun("tun:\n  enable: true\n  mtu: 9000\n").await;
    assert_eq!(explicit_mtu, omitted, "explicit default ≡ omitted");

    assert_ne!(
        omitted,
        tun("tun:\n  enable: true\n  mtu: 1500\n").await,
        "a real mtu change must differ"
    );
    assert_ne!(
        omitted,
        tun("tun:\n  enable: true\n  dns-hijack:\n    - any:53\n").await,
        "a real dns-hijack change must differ"
    );
    assert_ne!(
        omitted,
        tun("max-connections: 512\ntun:\n  enable: true\n").await,
        "inherited max-connections must differ"
    );

    // `outbound-interface` is ignored in fake-IP scope — a value that does
    // nothing must not reach the diff, or a PUT touching only it would
    // bounce a healthy fake-ip listener (issue #543 review).
    let fake_ip = tun("tun:\n  enable: true\n  auto-route: fake-ip\n").await;
    let ignored_iface =
        tun("tun:\n  enable: true\n  auto-route: fake-ip\n  outbound-interface: eth9\n").await;
    assert_eq!(
        fake_ip, ignored_iface,
        "outbound-interface under fake-ip scope must not change the diff"
    );
    assert_ne!(
        omitted,
        tun("tun:\n  enable: true\n  outbound-interface: eth9\n").await,
        "the same field under global scope is real and must differ"
    );

    // Remaining listener inputs are covered by the derived PartialEq —
    // pin a representative from each family so the diff can't silently
    // stop noticing a field (issue #543 review).
    for (yaml, what) in [
        ("tun:\n  enable: true\n  device: tun7\n", "device"),
        (
            "tun:\n  enable: true\n  inet4-address: 10.9.0.1/24\n",
            "inet4-address",
        ),
        ("tun:\n  enable: true\n  udp-timeout: 30\n", "udp-timeout"),
        (
            "tun:\n  enable: true\n  auto-route: fake-ip\n",
            "route_mode",
        ),
        (
            "tun:\n  enable: true\n  strict-route: true\n",
            "strict-route",
        ),
        (
            "tun:\n  enable: true\n  route-exclude-address: [10.0.0.0/8]\n",
            "route-exclude-address",
        ),
        (
            "tun:\n  enable: true\n  dns-hijack: [tcp://any:53]\n",
            "TCP dns-hijack",
        ),
    ] {
        assert_ne!(omitted, tun(yaml).await, "a real {what} change must differ");
    }
}

// ─── T17: the pre-build global-route gate agrees with the parser (#695) ───
// The binary installs the outbound-interface binding from the *raw*
// document before `build_config` dials anything. That gate must select
// exactly the configs the parser turns into an enabled global-scope TUN,
// with the same interface — never a fake-IP / disabled one (zero change
// there), never miss a global one (its early sockets would loop).

#[tokio::test]
async fn t17_global_route_gate_matches_parsed_config() {
    use rill_config::{global_route_outbound_interface, parse_raw_yaml, TunRouteMode};

    for yaml in [
        "port: 7890\n",
        "tun:\n  enable: true\n",
        "tun:\n  enable: false\n  auto-route: global\n  outbound-interface: eth0\n",
        "tun:\n  enable: true\n  auto-route: true\n  outbound-interface: eth0\n",
        "tun:\n  enable: true\n  auto-route: false\n",
        "tun:\n  enable: true\n  auto-route: fake-ip\n  outbound-interface: eth0\n",
        "tun:\n  enable: true\n  auto-route: global\n",
        "tun:\n  enable: true\n  auto-route: global\n  outbound-interface: eth0\n",
        "tun:\n  enable: true\n  auto-route: global\n  outbound-interface: ''\n",
        "tun:\n  enable: true\n  auto-route: everything\n",
    ] {
        let raw = parse_raw_yaml(yaml).expect("raw YAML must parse");
        let gate = global_route_outbound_interface(raw.tun.as_ref());
        let expected = match load_config_from_str(yaml).await {
            Ok(cfg)
                if cfg.tun.enable
                    && cfg.tun.auto_route
                    && cfg.tun.route_mode == TunRouteMode::Global =>
            {
                Some(cfg.tun.outbound_interface)
            }
            // Not global scope, or rejected by the parser: no early binding.
            _ => None,
        };
        assert_eq!(gate, expected, "{yaml}");
    }

    // Spot-check the global cases explicitly so a regression to "always
    // None" can't pass by matching a parser that also stopped selecting
    // global scope.
    let gate =
        |yaml: &str| global_route_outbound_interface(parse_raw_yaml(yaml).unwrap().tun.as_ref());
    assert_eq!(
        gate("tun:\n  enable: true\n  auto-route: global\n  outbound-interface: eth0\n"),
        Some(Some("eth0".to_owned()))
    );
    assert_eq!(
        gate("tun:\n  enable: true\n  auto-route: global\n"),
        Some(None),
        "no outbound-interface → auto-detect"
    );
}

// ─── T18: dns-hijack transports ───────────────────────────────────────────

#[tokio::test]
async fn t18_dns_hijack_splits_udp_and_tcp() {
    async fn hijack(entries: &str) -> (bool, bool) {
        let yaml = format!("tun:\n  enable: true\n  dns-hijack: {entries}\n");
        let tun = load_config_from_str(&yaml)
            .await
            .expect("config must load")
            .tun;
        (tun.dns_hijack, tun.dns_hijack_tcp)
    }
    assert_eq!(hijack("[any:53]").await, (true, false));
    assert_eq!(hijack("[udp://1.1.1.1:53]").await, (true, false));
    assert_eq!(hijack("[tcp://any:53]").await, (false, true));
    assert_eq!(hijack("[any:53, tcp://any:53]").await, (true, true));
    // An unknown scheme or another port is ignored with a warning.
    assert_eq!(hijack("[quic://any:53, any:5353]").await, (false, false));
}

// ─── T19: strict-route and the global route lists ─────────────────────────

#[tokio::test]
async fn t19_strict_route_and_route_lists() {
    let tun = |yaml: &str| {
        let yaml = yaml.to_string();
        async move {
            load_config_from_str(&yaml)
                .await
                .expect("config must load")
                .tun
        }
    };
    let nets =
        |list: &[&str]| -> Vec<ipnet::IpNet> { list.iter().map(|s| s.parse().unwrap()).collect() };

    let cfg = tun("tun:\n  enable: true\n  strict-route: true\n  \
         route-address: [1.0.0.0/8, 2001:db8::/32]\n  inet4-route-address: 9.9.9.9\n  \
         route-exclude-address: 192.168.1.0/24\n  \
         inet6-route-exclude-address: [fd00::/8]\n")
    .await;
    assert!(cfg.strict_route);
    // A bare address is a host route; legacy per-family keys merge in.
    assert_eq!(
        cfg.route_address,
        nets(&["1.0.0.0/8", "2001:db8::/32", "9.9.9.9/32"])
    );
    assert_eq!(
        cfg.route_exclude_address,
        nets(&["192.168.1.0/24", "fd00::/8"])
    );
    // A CIDR with host bits set is normalised to its network.
    assert_eq!(
        tun("tun:\n  enable: true\n  route-exclude-address: [10.1.2.3/8]\n")
            .await
            .route_exclude_address,
        nets(&["10.0.0.0/8"])
    );

    // They only shape global routing: normalised out under fake-IP scope.
    let fake = tun(
        "tun:\n  enable: true\n  auto-route: fake-ip\n  strict-route: true\n  \
         route-exclude-address: [192.168.1.0/24]\n",
    )
    .await;
    assert!(!fake.strict_route);
    assert!(fake.route_exclude_address.is_empty());

    let err = expect_load_err("tun:\n  enable: true\n  route-exclude-address: [nope]\n").await;
    assert!(err.contains("route-exclude-address"), "{err}");
}

#[tokio::test]
async fn t19b_inet4_address_accepts_mihomo_list_form() {
    let cfg = load_config_from_str("tun:\n  enable: true\n  inet4-address: [198.19.0.1/30]\n")
        .await
        .expect("config must load");
    assert_eq!(cfg.tun.inet4_address.to_string(), "198.19.0.1/30");
}

// ─── T20: FlowBar's injected tun: block ───────────────────────────────────
// FlowBar rewrites every profile's `tun:` section to exactly this before
// starting the kernel (FlowBar `src/config.rs` `runtime`, IPv6 off, plus a
// profile's own exclusion it keeps). It must mean what it means to mihomo.

#[tokio::test]
async fn t20_flowbar_tun_block_means_what_it_means_to_mihomo() {
    let yaml = r#"
ipv6: false
tun:
  route-exclude-address: [192.168.1.0/24]
  enable: true
  device: utun
  auto-route: true
  auto-detect-interface: true
  stack: mixed
  dns-hijack:
    - any:53
    - tcp://any:53
  strict-route: true
"#;
    let tun = load_config_from_str(yaml)
        .await
        .expect("config must load")
        .tun;
    assert!(tun.enable && tun.auto_route);
    assert_eq!(tun.stack, rill_config::TunStack::System);
    assert_eq!(tun.route_mode, rill_config::TunRouteMode::Global);
    assert_eq!(tun.device.as_deref(), Some("utun"));
    assert!(tun.dns_hijack && tun.dns_hijack_tcp);
    assert!(tun.strict_route);
    assert_eq!(
        tun.inet6_address, None,
        "IPv6 off → the device is IPv4-only"
    );
    assert_eq!(
        tun.route_exclude_address,
        vec!["192.168.1.0/24".parse::<ipnet::IpNet>().unwrap()]
    );
    assert_eq!(tun.mtu, 9000);
    assert_eq!(tun.outbound_interface, None, "auto-detected and followed");
}

#[tokio::test]
async fn stack_aliases_defaults_and_unknown_values() {
    use rill_config::TunStack;

    for (value, expected) in [
        ("system", TunStack::System),
        ("mixed", TunStack::System),
        ("gvisor", TunStack::Lwip),
        ("lwip", TunStack::Lwip),
        ("future-stack", TunStack::Lwip),
        ("42", TunStack::Lwip),
        ("[system]", TunStack::Lwip),
        ("null", TunStack::Lwip),
    ] {
        let yaml = format!("tun:\n  enable: true\n  stack: {value}\n");
        let cfg = load_config_from_str(&yaml).await.unwrap();
        assert_eq!(cfg.tun.stack, expected, "{value}");
    }
    let default = load_config_from_str("tun:\n  enable: true\n")
        .await
        .unwrap()
        .tun;
    assert_eq!(default.stack, TunStack::Lwip);
    let system = load_config_from_str("tun:\n  enable: true\n  stack: system\n")
        .await
        .unwrap()
        .tun;
    let mixed = load_config_from_str("tun:\n  enable: true\n  stack: mixed\n")
        .await
        .unwrap()
        .tun;
    assert_eq!(system, mixed);
    assert_ne!(default, system, "stack changes must restart the listener");
}

/// A saved config keeps the user's spelling: `mixed` / `gvisor` are not
/// rewritten to the backend rill picked for them.
#[test]
fn stack_round_trips_as_written() {
    for value in ["mixed", "gvisor", "future-stack"] {
        let yaml = format!("tun:\n  enable: true\n  stack: {value}\n");
        let raw: rill_config::raw::RawConfig = serde_yaml::from_str(&yaml).unwrap();
        let saved = serde_yaml::to_string(&raw).unwrap();
        assert!(saved.contains(&format!("stack: {value}")), "{saved}");
    }
}
