use std::collections::HashMap;
fn node(extra: &str) -> HashMap<String, serde_yaml::Value> {
    serde_yaml::from_str(&format!("name: fixture\ntype: xpro\nserver: localhost\nport: 443\ndevice-id: '01010101010101010101010101010101'\nkey-file: /missing-xpro-key\n{extra}")).unwrap()
}
#[cfg(not(feature = "xpro"))]
#[test]
fn disabled_feature_is_actionable() {
    let error = rill_config::proxy_parser::parse_proxy(&node(""), false)
        .err()
        .unwrap();
    assert!(error.contains("--features xpro"));
}
#[tokio::test]
async fn invalid_xpro_stays_bound_across_reload_and_provider() {
    use rill_common::AdapterType;
    for kind in ["xpro", " Xpro "] {
        let mut node = node("");
        node.insert("type".into(), kind.into());
        let raw = rill_config::raw::RawConfig {
            proxies: Some(vec![node]),
            ..Default::default()
        };
        for _ in 0..2 {
            let built = rill_config::rebuild_from_raw(&raw).unwrap();
            let proxy = &built.proxies["fixture"];
            assert_eq!(proxy.adapter_type(), AdapterType::Xpro);
            assert!(!proxy.alive());
            assert!(proxy.support_udp());
            assert!(proxy.dial_tcp(&Default::default()).await.is_err());
            assert!(proxy.dial_udp(&Default::default()).await.is_err());
        }
    }
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("nodes.yaml");
    std::fs::write(
        &path,
        "proxies:\n  - {name: fixture, type: xpro, server: localhost, port: 443}\n",
    )
    .unwrap();
    let raw = serde_yaml::from_str(&format!("type: file\npath: {}\n", path.display())).unwrap();
    let provider = rill_config::proxy_provider::ProxyProvider::new(
        "xpro",
        &raw,
        Some(dir.path()),
        false,
        false,
        Default::default(),
    )
    .unwrap();
    provider.acquire_initial().await.unwrap();
    let proxies = provider.proxies();
    assert_eq!(proxies.len(), 1);
    assert_eq!(proxies[0].adapter_type(), AdapterType::Xpro);
    assert!(!proxies[0].alive());
}
#[cfg(feature = "xpro")]
#[test]
fn enabled_schema_and_unsupported_policies() {
    let key = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(key.path(), [7; 32]).unwrap();
    let mut good = node("");
    good.insert("key-file".into(), key.path().to_str().unwrap().into());
    let proxy = rill_config::proxy_parser::parse_proxy(&good, false).unwrap();
    assert_eq!(proxy.adapter_type(), rill_common::AdapterType::Xpro);
    assert!(!proxy.support_udp());
    for extra in [
        "udp: true",
        "udp: maybe",
        "transport: quic",
        "skip-cert-verify: true",
        "dialer-proxy: DIRECT",
        "transport: wss",
        "inner-tls: {}",
        "key: do-not-log-secret",
    ] {
        let additional: HashMap<String, serde_yaml::Value> = serde_yaml::from_str(extra).unwrap();
        let mut bad = good.clone();
        bad.extend(additional);
        let error = rill_config::proxy_parser::parse_proxy(&bad, false)
            .err()
            .unwrap();
        assert!(!error.contains("do-not-log-secret"));
    }
}
