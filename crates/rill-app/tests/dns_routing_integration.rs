//! DNS outbound selection through the real config, resolver and tunnel wiring.
use rill_common::{Metadata, ProxyAdapter, TunnelMode};
use rill_dns::Resolver;
use rill_tunnel::Tunnel;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};

async fn dns_stub(ip: [u8; 4]) -> (SocketAddr, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let queries = Arc::new(AtomicUsize::new(0));
    let count = Arc::clone(&queries);
    tokio::spawn(async move {
        while let Ok((mut connection, _)) = listener.accept().await {
            let count = Arc::clone(&count);
            tokio::spawn(async move {
                while let Ok(length) = connection.read_u16().await {
                    let mut query = vec![0; usize::from(length)];
                    if connection.read_exact(&mut query).await.is_err() {
                        break;
                    }
                    count.fetch_add(1, Ordering::SeqCst);
                    let mut end = 12;
                    while query[end] != 0 {
                        end += usize::from(query[end]) + 1;
                    }
                    end += 5; // root label, type, class
                    let mut answer = query[..end].to_vec();
                    answer[2..4].copy_from_slice(&0x8180u16.to_be_bytes());
                    answer[6..8].copy_from_slice(&1u16.to_be_bytes());
                    answer[8..12].fill(0);
                    answer.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4]);
                    answer.extend_from_slice(&ip);
                    if connection.write_u16(answer.len() as u16).await.is_err() {
                        break;
                    }
                    if connection.write_all(&answer).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    (address, queries)
}

async fn configured(dns: &str) -> (Arc<Resolver>, Tunnel) {
    let config = rill_config::load_config_from_str(&format!(
        "ipv6: false\nproxies: []\nproxy-groups: []\nrules: [\"MATCH,REJECT\"]\ndns:\n  enable: true\n{dns}"
    )).await.unwrap();
    let resolver = Arc::clone(&config.dns.resolver);
    let tunnel = Tunnel::new_with_slot(Arc::clone(&config.dns.resolver_slot));
    tunnel.update_routing(config.proxies, config.rules, config.dialer_registry);
    (resolver, tunnel)
}

#[tokio::test]
async fn respect_rules_and_explicit_outbound_tags_use_live_routing() {
    let (upstream, count) = dns_stub([203, 0, 113, 7]).await;
    let (resolver, tunnel) = configured(&format!(
        "  respect-rules: true\n  proxy-server-nameserver: [tcp://{upstream}]\n  nameserver: [tcp://{upstream}]\n"
    ))
    .await;
    assert!(resolver.resolve_ips("rejected.test").await.is_err());
    assert_eq!(
        count.load(Ordering::SeqCst),
        0,
        "REJECT must prevent an upstream dial"
    );

    tunnel.set_mode(TunnelMode::Direct);
    assert_eq!(
        resolver
            .resolve_ips("direct-mode.test")
            .await
            .unwrap()
            .unwrap(),
        vec![IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7))]
    );
    assert_eq!(count.load(Ordering::SeqCst), 1);
    let replacement = rill_config::load_config_from_str(&format!(
        "ipv6: false\ndns:\n  enable: true\n  respect-rules: true\n  proxy-server-nameserver: [tcp://{upstream}]\n  nameserver: [tcp://{upstream}]\n"
    )).await.unwrap();
    tunnel.set_resolver(Arc::clone(&replacement.dns.resolver));
    assert!(replacement
        .dns
        .resolver
        .resolve_ips("after-reload.test")
        .await
        .unwrap()
        .is_some());
    tunnel.set_mode(TunnelMode::Rule);
    assert!(replacement
        .dns
        .resolver
        .resolve_ips("rejected-after-reload.test")
        .await
        .is_err());
    assert_eq!(count.load(Ordering::SeqCst), 2);
    drop(tunnel);
    assert!(
        resolver
            .resolve_ips("after-tunnel-drop.test")
            .await
            .is_err(),
        "a retained resolver must fail closed after its routing owner stops"
    );

    let (resolver, _tunnel) = configured(&format!(
        "  respect-rules: true\n  proxy-server-nameserver: [tcp://{upstream}]\n  nameserver: ['tcp://{upstream}#DIRECT']\n"
    ))
    .await;
    assert!(resolver
        .resolve_ips("explicit-direct.test")
        .await
        .unwrap()
        .is_some());
    assert_eq!(count.load(Ordering::SeqCst), 3);

    let (resolver, _tunnel) = configured(&format!(
        "  respect-rules: false\n  nameserver: ['tcp://{upstream}#RULES']\n"
    ))
    .await;
    assert!(resolver.resolve_ips("explicit-rules.test").await.is_err());
    assert_eq!(count.load(Ordering::SeqCst), 3);
}

#[tokio::test]
async fn direct_nameserver_has_separate_cache_and_optional_policy() {
    let (main, _) = dns_stub([127, 0, 0, 2]).await;
    let (direct, _) = dns_stub([127, 0, 0, 1]).await;
    let (policy, _) = dns_stub([127, 0, 0, 3]).await;
    for follow in [false, true] {
        let (resolver, tunnel) = configured(&format!(
            "  nameserver: [tcp://{main}]\n  direct-nameserver: [tcp://{direct}]\n  direct-nameserver-follow-policy: {follow}\n  nameserver-policy:\n    policy.test: tcp://{policy}\n"
        )).await;
        assert_eq!(
            resolver.resolve_ips("normal.test").await.unwrap().unwrap(),
            vec![IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2))]
        );
        assert_eq!(
            resolver
                .resolve_ips_direct("normal.test")
                .await
                .unwrap()
                .unwrap(),
            vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]
        );
        assert_eq!(
            resolver.resolve_ips("policy.test").await.unwrap().unwrap(),
            vec![IpAddr::V4(Ipv4Addr::new(127, 0, 0, 3))]
        );
        let expected = if follow { 3 } else { 1 };
        assert_eq!(
            resolver
                .resolve_ips_direct("policy.test")
                .await
                .unwrap()
                .unwrap(),
            vec![IpAddr::V4(Ipv4Addr::new(127, 0, 0, expected))]
        );

        let destination = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let connection = tunnel
            .inner()
            .direct
            .dial_tcp(&Metadata {
                host: "normal.test".into(),
                dst_port: destination.local_addr().unwrap().port(),
                ..Metadata::default()
            })
            .await
            .expect("DIRECT must dial the direct-nameserver answer, not the main cache");
        drop(connection);

        // IP rules may already have populated dst_ip from the main cache.
        // The selected DIRECT outbound must still use its dedicated resolver.
        let mut metadata = Metadata {
            host: "normal.test".into(),
            dst_ip: Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2))),
            dst_port: destination.local_addr().unwrap().port(),
            ..Metadata::default()
        };
        let connection = tunnel.inner().direct.dial_tcp(&metadata).await.unwrap();
        drop(connection);

        let echo = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        metadata.network = rill_common::Network::Udp;
        metadata.dst_port = echo.local_addr().unwrap().port();
        let connection = tunnel.inner().direct.dial_udp(&metadata).await.unwrap();
        let old_target = SocketAddr::new(metadata.dst_ip.unwrap(), metadata.dst_port);
        connection
            .write_packet(b"direct-dns-udp", &old_target)
            .await
            .unwrap();
        let mut buffer = [0; 64];
        let (length, source) = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            echo.recv_from(&mut buffer),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(&buffer[..length], b"direct-dns-udp");
        echo.send_to(&buffer[..length], source).await.unwrap();
        let (length, source) = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            connection.read_packet(&mut buffer),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(&buffer[..length], b"direct-dns-udp");
        assert_eq!(source, echo.local_addr().unwrap());

        // Internal DNS dials retain their bootstrap address and cannot loop.
        metadata.network = rill_common::Network::Tcp;
        metadata.internal = true;
        metadata.dst_ip = Some(IpAddr::V4(Ipv4Addr::LOCALHOST));
        metadata.dst_port = destination.local_addr().unwrap().port();
        metadata.host = "upstream.invalid".into();
        assert!(tunnel.inner().direct.dial_tcp(&metadata).await.is_ok());
    }
}

async fn load_error(dns: &str) -> String {
    let error = rill_config::load_config_from_str(&format!(
        "ipv6: false\nproxies: []\nrules: [\"MATCH,REJECT\"]\n{dns}"
    ))
    .await
    .err()
    .expect("config must be rejected");
    format!("{error:#}")
}

#[tokio::test]
async fn respect_rules_requires_proxy_server_nameserver_as_in_mihomo() {
    let error = load_error(
        "dns:\n  enable: true\n  respect-rules: true\n  nameserver: [tcp://127.0.0.1:1]\n",
    )
    .await;
    assert!(error.contains("proxy-server-nameserver"), "{error}");
}

#[tokio::test]
async fn direct_nameserver_keeps_its_own_route_under_respect_rules() {
    let (main, main_count) = dns_stub([127, 0, 0, 2]).await;
    let (direct, direct_count) = dns_stub([127, 0, 0, 1]).await;
    let (resolver, _tunnel) = configured(&format!(
        "  respect-rules: true\n  proxy-server-nameserver: [tcp://{main}]\n  nameserver: [tcp://{main}]\n  direct-nameserver: [tcp://{direct}]\n"
    ))
    .await;
    assert!(
        resolver.resolve_ips("ruled.test").await.is_err(),
        "MATCH,REJECT routes the main nameserver"
    );
    assert_eq!(main_count.load(Ordering::SeqCst), 0);
    assert_eq!(
        resolver
            .resolve_ips_direct("direct.test")
            .await
            .unwrap()
            .unwrap(),
        vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
        "direct-nameserver is not rule-routed (mihomo parses it with respect-rules off)"
    );
    assert_eq!(direct_count.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn mihomo_parameters_and_missing_outbounds_still_load() {
    let (upstream, count) = dns_stub([203, 0, 113, 9]).await;
    // Subscriptions carry these; mihomo loads them and so must rill.
    let (resolver, _tunnel) = configured(&format!(
        "  nameserver: ['tcp://{upstream}#h3=true&ecs=1.2.3.0/24&disable-ipv6=true']\n"
    ))
    .await;
    assert_eq!(
        resolver.resolve_ips("params.test").await.unwrap().unwrap(),
        vec![IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9))]
    );
    assert_eq!(count.load(Ordering::SeqCst), 1);

    // A group the config lacks: the config loads, the upstream fails its
    // queries — never a direct query — and the other upstreams still answer.
    for lists in [
        format!("  nameserver: ['tcp://{upstream}#节点选择']\n"),
        format!("  nameserver: [tcp://127.0.0.1:1]\n  fallback: ['tcp://{upstream}#节点选择']\n"),
        format!("  nameserver: [tcp://127.0.0.1:1]\n  direct-nameserver: ['tcp://{upstream}#节点选择']\n"),
    ] {
        let (resolver, _tunnel) = configured(&lists).await;
        assert!(resolver.resolve_ips_direct("missing.test").await.is_err());
    }
    let (resolver, _tunnel) = configured(&format!(
        "  nameserver: ['tcp://{upstream}#节点选择']\n  nameserver-policy:\n    policy.test: 'tcp://{upstream}#节点选择'\n"
    ))
    .await;
    assert!(resolver.resolve_ips("policy.test").await.is_err());
    assert_eq!(
        count.load(Ordering::SeqCst),
        1,
        "a missing outbound never dials"
    );
    let labels: Vec<String> = resolver
        .nameserver_policy()
        .unwrap()
        .clients()
        .iter()
        .map(|client| client.upstream_label())
        .collect();
    assert_eq!(labels, [format!("{upstream}#节点选择")]);
    let (resolver, _tunnel) = configured(&format!(
        "  nameserver: ['tcp://{upstream}#节点选择', 'tcp://{upstream}']\n"
    ))
    .await;
    assert!(resolver.resolve_ips("other.test").await.unwrap().is_some());
    assert_eq!(
        count.load(Ordering::SeqCst),
        2,
        "the defined upstream answers"
    );

    let error = load_error(&format!(
        "strict: true\ndns:\n  enable: true\n  nameserver: ['tcp://{upstream}#节点选择']\n"
    ))
    .await;
    assert!(
        error.contains("节点选择") && error.contains("strict"),
        "{error}"
    );

    // rill 0.1.0 read a bare DoT/DoH fragment as the TLS name; say how to
    // write that now.
    let error = load_error(
        "strict: true\ndns:\n  enable: true\n  nameserver: ['tls://1.1.1.1#cloudflare-dns.com']\n",
    )
    .await;
    assert!(error.contains("#sni=cloudflare-dns.com"), "{error}");
}

#[tokio::test]
async fn policy_upstream_keeps_its_hostname_after_bootstrap() {
    let (bootstrap, _) = dns_stub([127, 0, 0, 1]).await;
    let (resolver, _tunnel) = configured(&format!(
        "  default-nameserver: [tcp://{bootstrap}]\n  nameserver: [tcp://{bootstrap}]\n  nameserver-policy:\n    policy.test: ['https://doh.test/dns-query', 'tls://dot.test:8853']\n"
    ))
    .await;
    let labels: Vec<String> = resolver
        .nameserver_policy()
        .unwrap()
        .lookup("policy.test")
        .unwrap()
        .nameservers
        .iter()
        .map(|client| client.upstream_label())
        .collect();
    // The bootstrap IP is only where to connect: the name stays the DoH
    // `Host`, the TLS name and the destination DNS routing matches.
    assert_eq!(
        labels,
        ["https://doh.test/dns-query", "tls://dot.test:8853"]
    );
}

#[test]
fn dns_routing_options_reject_malformed_types() {
    for option in [
        "respect-rules",
        "direct-nameserver",
        "direct-nameserver-follow-policy",
    ] {
        let yaml = format!("strict: true\ndns:\n  {option}: {{invalid: shape}}\n");
        assert!(
            serde_yaml::from_str::<rill_config::raw::RawConfig>(&yaml).is_err(),
            "{option} must not be silently discarded"
        );
    }
}
