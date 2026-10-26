//! Inbound protocol listeners for the rill proxy kernel.
//!
//! Mixed, HTTP, SOCKS5, and TProxy acceptors, plus an optional TUN device
//! inbound (feature `listener-tun`).

pub mod sniffer;

pub const DEFAULT_HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

/// Process-wide monotonic timestamp in milliseconds. Used by UDP flow tables
/// (SOCKS5-UDP and the shadowsocks listener) for idle eviction. The `START`
/// instant is lazily initialized on the first call and never changes.
#[cfg(any(feature = "listener-socks5", feature = "listener-shadowsocks"))]
pub(crate) fn monotonic_ms() -> u64 {
    static START: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
    START
        .get_or_init(std::time::Instant::now)
        .elapsed()
        .as_millis() as u64
}

/// Disable Nagle on an accepted inbound socket, as Go (and so mihomo) does
/// for every TCP conn. With Nagle on, the tail of each response written back
/// to the client waits for the client's delayed ACK (40 ms on Linux), which
/// capped sequential 1 MiB relays at ~0.4 Gbps on loopback. Best effort: a
/// socket that refuses the option still relays, just with Nagle.
#[cfg(any(feature = "listener-mixed", feature = "listener-tproxy"))]
pub(crate) fn set_inbound_nodelay(stream: &tokio::net::TcpStream) {
    if let Err(e) = stream.set_nodelay(true) {
        tracing::debug!("TCP_NODELAY on inbound socket failed: {e}");
    }
}

#[cfg(feature = "listener-http")]
pub mod http_proxy;
#[cfg(feature = "listener-mixed")]
pub mod mixed;
#[cfg(feature = "listener-shadowsocks")]
pub mod shadowsocks;
#[cfg(feature = "listener-socks5")]
pub mod socks5;
#[cfg(feature = "listener-socks5")]
mod socks5_udp;
#[cfg(feature = "listener-tproxy")]
pub mod tproxy;
#[cfg(feature = "listener-tun")]
pub mod tun;

#[cfg(feature = "listener-mixed")]
pub use mixed::MixedListener;
#[cfg(feature = "listener-shadowsocks")]
pub use shadowsocks::{ShadowsocksListener, SsObfsMode};
pub use sniffer::SnifferRuntime;
#[cfg(feature = "listener-tproxy")]
pub use tproxy::TProxyListener;
#[cfg(feature = "listener-tun")]
pub use tun::{OutboundBinding, TunListener, TunListenerConfig, TunReady, TunRouteScope};

#[cfg(all(test, any(feature = "listener-mixed", feature = "listener-tproxy")))]
#[tokio::test]
async fn inbound_nodelay_disables_nagle() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let client = tokio::net::TcpStream::connect(listener.local_addr().unwrap())
        .await
        .unwrap();
    let (server, _) = listener.accept().await.unwrap();
    assert!(
        !server.nodelay().unwrap(),
        "accepted sockets start with Nagle on"
    );
    set_inbound_nodelay(&server);
    assert!(server.nodelay().unwrap());
    drop(client);
}

#[cfg(all(
    test,
    any(
        feature = "listener-socks5",
        feature = "listener-tun",
        feature = "listener-shadowsocks"
    )
))]
fn test_rule_tunnel() -> rill_tunnel::Tunnel {
    let resolver = std::sync::Arc::new(rill_dns::Resolver::new(
        vec![],
        vec![],
        rill_common::DnsMode::Normal,
        rill_trie::DomainTrie::new(),
        false,
        true,
    ));
    let tunnel = rill_tunnel::Tunnel::new(resolver);
    let res = rill_config::rebuild_from_raw(&Default::default()).unwrap();
    tunnel.update_proxies(res.proxies, res.dialer_registry);
    tunnel.update_rules(vec![Box::new(rill_rules::final_rule::FinalRule::new(
        "REJECT",
    ))]);
    tunnel
}
