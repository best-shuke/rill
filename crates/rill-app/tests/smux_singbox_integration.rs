// Real-server smux E2E (PR #491 review): the smux echo/pool/UDP suites all
// use in-memory mock peers, and the v2ray-plugin integration test runs the
// server with `mux=0`, so nothing validated smux against a real
// sing-box/mihomo server. This suite closes that gap: every byte travels
// config parsing → mixed listener → tunnel routing → VLESS adapter
// (+ sing-mux smux) → a real sing-box process → direct outbound → a local
// echo server, and back.
//
// It covers:
//   * a 4 MiB bulk transfer — thirty-two times the per-stream receive
//     share — with a continuously reading consumer, which must never be
//     aborted;
//   * a slow reader sharing the physical session (max-connections: 1)
//     with fast readers: the slow stream is isolated, its peers and the
//     session itself survive, and a fresh stream on the same session
//     works afterwards;
//   * `padding: true` sessions (smux, yamux, h2mux) against an inbound
//     with `multiplex.padding: true`, which rejects unpadded clients
//     (issue #495 item 11).
//
// Server availability policy — the inverse of the SKIP-by-default suites:
// this test FAILS when sing-box is missing, because a green CI run must
// mean real-server smux was exercised. CI installs a pinned sing-box (see
// .github/workflows/test.yml). To skip locally — never in CI — set
// RILL_SMUX_E2E_ALLOW_SKIP=1; the skip line is loud and explicit.
//
// Binary discovery: `$SINGBOX_BIN` overrides, otherwise `sing-box` must be
// on PATH.
#![cfg(all(feature = "vless", feature = "mux", feature = "listener-mixed"))]

use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Pinned sing-box release this suite is validated against. Bump together
/// with the CI install step in .github/workflows/test.yml.
const SINGBOX_VERSION: &str = "1.14.0";
/// VLESS user UUID shared by the client config and the sing-box inbound.
const TEST_UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";
/// Per-stream receive share in rill's smux (`MAX_RECEIVE_BUFFER / 32`).
/// Duplicated here because the constant is private to rill-proxy.
const MAX_STREAM_BUFFER: usize = 4 * 1024 * 1024 / 32;
/// Wall-clock margin over rill's `STREAM_STALL_GRACE` (500 ms) for the
/// slow-reader isolation to take effect against real sockets.
const ISOLATION_WAIT: Duration = Duration::from_secs(2);

// ─── sing-box server ──────────────────────────────────────────────────────

/// Locate the sing-box binary: `$SINGBOX_BIN`, then PATH.
fn singbox_binary() -> Option<PathBuf> {
    if let Some(path) = std::env::var_os("SINGBOX_BIN") {
        let path = PathBuf::from(path);
        if path.is_file() {
            return Some(path);
        }
        panic!("SINGBOX_BIN is set but does not point at a file: {path:?}");
    }
    let path_var = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path_var) {
        let exe = if cfg!(windows) {
            dir.join("sing-box.exe")
        } else {
            dir.join("sing-box")
        };
        if exe.is_file() {
            return Some(exe);
        }
    }
    None
}

/// Resolve sing-box, or fail the test. The explicit opt-out env var prints
/// a loud SKIP line and lets the test return early; everything else —
/// including CI — fails hard, so green always means "real-server smux was
/// exercised".
fn require_singbox() -> Option<PathBuf> {
    match singbox_binary() {
        Some(bin) => Some(bin),
        None => {
            if std::env::var_os("RILL_SMUX_E2E_ALLOW_SKIP").is_some() {
                eprintln!(
                    "SKIP: sing-box (v{SINGBOX_VERSION}) not found and \
                     RILL_SMUX_E2E_ALLOW_SKIP is set — real-server smux E2E \
                     NOT exercised"
                );
                None
            } else {
                panic!(
                    "sing-box (v{SINGBOX_VERSION}) is required for the real-server \
                     smux E2E and was not found (SINGBOX_BIN unset, not on PATH). \
                     Install it from https://github.com/SagerNet/sing-box/releases — \
                     a green CI run must exercise real-server smux, so this test \
                     refuses to silently skip. Set RILL_SMUX_E2E_ALLOW_SKIP=1 \
                     only for a loud local skip."
                )
            }
        }
    }
}

struct SingBoxServer {
    child: Child,
    log_path: PathBuf,
}

impl Drop for SingBoxServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Start `sing-box run` with a VLESS inbound (multiplex enabled) and a
/// direct outbound. The client selects the mux protocol via its sing-mux
/// request header, so the server side needs only `"enabled": true`;
/// `padding` makes the inbound require padded sessions.
fn start_singbox(bin: &Path, dir: &Path, port: u16, padding: bool) -> SingBoxServer {
    let config = format!(
        r#"{{
  "log": {{"level": "info", "output": "singbox.log"}},
  "inbounds": [{{
    "type": "vless",
    "tag": "vless-in",
    "listen": "127.0.0.1",
    "listen_port": {port},
    "users": [{{"name": "e2e", "uuid": "{TEST_UUID}"}}],
    "multiplex": {{"enabled": true, "padding": {padding}}}
  }}],
  "outbounds": [{{"type": "direct", "tag": "out"}}]
}}"#
    );
    let config_path = dir.join("singbox.json");
    std::fs::write(&config_path, config).expect("write sing-box config");
    let log_path = dir.join("singbox.log");

    let child = Command::new(bin)
        .arg("run")
        .arg("-c")
        .arg(&config_path)
        .current_dir(dir)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap_or_else(|e| panic!("failed to spawn sing-box at {bin:?}: {e}"));
    SingBoxServer { child, log_path }
}

fn singbox_log(server: &SingBoxServer) -> String {
    std::fs::read_to_string(&server.log_path).unwrap_or_default()
}

/// Poll until sing-box's VLESS inbound accepts connections.
async fn wait_listening(server: &SingBoxServer, port: u16) {
    let addr: SocketAddr = ([127, 0, 0, 1], port).into();
    for _ in 0..100 {
        if TcpStream::connect(addr).await.is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(150)).await;
    }
    panic!(
        "sing-box did not listen on {addr} within 15s; log:\n{}",
        singbox_log(server)
    );
}

// ─── rill under test ─────────────────────────────────────────────────────

/// Build the rill side exactly like `main.rs` does: parse the config, wire
/// the tunnel, and serve a mixed listener on an ephemeral port. The config
/// pins `max-connections: 1` so every logical connection shares one
/// physical mux session.
async fn start_rill(singbox_port: u16, protocol: &str, padding: bool) -> SocketAddr {
    let yaml = format!(
        r#"
mixed-port: 7890          # inert: the test binds its own ephemeral listener
mode: rule
log-level: warning
ipv6: false
allow-lan: false

proxies:
  - name: singbox-smux
    type: vless
    server: 127.0.0.1
    port: {singbox_port}
    uuid: {TEST_UUID}
    smux:
      enabled: true
      protocol: {protocol}
      padding: {padding}
      max-connections: 1

rules:
  - MATCH,singbox-smux
"#
    );
    let config = rill_config::load_config_from_str(&yaml)
        .await
        .expect("parse smux e2e config");
    let tunnel = rill_tunnel::Tunnel::new(std::sync::Arc::clone(&config.dns.resolver));
    tunnel.set_mode(config.general.mode);
    tunnel.update_routing(config.proxies, config.rules, config.dialer_registry);
    tunnel.spawn_background_tasks();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let mixed = rill_listener::MixedListener::new(tunnel, addr, "smux-e2e".to_string());
    tokio::spawn(async move {
        let _ = mixed.run_on(listener).await;
    });
    addr
}

/// SOCKS5 CONNECT through the mixed listener; returns the relayed stream.
async fn socks5_connect(proxy: SocketAddr, target: SocketAddr) -> TcpStream {
    let mut stream = TcpStream::connect(proxy).await.expect("connect mixed port");
    stream.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut method = [0u8; 2];
    stream.read_exact(&mut method).await.unwrap();
    assert_eq!(&method, &[0x05, 0x00], "unexpected SOCKS5 greeting reply");
    let mut request = vec![0x05, 0x01, 0x00, 0x01];
    let IpAddr::V4(ip) = target.ip() else {
        panic!("echo target must be IPv4");
    };
    request.extend_from_slice(&ip.octets());
    request.extend_from_slice(&target.port().to_be_bytes());
    stream.write_all(&request).await.unwrap();
    let mut reply = [0u8; 10];
    stream.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[1], 0x00, "SOCKS5 CONNECT rejected: {}", reply[1]);
    stream
}

/// A local TCP echo server accepting any number of connections.
async fn start_echo_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut buf = vec![0u8; 16 * 1024];
                loop {
                    let n = match stream.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => n,
                    };
                    if stream.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    addr
}

/// A deterministic 64 KiB pattern block, repeated to `total` bytes.
fn pattern(total: usize) -> Vec<u8> {
    let block: Vec<u8> = (0..64 * 1024).map(|i| (i * 31 % 251) as u8).collect();
    let mut out = Vec::with_capacity(total);
    while out.len() < total {
        let take = block.len().min(total - out.len());
        out.extend_from_slice(&block[..take]);
    }
    out
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("bind ephemeral port")
        .local_addr()
        .expect("local addr")
        .port()
}

// ─── tests ───────────────────────────────────────────────────────────────

/// A 4 MiB bulk transfer — 32× the per-stream receive share — with a
/// continuously reading consumer must complete byte-identical through the
/// real server. This is the E2E twin of the buffered-burst regression: a
/// healthy reader must never be aborted for going over its share, no
/// matter how fast the real server pushes.
#[tokio::test]
async fn large_transfer_survives_a_real_smux_server() {
    let Some(bin) = require_singbox() else {
        return;
    };
    let dir = tempfile::tempdir().expect("tempdir");
    let singbox_port = free_port();
    let server = start_singbox(&bin, dir.path(), singbox_port, false);
    wait_listening(&server, singbox_port).await;

    let echo_addr = start_echo_server().await;
    let mixed = start_rill(singbox_port, "smux", false).await;

    let total = 32 * MAX_STREAM_BUFFER;
    let payload = pattern(total);
    let conn = socks5_connect(mixed, echo_addr).await;
    let (mut reader_half, mut writer_half) = conn.into_split();

    let reader = tokio::spawn(async move {
        let mut received = vec![0u8; total];
        reader_half
            .read_exact(&mut received)
            .await
            .expect("4 MiB must come back through the real smux server");
        received
    });
    writer_half
        .write_all(&payload)
        .await
        .expect("4 MiB must be accepted by the real smux server");
    let received = tokio::time::timeout(Duration::from_secs(60), reader)
        .await
        .expect("echo roundtrip timed out")
        .expect("reader task panicked");
    assert_eq!(received.len(), total);
    assert_eq!(received, payload, "echo payload corrupted over smux");
}

/// A slow reader sharing the physical session with fast readers: the slow
/// stream is isolated — its relay parks the backlog until the stall
/// watchdog retires the stream and the local connection is torn down —
/// while every fast reader, before and after the isolation, completes fine
/// on the very same session (max-connections: 1 pins them together).
#[tokio::test]
async fn slow_reader_is_isolated_and_fast_readers_survive() {
    let Some(bin) = require_singbox() else {
        return;
    };
    let dir = tempfile::tempdir().expect("tempdir");
    let singbox_port = free_port();
    let server = start_singbox(&bin, dir.path(), singbox_port, false);
    wait_listening(&server, singbox_port).await;

    let echo_addr = start_echo_server().await;
    let mixed = start_rill(singbox_port, "smux", false).await;

    // The slow reader: 2 MiB requested (the writer blocks partway once
    // every buffer in the chain fills — that is the point), and the client
    // side never reads a byte, so the relay parks the backlog on the smux
    // stream until the stall watchdog retires it.
    let mut slow = socks5_connect(mixed, echo_addr).await;
    let slow_writer = tokio::spawn(async move {
        let big = pattern(2 * 1024 * 1024);
        // Errors are expected once the stream is retired and the relay
        // tears the local connection down; the amount pushed before that
        // is what builds the over-share backlog.
        let _ = slow.write_all(&big).await;
    });

    // A fast reader works while the slow one is stalled over its share.
    fast_roundtrip(mixed, echo_addr).await;

    // Let the stall watchdog (500 ms grace) retire the slow stream. The
    // writer task's blocked write errors out once the relay tears the
    // local connection down; the timeout is insurance so a pathological
    // teardown can never hang the whole test binary.
    tokio::time::sleep(ISOLATION_WAIT).await;
    let _ = tokio::time::timeout(Duration::from_secs(10), slow_writer).await;

    // The retire stayed scoped: the session survived, and a fresh stream
    // multiplexed onto the same physical session works end-to-end.
    fast_roundtrip(mixed, echo_addr).await;
}

/// `padding: true` against an inbound that requires it: every sing-mux
/// protocol must carry streams through the padded phase (the first 16
/// frames each way) and past it into the unframed remainder, on one
/// physical session.
async fn padded_session_round_trips(protocol: &str) {
    let Some(bin) = require_singbox() else {
        return;
    };
    let dir = tempfile::tempdir().expect("tempdir");
    let singbox_port = free_port();
    let server = start_singbox(&bin, dir.path(), singbox_port, true);
    wait_listening(&server, singbox_port).await;

    let echo_addr = start_echo_server().await;
    let mixed = start_rill(singbox_port, protocol, true).await;

    // sing-box's log names the rejection ("non-padded connection
    // rejected", or a mux parse error) — surface it on failure.
    for _ in 0..4 {
        if let Err(e) = tokio::spawn(fast_roundtrip(mixed, echo_addr)).await {
            panic!(
                "padded {protocol} roundtrip failed: {e}; sing-box log:\n{}",
                singbox_log(&server)
            );
        }
    }
    let total = 1024 * 1024;
    let payload = pattern(total);
    let conn = socks5_connect(mixed, echo_addr).await;
    let (mut reader_half, mut writer_half) = conn.into_split();
    let reader = tokio::spawn(async move {
        let mut received = vec![0u8; total];
        reader_half
            .read_exact(&mut received)
            .await
            .map(|_| received)
    });
    writer_half
        .write_all(&payload)
        .await
        .expect("bulk write over a padded session");
    let received = tokio::time::timeout(Duration::from_secs(30), reader)
        .await
        .unwrap_or_else(|_| {
            panic!(
                "padded {protocol} bulk echo timed out; sing-box log:\n{}",
                singbox_log(&server)
            )
        })
        .expect("reader task panicked")
        .unwrap_or_else(|e| {
            panic!(
                "padded {protocol} bulk echo failed: {e}; sing-box log:\n{}",
                singbox_log(&server)
            )
        });
    assert_eq!(
        received, payload,
        "echo payload corrupted over padded {protocol}"
    );
    fast_roundtrip(mixed, echo_addr).await;
}

#[tokio::test]
async fn padded_smux_session_interoperates_with_a_real_server() {
    padded_session_round_trips("smux").await;
}

#[tokio::test]
async fn padded_yamux_session_interoperates_with_a_real_server() {
    padded_session_round_trips("yamux").await;
}

#[tokio::test]
async fn padded_h2mux_session_interoperates_with_a_real_server() {
    padded_session_round_trips("h2mux").await;
}

/// One small echo roundtrip through the mixed listener.
async fn fast_roundtrip(mixed: SocketAddr, echo_addr: SocketAddr) {
    let mut conn = socks5_connect(mixed, echo_addr).await;
    let payload = pattern(16 * 1024);
    tokio::time::timeout(Duration::from_secs(20), async {
        conn.write_all(&payload).await.expect("write fast stream");
        let mut received = vec![0u8; payload.len()];
        conn.read_exact(&mut received)
            .await
            .expect("read fast stream");
        assert_eq!(received, payload, "fast stream corrupted");
    })
    .await
    .expect("fast roundtrip must not be blocked by a slow sibling stream");
}

/// A real sing-box Vision user rejects bare CommandUDP (missing flow),
/// and rejects Vision + CommandUDP too. Datagram forwarding must use the
/// Vision-protected CommandMux/XUDP carrier instead.
#[cfg(feature = "vless-vision")]
#[tokio::test]
async fn vision_udp_interoperates_with_a_real_singbox_server() {
    use rill_common::{Metadata, Network};
    use tokio::net::UdpSocket;

    let Some(bin) = require_singbox() else {
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    let cert = dir.path().join("cert.pem");
    let key = dir.path().join("key.pem");
    let generated = Command::new("openssl")
        .args([
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "1",
            "-subj",
            "/CN=localhost",
            "-keyout",
        ])
        .arg(&key)
        .arg("-out")
        .arg(&cert)
        .output()
        .expect("openssl generates the isolated test certificate");
    assert!(
        generated.status.success(),
        "{}",
        String::from_utf8_lossy(&generated.stderr)
    );
    let peer_port = free_port();
    let config = serde_json::json!({
        "log": { "level": "info" },
        "dns": {"servers": [{"type": "hosts", "tag": "hosts", "predefined": {"vision-echo.test": ["127.0.0.1"]}}]},
        "route": {"default_domain_resolver": "hosts"},
        "inbounds": [{
            "type": "vless", "listen": "127.0.0.1", "listen_port": peer_port,
            "users": [{"name": "vision-e2e", "uuid": TEST_UUID, "flow": "xtls-rprx-vision"}],
            "tls": {"enabled": true, "server_name": "localhost", "certificate_path": cert, "key_path": key}
        }],
        "outbounds": [{"type": "direct", "tag": "direct"}]
    });
    let path = dir.path().join("vision-server.json");
    std::fs::write(&path, serde_json::to_vec(&config).unwrap()).unwrap();
    let server = SingBoxServer {
        child: Command::new(bin)
            .arg("run")
            .arg("-c")
            .arg(path)
            .current_dir(dir.path())
            .stdout(Stdio::null())
            .stderr(Stdio::from(
                std::fs::File::create(dir.path().join("singbox.log")).unwrap(),
            ))
            .spawn()
            .unwrap(),
        log_path: dir.path().join("singbox.log"),
    };
    wait_listening(&server, peer_port).await;

    let echo = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let destination = echo.local_addr().unwrap();
    let echo_task = tokio::spawn(async move {
        let mut buffer = [0; 8192];
        while let Ok((length, peer)) = echo.recv_from(&mut buffer).await {
            if echo.send_to(&buffer[..length], peer).await.is_err() {
                break;
            }
        }
    });
    let config = rill_config::load_config_from_str(&format!(
        r#"
ipv6: false
proxies:
  - name: vision
    type: vless
    server: 127.0.0.1
    port: {peer_port}
    uuid: {TEST_UUID}
    flow: xtls-rprx-vision
    tls: true
    servername: localhost
    skip-cert-verify: true
    udp: true
proxy-groups: []
rules: ["MATCH,vision"]
"#
    ))
    .await
    .unwrap();
    let proxy = config.proxies.get("vision").unwrap();
    let metadata = Metadata {
        network: Network::Udp,
        dst_ip: Some(destination.ip()),
        dst_port: destination.port(),
        ..Metadata::default()
    };
    let packets = proxy.dial_udp(&metadata).await.unwrap();
    for size in [64, 1400, 4096, 8192] {
        let payload = pattern(size);
        packets.write_packet(&payload, &destination).await.unwrap();
        let mut received = vec![0; size];
        let (length, source) =
            tokio::time::timeout(Duration::from_secs(10), packets.read_packet(&mut received))
                .await
                .unwrap_or_else(|_| {
                    panic!("Vision UDP timed out; peer log:\n{}", singbox_log(&server))
                })
                .unwrap();
        assert_eq!(source, destination);
        assert_eq!(&received[..length], payload);
    }
    // A second association shares the Vision carrier while preserving its own UDP flow.
    let second = proxy.dial_udp(&metadata).await.unwrap();
    second
        .write_packet(b"second-association", &destination)
        .await
        .unwrap();
    let mut received = [0; 64];
    let (length, _) =
        tokio::time::timeout(Duration::from_secs(10), second.read_packet(&mut received))
            .await
            .unwrap()
            .unwrap();
    assert_eq!(&received[..length], b"second-association");
    // SOCKS/fake-IP flows may keep only a domain until the remote resolves it.
    let domain = proxy
        .dial_udp(&Metadata {
            network: Network::Udp,
            host: "vision-echo.test".into(),
            dst_port: destination.port(),
            ..Metadata::default()
        })
        .await
        .unwrap();
    domain
        .write_packet(
            b"domain-association",
            &SocketAddr::from(([0, 0, 0, 0], destination.port())),
        )
        .await
        .unwrap();
    let (length, source) =
        tokio::time::timeout(Duration::from_secs(10), domain.read_packet(&mut received))
            .await
            .unwrap_or_else(|_| panic!("domain UDP timed out; peer log:\n{}", singbox_log(&server)))
            .unwrap_or_else(|e| {
                panic!(
                    "domain UDP failed: {e}; peer log:\n{}",
                    singbox_log(&server)
                )
            });
    // The packet API uses an unspecified source when the peer echoes a
    // domain address rather than an IP; the inbound retains the original target.
    assert!(source.ip().is_unspecified() || source == destination);
    assert_eq!(&received[..length], b"domain-association");
    proxy.reset_sessions();
    let after_reset = proxy.dial_udp(&metadata).await.unwrap();
    after_reset
        .write_packet(b"after-reset", &destination)
        .await
        .unwrap();
    let (length, _) = tokio::time::timeout(
        Duration::from_secs(10),
        after_reset.read_packet(&mut received),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(&received[..length], b"after-reset");
    assert!(!singbox_log(&server).contains("flow mismatch"));
    echo_task.abort();
}
