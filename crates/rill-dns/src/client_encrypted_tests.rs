use super::*;
use rill_common::{
    AdapterType, DelayHistory, Metadata, Proxy, ProxyAdapter, ProxyConn, ProxyHealth,
    ProxyPacketConn, Result as ProxyResult,
};
use rill_transport::tls::TlsConfig;
use std::sync::Mutex;
use tokio::net::TcpListener;

#[derive(Default)]
struct RecordingProxy {
    seen: Mutex<Vec<Metadata>>,
    health: ProxyHealth,
}

#[async_trait::async_trait]
impl ProxyAdapter for RecordingProxy {
    fn name(&self) -> &str {
        "dns-proxy"
    }
    fn adapter_type(&self) -> AdapterType {
        AdapterType::Direct
    }
    fn addr(&self) -> &str {
        ""
    }
    fn support_udp(&self) -> bool {
        false
    }
    async fn dial_tcp(&self, metadata: &Metadata) -> ProxyResult<Box<dyn ProxyConn>> {
        self.seen.lock().unwrap().push(metadata.clone());
        Ok(Box::new(
            TcpStream::connect(SocketAddr::new(metadata.dst_ip.unwrap(), metadata.dst_port))
                .await?,
        ))
    }
    async fn dial_udp(&self, _: &Metadata) -> ProxyResult<Box<dyn ProxyPacketConn>> {
        unreachable!("encrypted DNS uses TCP")
    }
    fn health(&self) -> &ProxyHealth {
        &self.health
    }
}
impl Proxy for RecordingProxy {
    fn alive(&self) -> bool {
        true
    }
    fn alive_for_url(&self, _: &str) -> bool {
        true
    }
    fn last_delay(&self) -> u16 {
        0
    }
    fn last_delay_for_url(&self, _: &str) -> u16 {
        0
    }
    fn delay_history(&self) -> Vec<DelayHistory> {
        Vec::new()
    }
}

async fn tls_server(http: bool) -> (SocketAddr, Vec<u8>) {
    let certified = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let certificate = certified.cert.der().clone();
    let key = rustls::pki_types::PrivatePkcs8KeyDer::from(certified.key_pair.serialize_der());
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(vec![certificate.clone()], key.into())
    .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let Ok(mut socket) = acceptor.accept(socket).await else {
            return;
        };
        if http {
            let mut header = Vec::new();
            while !header.ends_with(b"\r\n\r\n") {
                header.push(socket.read_u8().await.unwrap());
            }
            let header = String::from_utf8(header).unwrap();
            assert!(header.starts_with("POST /dns-query HTTP/1.1\r\n"));
            assert!(header.contains(&format!("Host: origin.test:{}\r\n", address.port())));
            let length: usize = header
                .lines()
                .find_map(|line| line.strip_prefix("Content-Length: "))
                .unwrap()
                .parse()
                .unwrap();
            let mut query = vec![0; length];
            socket.read_exact(&mut query).await.unwrap();
            assert_eq!(query, b"dns-query");
            socket.write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\ndns\r\n7\r\n-answer\r\n0\r\n\r\n").await.unwrap();
        } else {
            assert_eq!(read_lp(&mut socket).await.unwrap(), b"dns-query");
            write_lp(&mut socket, b"dns-answer").await.unwrap();
        }
        socket.shutdown().await.unwrap();
    });
    (address, certificate.to_vec())
}

#[tokio::test]
async fn doh_and_dot_use_proxy_with_verified_tls_and_separate_origin_name() {
    for http in [false, true] {
        let (address, root) = tls_server(http).await;
        let proxy = Arc::new(RecordingProxy::default());
        let routed: DnsProxy = Arc::clone(&proxy) as Arc<dyn Proxy>;
        let tls = TlsLayer::new(&TlsConfig {
            additional_roots: vec![root],
            ..TlsConfig::new("localhost")
        })
        .unwrap();
        let reply = if http {
            doh_exchange_with_tls(
                address,
                "origin.test",
                "/dns-query",
                b"dns-query",
                Some(&routed),
                tls,
            )
            .await
        } else {
            dot_exchange_with_tls(address, "origin.test", b"dns-query", Some(&routed), tls).await
        }
        .unwrap();
        assert_eq!(reply, b"dns-answer");
        let seen = proxy.seen.lock().unwrap();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].host, "origin.test");
        assert!(seen[0].internal);
        assert_eq!(seen[0].dst_ip, Some(address.ip()));
    }
}

#[tokio::test]
async fn encrypted_dns_through_proxy_still_rejects_wrong_certificate_name() {
    let (address, root) = tls_server(false).await;
    let proxy: DnsProxy = Arc::new(RecordingProxy::default());
    let tls = TlsLayer::new(&TlsConfig {
        additional_roots: vec![root],
        ..TlsConfig::new("wrong.invalid")
    })
    .unwrap();
    let result =
        dot_exchange_with_tls(address, "origin.test", b"dns-query", Some(&proxy), tls).await;
    assert!(
        matches!(result, Err(ClientError::Tls(_))),
        "routing must preserve certificate verification"
    );
}

#[test]
fn doh_chunked_body_rejects_truncation_and_oversize() {
    let header = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked";
    for body in [b"3\r\nab".as_slice(), b"0\r\n", b"ffffffffff\r\n"] {
        assert!(decode_doh_body(header, body).is_err());
    }
    assert!(decode_doh_body("HTTP/1.1 200 OK\r\nContent-Length: 4", b"abc").is_err());
    assert_eq!(
        decode_doh_body(header, b"3;ext=1\r\nabc\r\n0\r\n\r\n").unwrap(),
        b"abc"
    );
}
