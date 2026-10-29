#![cfg(feature = "xpro")]
//! Independent rustls/H2 peer verifies the native adapter and RFC 9266 binding.
use async_trait::async_trait;
use rill_common::{Metadata, ProxyAdapter};
use rill_proxy::{
    dialer::{DirectDialer, TcpDialer},
    xpro::{Config, DeviceKey, Profile, XproAdapter},
};
use std::{
    io,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use xpro_client::{
    xpro_protocol::{now, session, AuthOpen, Destination, Frame, Kind, Proof, AUTH_HEADER},
    xpro_transport::H2Io,
};
struct CountDialer(Arc<AtomicUsize>);
#[async_trait]
impl TcpDialer for CountDialer {
    async fn dial(
        &self,
        host: &str,
        port: u16,
        internal: bool,
    ) -> io::Result<Box<dyn rill_transport::Stream>> {
        self.0.fetch_add(1, Ordering::SeqCst);
        DirectDialer.dial(host, port, internal).await
    }
}
#[tokio::test]
async fn native_h2_adapter_uses_injected_dialer_and_preserves_domain_and_fin() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let ca = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(ca.path(), cert.cert.pem()).unwrap();
        let mut tls =
            rustls::ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                .with_no_client_auth()
                .with_single_cert(
                    vec![cert.cert.der().clone()],
                    rustls::pki_types::PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der())
                        .into(),
                )
                .unwrap();
        tls.alpn_protocols = vec![b"h2".to_vec()];
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls));
        let task = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let tls = acceptor.accept(socket).await.unwrap();
            let binding = tls
                .get_ref()
                .1
                .export_keying_material([0; 32], b"EXPORTER-Channel-Binding", Some(&[]))
                .unwrap();
            let mut connection = h2::server::handshake(tls).await.unwrap();
            let mut tasks = tokio::task::JoinSet::new();
            while let Some(request) = connection.accept().await {
                let (request, mut respond) = request.unwrap();
                let proof =
                    Proof::from_header(request.headers()[AUTH_HEADER].to_str().unwrap()).unwrap();
                proof
                    .verify(
                        &DeviceKey::new([2; 32]),
                        &proof
                            .admission_input(
                                &format!("localhost:{port}"),
                                "POST",
                                "/api/stream",
                                Some(&binding),
                            )
                            .unwrap(),
                        now(),
                    )
                    .unwrap();
                let send = respond
                    .send_response(http::Response::new(()), false)
                    .unwrap();
                tasks.spawn(async move {
                    let mut io = H2Io::new(request.into_body(), send);
                    let frame = Frame::read(&mut io).await.unwrap();
                    assert_eq!(frame.kind, Kind::AuthOpen);
                    let open = AuthOpen::decode(&frame.payload).unwrap();
                    assert_eq!(
                        open.destination,
                        Destination::new("example.com", 443).unwrap()
                    );
                    open.proof
                        .verify(
                            &DeviceKey::new([2; 32]),
                            &open
                                .proof
                                .open_input(&binding, &open.destination.encode().unwrap()),
                            now(),
                        )
                        .unwrap();
                    Frame::new(Kind::Connected, vec![])
                        .write(&mut io)
                        .await
                        .unwrap();
                    let mut stream = session(io);
                    stream.write_all(b"hello").await.unwrap();
                    let mut input = Vec::new();
                    stream.read_to_end(&mut input).await.unwrap();
                    assert_eq!(input, b"payload");
                    stream.write_all(&input).await.unwrap();
                    stream.shutdown().await.unwrap();
                    stream.finish().await.unwrap();
                });
            }
            while let Some(result) = tasks.join_next().await {
                result.unwrap();
            }
        });
        let count = Arc::new(AtomicUsize::new(0));
        let adapter = XproAdapter::new(
            "fixture",
            Config {
                heartbeat: Default::default(),
                server: "127.0.0.1".into(),
                port,
                servername: "localhost".into(),
                path: "/api/stream".into(),
                profile: Profile::H2,
                device_id: [1; 16],
                key: DeviceKey::new([2; 32]),
                ca_file: Some(ca.path().into()),
                inner_tls: None,
            },
            Arc::new(CountDialer(Arc::clone(&count))),
        )
        .unwrap();
        let metadata = Metadata {
            host: "example.com".into(),
            dst_ip: Some("198.18.0.1".parse().unwrap()),
            dst_port: 443,
            ..Default::default()
        };
        let mut stream = adapter.dial_tcp(&metadata).await.unwrap();
        let mut hello = [0; 5];
        stream.read_exact(&mut hello).await.unwrap();
        assert_eq!(&hello, b"hello");
        stream.write_all(b"payload").await.unwrap();
        stream.shutdown().await.unwrap();
        let mut output = Vec::new();
        stream.read_to_end(&mut output).await.unwrap();
        assert_eq!(output, b"payload");
        assert_eq!(count.load(Ordering::SeqCst), 1);
        assert!(!adapter.support_udp());
        assert!(adapter.dial_udp(&metadata).await.is_err());
        drop(stream);
        adapter.reset_sessions();
        drop(adapter);
        task.await.unwrap();
    })
    .await
    .unwrap();
}
