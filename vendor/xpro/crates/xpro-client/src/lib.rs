//! XPro client with an injected TCP dialer and bounded, resettable H2 sessions.
use async_trait::async_trait;
use bytes::Bytes;
use std::{
    io,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio_util::sync::CancellationToken;
pub use xpro_protocol;
use xpro_protocol::{
    denied, invalid, now, session_cancellable, AuthOpen, Destination, DeviceId, DeviceKey, Frame,
    Kind, Profile, Proof, Session, AUTH_HEADER,
};
pub use xpro_transport;
pub use xpro_transport::Heartbeat;
use xpro_transport::{connect, connector, exporter, ws_config, BoxIo, H2Io, WsIo};
#[async_trait]
pub trait Dialer: Send + Sync {
    async fn dial(&self, host: &str, port: u16) -> io::Result<BoxIo>;
}
pub struct SystemDialer;
#[async_trait]
impl Dialer for SystemDialer {
    async fn dial(&self, host: &str, port: u16) -> io::Result<BoxIo> {
        Ok(Box::new(
            tokio::net::TcpStream::connect((host, port)).await?,
        ))
    }
}
#[derive(Clone, Debug)]
pub struct InnerTls {
    pub servername: String,
    pub ca_file: PathBuf,
}
#[derive(Clone, Debug)]
pub struct Config {
    pub server: String,
    pub port: u16,
    pub servername: String,
    pub path: String,
    pub profile: Profile,
    pub device_id: DeviceId,
    pub key: DeviceKey,
    pub ca_file: Option<PathBuf>,
    pub inner_tls: Option<InnerTls>,
    pub heartbeat: Heartbeat,
}
impl Config {
    pub fn validate(&self) -> io::Result<()> {
        self.heartbeat.validate()?;
        if self.port == 0
            || self.server.is_empty()
            || self.servername.is_empty()
            || !self.path.starts_with('/')
            || self.path.starts_with("//")
            || self.path.contains('?')
            || self.path.contains('#')
        {
            return Err(invalid("invalid XPro endpoint"));
        }
        http::uri::Authority::try_from(self.authority())
            .map_err(|_| invalid("invalid authority"))?;
        http::uri::PathAndQuery::try_from(self.path.as_str())
            .map_err(|_| invalid("invalid path"))?;
        if (self.profile == Profile::Wss) != self.inner_tls.is_some() {
            return Err(invalid("WSS requires inner TLS; H2 forbids it"));
        }
        if let Some(inner) = &self.inner_tls {
            if inner.servername != "xpro-origin" {
                return Err(invalid("inner TLS servername must be xpro-origin"));
            }
        }
        Ok(())
    }
    pub fn authority(&self) -> String {
        let name = if self.servername.contains(':') {
            format!("[{}]", self.servername)
        } else {
            self.servername.clone()
        };
        if self.port == 443 {
            name
        } else {
            format!("{name}:{}", self.port)
        }
    }
}
struct H2Session {
    sender: h2::client::SendRequest<Bytes>,
    exporter: [u8; 32],
    slots: Arc<Semaphore>,
    dead: std::sync::atomic::AtomicBool,
}
struct Generation {
    cancel: CancellationToken,
    pool: Vec<Arc<H2Session>>,
}
pub struct Client {
    config: Config,
    dialer: Arc<dyn Dialer>,
    tls: boring::ssl::SslConnector,
    inner: Option<boring::ssl::SslConnector>,
    state: Mutex<Generation>,
    creating: tokio::sync::Mutex<()>,
    slots: Arc<Semaphore>,
}
impl Client {
    pub fn new(config: Config, dialer: Arc<dyn Dialer>) -> io::Result<Self> {
        config.validate()?;
        let alpn = if config.profile == Profile::H2 {
            b"\x02h2".as_slice()
        } else {
            b"\x08http/1.1".as_slice()
        };
        let tls = connector(config.ca_file.as_deref(), alpn)?;
        let inner = config
            .inner_tls
            .as_ref()
            .map(|c| connector(Some(&c.ca_file), b""))
            .transpose()?;
        Ok(Self {
            config,
            dialer,
            tls,
            inner,
            state: Mutex::new(Generation {
                cancel: CancellationToken::new(),
                pool: vec![],
            }),
            creating: tokio::sync::Mutex::new(()),
            slots: Arc::new(Semaphore::new(64)),
        })
    }
    pub fn reset(&self) {
        let mut s = self.state.lock().unwrap();
        s.cancel.cancel();
        *s = Generation {
            cancel: CancellationToken::new(),
            pool: vec![],
        };
    }
    fn admission(&self, exporter: Option<&[u8; 32]>) -> io::Result<Proof> {
        let mut p = Proof::fresh(self.config.profile, self.config.device_id, now())?;
        let input = p.admission_input(
            &self.config.authority(),
            if self.config.profile == Profile::H2 {
                "POST"
            } else {
                "GET"
            },
            &self.config.path,
            exporter,
        )?;
        p.sign(&self.config.key, &input)?;
        Ok(p)
    }
    async fn h2(
        &self,
        cancel: &CancellationToken,
    ) -> io::Result<(BoxIo, [u8; 32], OwnedSemaphorePermit)> {
        // Serialize physical connection creation, never authenticated stream handshakes.
        let lock = self.creating.lock().await;
        let existing = {
            let mut s = self.state.lock().unwrap();
            s.pool
                .retain(|p| !p.dead.load(std::sync::atomic::Ordering::Acquire));
            s.pool
                .iter()
                .filter_map(|p| {
                    Arc::clone(&p.slots)
                        .try_acquire_owned()
                        .ok()
                        .map(|permit| (Arc::clone(p), permit))
                })
                .next()
        };
        let (pooled, permit) = if let Some(pair) = existing {
            pair
        } else {
            if self.state.lock().unwrap().pool.len() >= 2 {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "XPro H2 pool full",
                ));
            }
            let tcp = self
                .dialer
                .dial(&self.config.server, self.config.port)
                .await?;
            let tls = connect(&self.tls, &self.config.servername, tcp).await?;
            if tls.ssl().selected_alpn_protocol() != Some(b"h2") {
                return Err(invalid("H2 ALPN was not negotiated"));
            }
            let binding = exporter(tls.ssl())?;
            let (sender, connection) = h2::client::Builder::new()
                .initial_window_size(256 * 1024)
                .initial_connection_window_size(8 * 1024 * 1024)
                .max_header_list_size(16384)
                .handshake(tls)
                .await
                .map_err(io::Error::other)?;
            let pooled = Arc::new(H2Session {
                sender,
                exporter: binding,
                slots: Arc::new(Semaphore::new(32)),
                dead: std::sync::atomic::AtomicBool::new(false),
            });
            let token = cancel.clone();
            let tracked = Arc::clone(&pooled);
            tokio::spawn(async move {
                tokio::select! {_=token.cancelled()=>{},_=connection=>{}}
                tracked
                    .dead
                    .store(true, std::sync::atomic::Ordering::Release);
            });
            let permit = Arc::clone(&pooled.slots)
                .try_acquire_owned()
                .map_err(io::Error::other)?;
            let mut state = self.state.lock().unwrap();
            // reset() cancels the old token before any old result can re-enter the pool.
            if cancel.is_cancelled() {
                return Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "XPro generation retired",
                ));
            }
            state.pool.push(Arc::clone(&pooled));
            (pooled, permit)
        };
        drop(lock);
        let proof = self.admission(Some(&pooled.exporter))?;
        let mut value = http::HeaderValue::from_str(&proof.header())
            .map_err(|_| invalid("invalid admission header"))?;
        value.set_sensitive(true);
        let request = http::Request::builder()
            .method("POST")
            .uri(format!(
                "https://{}{}",
                self.config.authority(),
                self.config.path
            ))
            .header(AUTH_HEADER, value)
            .body(())
            .map_err(io::Error::other)?;
        let mut sender = pooled.sender.clone().ready().await.map_err(|e| {
            pooled
                .dead
                .store(true, std::sync::atomic::Ordering::Release);
            io::Error::other(e)
        })?;
        let (response, send) = sender
            .send_request(request, false)
            .map_err(io::Error::other)?;
        let response = response.await.map_err(io::Error::other)?;
        if response.status() != http::StatusCode::OK {
            return Err(denied());
        }
        Ok((
            Box::new(H2Io::new(response.into_body(), send)),
            pooled.exporter,
            permit,
        ))
    }
    async fn wss(&self) -> io::Result<(BoxIo, [u8; 32])> {
        use tokio_tungstenite::tungstenite::client::IntoClientRequest;
        let tcp = self
            .dialer
            .dial(&self.config.server, self.config.port)
            .await?;
        let tls = connect(&self.tls, &self.config.servername, tcp).await?;
        let mut request = format!("wss://{}{}", self.config.authority(), self.config.path)
            .into_client_request()
            .map_err(io::Error::other)?;
        let mut value = http::HeaderValue::from_str(&self.admission(None)?.header())
            .map_err(|_| invalid("invalid admission"))?;
        value.set_sensitive(true);
        request.headers_mut().insert(AUTH_HEADER, value);
        let (ws, response) =
            tokio_tungstenite::client_async_with_config(request, tls, Some(ws_config()))
                .await
                .map_err(|_| denied())?;
        if response.headers().contains_key("sec-websocket-extensions") {
            return Err(invalid("WebSocket extensions are disabled"));
        }
        let inner = self
            .config
            .inner_tls
            .as_ref()
            .ok_or_else(|| invalid("inner TLS missing"))?;
        let tls = connect(
            self.inner.as_ref().unwrap(),
            &inner.servername,
            WsIo::with_heartbeat(ws, self.config.heartbeat),
        )
        .await?;
        let binding = exporter(tls.ssl())?;
        Ok((Box::new(tls), binding))
    }
    pub async fn tcp(&self, destination: Destination) -> io::Result<Connection> {
        let permit = Arc::clone(&self.slots)
            .try_acquire_owned()
            .map_err(|_| io::Error::new(io::ErrorKind::WouldBlock, "XPro active stream limit"))?;
        let cancel = self.state.lock().unwrap().cancel.clone();
        let establish = async {
            let (mut wire, binding, h2_permit) = match self.config.profile {
                Profile::H2 => {
                    let (w, b, p) = self.h2(&cancel).await?;
                    (w, b, Some(p))
                }
                Profile::Wss => {
                    let (w, b) = self.wss().await?;
                    (w, b, None)
                }
            };
            let mut proof = Proof::fresh(self.config.profile, self.config.device_id, now())?;
            proof.sign(
                &self.config.key,
                &proof.open_input(&binding, &destination.encode()?),
            )?;
            Frame::new(Kind::AuthOpen, AuthOpen { proof, destination }.encode()?)
                .write(&mut wire)
                .await?;
            let response = Frame::read(&mut wire).await.map_err(|e| {
                if e.kind() == io::ErrorKind::UnexpectedEof {
                    invalid("truncated OPEN response")
                } else {
                    e
                }
            })?;
            match response.kind {
                Kind::Connected => {}
                Kind::Error if response.payload == [0, 1] => {
                    return Err(io::Error::new(
                        io::ErrorKind::ConnectionRefused,
                        "XPro target connection failed",
                    ))
                }
                Kind::Error => return Err(invalid("unknown XPro error code")),
                _ => return Err(invalid("expected CONNECTED")),
            }
            Ok((
                session_cancellable(wire, cancel.clone().cancelled_owned()),
                h2_permit,
            ))
        };
        let (stream, h2_permit) = tokio::select! {_=cancel.cancelled()=>return Err(io::Error::new(io::ErrorKind::Interrupted,"XPro generation retired")),r=tokio::time::timeout(Duration::from_secs(10),establish)=>r.map_err(|_|io::Error::new(io::ErrorKind::TimedOut,"XPro connect timeout"))??};
        Ok(Connection {
            stream,
            permit,
            _h2_permit: h2_permit,
            cancel: Box::pin(cancel.cancelled_owned()),
        })
    }
}
impl Drop for Client {
    fn drop(&mut self) {
        self.reset();
    }
}
use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
pub struct Connection {
    stream: Session,
    permit: OwnedSemaphorePermit,
    _h2_permit: Option<OwnedSemaphorePermit>,
    cancel: Pin<Box<dyn Future<Output = ()> + Send + Sync>>,
}
impl Connection {
    fn check(&mut self, cx: &mut Context<'_>) -> io::Result<()> {
        let _ = &self.permit;
        if self.cancel.as_mut().poll(cx).is_ready() {
            Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "XPro session reset",
            ))
        } else {
            Ok(())
        }
    }
}
impl AsyncRead for Connection {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        b: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.check(cx)?;
        Pin::new(&mut self.stream).poll_read(cx, b)
    }
}
impl AsyncWrite for Connection {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        b: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.check(cx)?;
        Pin::new(&mut self.stream).poll_write(cx, b)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.check(cx)?;
        Pin::new(&mut self.stream).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.check(cx)?;
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}
