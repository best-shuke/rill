//! DNS over HTTPS on one kept HTTP/2 connection per upstream.
//!
//! The HTTP/1.1 client this replaces opened a TCP + TLS connection (and, for
//! a `#PROXY` upstream, a proxy dial) for every query and closed it after the
//! answer, so each lookup paid two to four round-trips before the query was
//! even sent — through a distant proxy, most of a second. mihomo keeps one
//! HTTP/2 connection per DoH upstream; so does this: every query of a
//! [`DohSession`] is a stream on the same connection, a burst of lookups
//! shares it, and only the first query after it closes pays a handshake.
//!
//! Lifetime follows mihomo's transport: a connection silent for
//! [`PING_AFTER`] is pinged and dropped when the ping goes unanswered for
//! [`PING_TIMEOUT`]; one unused for [`IDLE_TIMEOUT`] is closed. A request
//! still outstanding after [`STALL_AFTER`] when its caller gives up marks the
//! connection dead too, so a connection a NAT silently dropped costs one
//! timed-out query, not every query until the next ping. A query that fails
//! because its reused connection broke is retried once on a fresh one.
//! [`crate::client::reset_pooled_connections`] (a network change, #695)
//! retires the connection at once.
//!
//! A server that does not negotiate `h2` over ALPN is remembered and served
//! over HTTP/1.1, one connection per query, as before.

use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use bytes::Bytes;
use h2::client::SendRequest;
use parking_lot::Mutex;
use rill_common::atomic::{AtomicU, Uint};
use rill_transport::h2_common;
use rill_transport::Stream;
use tokio::sync::Mutex as AsyncMutex;
use tokio::task::AbortHandle;
use tracing::debug;

use crate::client::{connection_generation, ClientError};

/// Close a connection no query has used for this long (mihomo
/// `transportDefaultIdleConnTimeout`).
const IDLE_TIMEOUT: Duration = Duration::from_secs(300);
/// Ping a connection that has been silent for this long (mihomo's HTTP/2
/// `SendPingTimeout`).
const PING_AFTER: Duration = Duration::from_secs(30);
/// How long a ping may go unanswered before the connection is presumed dead.
const PING_TIMEOUT: Duration = Duration::from_secs(15);
/// A request abandoned by its caller after waiting this long is taken as a
/// sign the connection is dead. Shorter waits are a nameserver race the
/// query lost (the resolver drops the slower upstreams' requests), which
/// says nothing about the connection.
const STALL_AFTER: Duration = Duration::from_secs(3);
/// Largest DNS message a response body may carry.
const MAX_DNS_MESSAGE: usize = 65535;

/// The kept connection of one DoH upstream (see the module docs).
pub(crate) struct DohSession {
    /// The live connection. The lock is held while a new one is opened, so
    /// a burst of queries that finds none waits for one handshake instead
    /// of each opening its own.
    slot: AsyncMutex<Option<Conn>>,
    /// Bumped by [`Self::reset`]; a connection opened under an older value
    /// is never used again.
    generation: AtomicU,
    /// The server did not negotiate `h2`: use HTTP/1.1, a connection per query.
    h1_only: AtomicBool,
}

/// A connection and the generations it was opened under.
#[derive(Clone)]
struct Conn {
    send: SendRequest<Bytes>,
    generation: (Uint, Uint),
    state: Arc<ConnState>,
}

struct ConnState {
    closed: AtomicBool,
    last_used: Mutex<Instant>,
    driver: OnceLock<AbortHandle>,
}

impl ConnState {
    fn kill(&self) {
        self.closed.store(true, Ordering::Release);
        if let Some(driver) = self.driver.get() {
            // Dropping the connection future closes the socket, failing any
            // request still waiting on it.
            driver.abort();
        }
    }

    fn idle_for(&self) -> Duration {
        self.last_used.lock().elapsed()
    }

    fn touch(&self) {
        *self.last_used.lock() = Instant::now();
    }
}

/// How a request on a connection failed.
enum Failure {
    /// The connection broke: worth one retry on a fresh connection.
    Connection(ClientError),
    /// The server answered, unusably: the query fails.
    Answer(ClientError),
}

impl Failure {
    fn into_error(self) -> ClientError {
        match self {
            Self::Connection(e) | Self::Answer(e) => e,
        }
    }
}

impl DohSession {
    pub(crate) fn new() -> Self {
        Self {
            slot: AsyncMutex::new(None),
            generation: AtomicU::new(0),
            h1_only: AtomicBool::new(false),
        }
    }

    fn current_generation(&self) -> (Uint, Uint) {
        (
            connection_generation(),
            self.generation.load(Ordering::Acquire),
        )
    }

    /// Retire the kept connection now. Returns the connections closed.
    pub(crate) fn reset(&self) -> usize {
        self.generation.fetch_add(1, Ordering::AcqRel);
        self.slot
            .try_lock()
            .map_or(0, |mut slot| match slot.take() {
                Some(conn) => {
                    conn.state.kill();
                    1
                }
                None => 0,
            })
    }

    /// The kept connection if it is still usable; an unusable one is closed
    /// and dropped.
    fn usable(&self, slot: &mut Option<Conn>) -> Option<Conn> {
        let conn = slot.as_ref()?;
        if !conn.state.closed.load(Ordering::Acquire)
            && conn.generation == self.current_generation()
            && conn.state.idle_for() < IDLE_TIMEOUT
        {
            return Some(conn.clone());
        }
        if let Some(conn) = slot.take() {
            conn.state.kill();
        }
        None
    }

    /// Send one query. `connect` opens the TLS stream (offering `h2` and
    /// `http/1.1` over ALPN) and reports whether `h2` was negotiated; `h1`
    /// runs the query over HTTP/1.1 on such a stream.
    pub(crate) async fn exchange<C, CFut, H, HFut>(
        &self,
        connect: C,
        h1: H,
        uri: &str,
        wire: &[u8],
    ) -> Result<Vec<u8>, ClientError>
    where
        C: FnOnce() -> CFut,
        CFut: Future<Output = Result<(Box<dyn Stream>, bool), ClientError>>,
        H: FnOnce(Box<dyn Stream>) -> HFut,
        HFut: Future<Output = Result<Vec<u8>, ClientError>>,
    {
        if self.h1_only.load(Ordering::Relaxed) {
            let (stream, _) = connect().await?;
            return h1(stream).await;
        }

        // Reuse the kept connection when there is one.
        let reused = {
            let mut slot = self.slot.lock().await;
            self.usable(&mut slot)
        };
        if let Some(conn) = reused {
            match request(&conn, uri, wire).await {
                Ok(answer) => return Ok(answer),
                Err(Failure::Answer(e)) => return Err(e),
                Err(Failure::Connection(e)) => {
                    debug!("doh: kept connection failed ({e}); reconnecting");
                    conn.state.kill();
                }
            }
        }

        let mut slot = self.slot.lock().await;
        // Another query may have opened a connection while this one waited
        // for the lock.
        if let Some(conn) = self.usable(&mut slot) {
            drop(slot);
            return request(&conn, uri, wire).await.map_err(Failure::into_error);
        }
        let generation = self.current_generation();
        let (stream, h2) = connect().await?;
        if !h2 {
            debug!("doh: upstream did not negotiate h2; using HTTP/1.1");
            self.h1_only.store(true, Ordering::Relaxed);
            drop(slot);
            return h1(stream).await;
        }
        let conn = open(stream, generation).await?;
        *slot = Some(conn.clone());
        drop(slot);
        request(&conn, uri, wire).await.map_err(Failure::into_error)
    }
}

impl Drop for DohSession {
    fn drop(&mut self) {
        if let Some(conn) = self.slot.get_mut().take() {
            conn.state.kill();
        }
    }
}

/// HTTP/2 handshake over `stream`; spawns the connection driver and its
/// keepalive. Goes through `rill_transport::h2_common`'s non-generic
/// wrappers so the h2 machinery is not linked a second time.
async fn open(stream: Box<dyn Stream>, generation: (Uint, Uint)) -> Result<Conn, ClientError> {
    let (send, mut connection) = h2_common::client_handshake(stream)
        .await
        .map_err(connection_error)?;
    let ping_pong = connection.ping_pong();
    let state = Arc::new(ConnState {
        closed: AtomicBool::new(false),
        last_used: Mutex::new(Instant::now()),
        driver: OnceLock::new(),
    });
    let driver_state = Arc::clone(&state);
    let driver = tokio::spawn(async move {
        if let Err(e) = connection.await {
            debug!("doh: connection closed: {e}");
        }
        driver_state.closed.store(true, Ordering::Release);
    });
    let _ = state.driver.set(driver.abort_handle());
    if let Some(ping_pong) = ping_pong {
        tokio::spawn(keepalive(ping_pong, Arc::clone(&state)));
    }
    Ok(Conn {
        send,
        generation,
        state,
    })
}

/// Ping a silent connection, close it when the ping goes unanswered or it
/// has been unused for [`IDLE_TIMEOUT`].
async fn keepalive(mut ping_pong: h2::PingPong, state: Arc<ConnState>) {
    loop {
        tokio::time::sleep(PING_AFTER).await;
        if state.closed.load(Ordering::Acquire) {
            return;
        }
        let idle = state.idle_for();
        if idle >= IDLE_TIMEOUT {
            debug!("doh: closing a connection idle for {idle:?}");
            state.kill();
            return;
        }
        if idle < PING_AFTER {
            continue;
        }
        match tokio::time::timeout(PING_TIMEOUT, ping_pong.ping(h2::Ping::opaque())).await {
            Ok(Ok(_)) => {}
            _ => {
                debug!("doh: ping unanswered; closing the connection");
                state.kill();
                return;
            }
        }
    }
}

/// Kills the connection when a request is abandoned after [`STALL_AFTER`].
struct StallGuard<'a> {
    state: &'a ConnState,
    started: Instant,
    done: bool,
}

impl Drop for StallGuard<'_> {
    fn drop(&mut self) {
        if !self.done && self.started.elapsed() >= STALL_AFTER {
            debug!(
                "doh: request abandoned after {:?}; closing the connection",
                self.started.elapsed()
            );
            self.state.kill();
        }
    }
}

/// One `POST` of `wire` on `conn`, returning the response body.
async fn request(conn: &Conn, uri: &str, wire: &[u8]) -> Result<Vec<u8>, Failure> {
    let mut guard = StallGuard {
        state: &conn.state,
        started: Instant::now(),
        done: false,
    };
    let result = send(conn, uri, wire).await;
    guard.done = true;
    if result.is_ok() {
        conn.state.touch();
    }
    result
}

async fn send(conn: &Conn, uri: &str, wire: &[u8]) -> Result<Vec<u8>, Failure> {
    let request = http::Request::post(uri)
        .header(http::header::ACCEPT, "application/dns-message")
        .header(http::header::CONTENT_TYPE, "application/dns-message")
        .header(http::header::CONTENT_LENGTH, wire.len())
        .header(http::header::USER_AGENT, "rill")
        .body(())
        .map_err(|_| Failure::Answer(ClientError::Protocol("doh: invalid request URI")))?;
    let response = h2_common::send_with_body(&conn.send, request, Bytes::copy_from_slice(wire))
        .await
        .map_err(|e| {
            if retryable(&e) {
                Failure::Connection(connection_error(e))
            } else {
                Failure::Answer(connection_error(e))
            }
        })?;
    if response.status() != http::StatusCode::OK {
        return Err(Failure::Answer(ClientError::Protocol(
            "doh: non-200 status",
        )));
    }
    let mut body = response.into_body();
    let mut answer = Vec::new();
    while let Some(chunk) = body.data().await {
        let chunk = chunk.map_err(|e| Failure::Answer(connection_error(e)))?;
        let _ = body.flow_control().release_capacity(chunk.len());
        if answer.len() + chunk.len() > MAX_DNS_MESSAGE {
            return Err(Failure::Answer(ClientError::Protocol(
                "doh: DNS body too large",
            )));
        }
        answer.extend_from_slice(&chunk);
    }
    Ok(answer)
}

/// Whether an error means the connection, not this request, failed: an I/O
/// error (including the connection having closed under the request), a
/// GOAWAY, or a stream the server refused unprocessed.
fn retryable(e: &h2::Error) -> bool {
    e.is_io() || e.is_go_away() || e.reason() == Some(h2::Reason::REFUSED_STREAM)
}

/// Keep an I/O error's errno (#682); describe anything else.
fn connection_error(e: h2::Error) -> ClientError {
    if !e.is_io() {
        return ClientError::Io(std::io::Error::other(format!("doh: h2: {e}")));
    }
    let text = e.to_string();
    ClientError::Io(
        e.into_io()
            .unwrap_or_else(|| std::io::Error::other(format!("doh: h2: {text}"))),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;
    use tokio::net::{TcpListener, TcpStream};

    /// Plain-TCP HTTP/2 DoH server echoing each body back with an `-ok`
    /// suffix. Counts accepted connections and requests.
    async fn h2_server() -> (std::net::SocketAddr, Arc<AtomicUsize>, Arc<AtomicUsize>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let connections = Arc::new(AtomicUsize::new(0));
        let requests = Arc::new(AtomicUsize::new(0));
        let (conns, reqs) = (Arc::clone(&connections), Arc::clone(&requests));
        tokio::spawn(async move {
            while let Ok((socket, _)) = listener.accept().await {
                conns.fetch_add(1, Ordering::SeqCst);
                let reqs = Arc::clone(&reqs);
                tokio::spawn(async move {
                    let mut server = h2::server::handshake(socket).await.unwrap();
                    while let Some(Ok((request, mut respond))) = server.accept().await {
                        reqs.fetch_add(1, Ordering::SeqCst);
                        tokio::spawn(async move {
                            assert_eq!(request.method(), http::Method::POST);
                            assert_eq!(request.uri().path(), "/dns-query");
                            let mut body = request.into_body();
                            let mut query = Vec::new();
                            while let Some(chunk) = body.data().await {
                                query.extend_from_slice(&chunk.unwrap());
                            }
                            query.extend_from_slice(b"-ok");
                            let response = http::Response::new(());
                            let mut stream = respond.send_response(response, false).unwrap();
                            stream.send_data(Bytes::from(query), true).unwrap();
                        });
                    }
                });
            }
        });
        (addr, connections, requests)
    }

    async fn query(
        session: &DohSession,
        addr: std::net::SocketAddr,
        wire: &[u8],
    ) -> Result<Vec<u8>, ClientError> {
        session
            .exchange(
                || async move {
                    Ok((
                        Box::new(TcpStream::connect(addr).await?) as Box<dyn Stream>,
                        true,
                    ))
                },
                |_| async { unreachable!("h2 was negotiated") },
                &format!("http://{addr}/dns-query"),
                wire,
            )
            .await
    }

    #[tokio::test]
    async fn queries_share_one_connection() {
        let (addr, connections, requests) = h2_server().await;
        let session = DohSession::new();
        assert_eq!(query(&session, addr, b"a").await.unwrap(), b"a-ok");
        let burst: Vec<_> = (0..8u8)
            .map(|i| {
                let session = &session;
                async move { query(session, addr, &[b'0' + i]).await.unwrap() }
            })
            .collect();
        let answers = futures::future::join_all(burst).await;
        for (i, answer) in answers.iter().enumerate() {
            assert_eq!(answer, &[b'0' + i as u8, b'-', b'o', b'k']);
        }
        assert_eq!(connections.load(Ordering::SeqCst), 1);
        assert_eq!(requests.load(Ordering::SeqCst), 9);
    }

    #[tokio::test]
    async fn a_reset_or_broken_connection_is_replaced() {
        let (addr, connections, _) = h2_server().await;
        let session = DohSession::new();
        query(&session, addr, b"a").await.unwrap();
        assert_eq!(session.reset(), 1);
        query(&session, addr, b"b").await.unwrap();
        assert_eq!(connections.load(Ordering::SeqCst), 2);

        // A connection that died under the session is replaced, and the
        // query that found it dead is retried transparently.
        let driver = session
            .slot
            .lock()
            .await
            .as_ref()
            .unwrap()
            .state
            .driver
            .get()
            .unwrap()
            .clone();
        driver.abort();
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(query(&session, addr, b"c").await.unwrap(), b"c-ok");
        assert_eq!(connections.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn an_h1_upstream_is_remembered() {
        let session = DohSession::new();
        let connects = AtomicUsize::new(0);
        for _ in 0..2 {
            let (client, _server) = tokio::io::duplex(64);
            let answer = session
                .exchange(
                    || async {
                        connects.fetch_add(1, Ordering::SeqCst);
                        Ok((Box::new(client) as Box<dyn Stream>, false))
                    },
                    |_| async { Ok(b"h1".to_vec()) },
                    "https://doh.test/dns-query",
                    b"q",
                )
                .await
                .unwrap();
            assert_eq!(answer, b"h1");
        }
        assert!(session.h1_only.load(Ordering::Relaxed));
        assert_eq!(connects.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn a_request_abandoned_after_the_stall_window_kills_the_connection() {
        let state = ConnState {
            closed: AtomicBool::new(false),
            last_used: Mutex::new(Instant::now()),
            driver: OnceLock::new(),
        };
        // Lost a nameserver race quickly: the connection stays.
        drop(StallGuard {
            state: &state,
            started: Instant::now(),
            done: false,
        });
        assert!(!state.closed.load(Ordering::Acquire));
        // Gave up on a request that hung past the window: it goes.
        drop(StallGuard {
            state: &state,
            started: Instant::now() - STALL_AFTER,
            done: false,
        });
        assert!(state.closed.load(Ordering::Acquire));
    }
}
