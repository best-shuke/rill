//! Global ceiling on a single outbound dial.
//!
//! Every inbound path (tunnel TCP/UDP, HTTP CONNECT, TProxy, SOCKS5-UDP, TUN,
//! the shadowsocks listener) hands its connection to a proxy adapter and awaits
//! [`ProxyAdapter::dial_tcp`]/[`dial_udp`]. Those futures are unbounded: a
//! server that completes the TCP handshake and then stalls mid-protocol —
//! blackholed VLESS/Trojan, a QUIC path that never validates, a relay chain
//! stuck on hop 2 — parks the caller forever, pinning the inbound socket, its
//! NAT/session slot, and (for group members) the health state that would
//! otherwise mark the node dead.
//!
//! mihomo bounds the same calls with `C.DefaultTCPTimeout` /
//! `C.DefaultUDPTimeout` (5 s each) around `proxy.DialContext` and
//! `proxy.ListenPacketContext` in `tunnel.handleTCPConn`. [`DIAL_TIMEOUT`] is
//! the rill equivalent.
//!
//! [`ProxyAdapter::dial_tcp`]: crate::adapter::ProxyAdapter::dial_tcp
//! [`dial_udp`]: crate::adapter::ProxyAdapter::dial_udp

use std::future::Future;
use std::io;
use std::time::Duration;
use tokio::time::Instant;

use crate::error::{Result, RillError};

/// Ceiling on one outbound dial: the adapter's own name resolution, TCP
/// connect, and whatever handshake its protocol performs before it yields a
/// stream or packet conn. Matches mihomo's `C.DefaultTCPTimeout`.
///
/// This bounds a *dial*, not a connection — an established relay runs for as
/// long as both peers keep it open.
pub const DIAL_TIMEOUT: Duration = Duration::from_secs(5);

tokio::task_local! {
    static DIAL_DEADLINE: Instant;
}

/// Deadline of the outbound dial currently being polled on this task.
///
/// Proxy groups capture it before awaiting a member so their cancellation
/// guards can distinguish deadline expiry from an early caller cancellation.
/// The scope follows the dial future; newly spawned tasks do not inherit it.
pub fn dial_deadline() -> Option<Instant> {
    DIAL_DEADLINE.try_with(|deadline| *deadline).ok()
}

/// Run a `dial_tcp`/`dial_udp` future under [`DIAL_TIMEOUT`].
///
/// `via` names the proxy for the error message; it is only formatted on the
/// timeout path.
///
/// Nested calls reuse the original deadline, including time spent on earlier
/// relay hops. Expiry surfaces as [`io::ErrorKind::TimedOut`]. Since timeout
/// drops the pending future, group failure tracking must also handle expiry
/// in a cancellation guard; an ordinary `Err` arm alone cannot observe it.
pub async fn with_dial_timeout<F, T>(via: &str, fut: F) -> Result<T>
where
    F: Future<Output = Result<T>>,
{
    let deadline = dial_deadline().unwrap_or_else(|| Instant::now() + DIAL_TIMEOUT);
    DIAL_DEADLINE
        .scope(deadline, async {
            match tokio::time::timeout_at(deadline, fut).await {
                Ok(result) => result,
                Err(_) => Err(RillError::Io(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!(
                        "dial via {via} exceeded the {}s deadline",
                        DIAL_TIMEOUT.as_secs()
                    ),
                ))),
            }
        })
        .await
}

/// Most attempts [`dial_with_retry`] makes for one connection.
pub const DIAL_ATTEMPTS: u32 = 3;

/// Pause before the first retry; doubled before each further one.
const RETRY_BACKOFF: Duration = Duration::from_millis(50);

/// Whether a failed dial is worth repeating within the same deadline: the
/// connection to the server was cut while it was being set up — reset,
/// aborted, closed before the handshake finished — which is what a
/// restarting server, a flaky middlebox or a lost NAT mapping produce and
/// what usually succeeds a moment later. A refusal, a DNS failure, a
/// timeout or a protocol error is final; so is local resource exhaustion,
/// which retrying only worsens.
pub fn is_transient_dial_error(err: &RillError) -> bool {
    match err {
        RillError::Io(e) => {
            matches!(
                e.kind(),
                io::ErrorKind::ConnectionReset
                    | io::ErrorKind::ConnectionAborted
                    | io::ErrorKind::UnexpectedEof
                    | io::ErrorKind::BrokenPipe
            ) && !err.is_local_resource_error()
        }
        RillError::RelayHopFailed { source, .. } => is_transient_dial_error(source),
        _ => false,
    }
}

/// [`with_dial_timeout`] that repeats a dial cut by a transient failure
/// ([`is_transient_dial_error`]) — up to [`DIAL_ATTEMPTS`] attempts, 50 ms
/// then 100 ms apart, all under the one deadline. mihomo's `tunnel.retry`
/// does the same with up to ten attempts but retries every error, which
/// holds a refused connection for seconds before the client hears of it;
/// here a final error returns at once.
///
/// Each attempt goes back through `dial`, so a proxy group picks its member
/// afresh (and has recorded the failure) — a retry can land on a healthy one.
pub async fn dial_with_retry<F, Fut, T>(via: &str, mut dial: F) -> Result<T>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T>>,
{
    with_dial_timeout(via, async {
        let mut backoff = RETRY_BACKOFF;
        let mut attempt = 1;
        loop {
            match dial().await {
                Err(err) if attempt < DIAL_ATTEMPTS && is_transient_dial_error(&err) => {
                    // Not worth starting an attempt the deadline would cut.
                    if dial_deadline().is_some_and(|deadline| Instant::now() + backoff >= deadline)
                    {
                        return Err(err);
                    }
                    tracing::debug!("dial via {via} failed ({err}); retrying");
                    crate::conn_note!(Dial, "Failed ({err}); retrying");
                    tokio::time::sleep(backoff).await;
                    backoff *= 2;
                    attempt += 1;
                }
                result => return result,
            }
        }
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::pending;
    use std::sync::atomic::{AtomicU32, Ordering};

    fn reset() -> RillError {
        RillError::Io(io::Error::from(io::ErrorKind::ConnectionReset))
    }

    /// A dial that fails with `errors` in turn, then succeeds.
    async fn flaky(errors: Vec<RillError>) -> (Result<u32>, u32) {
        let calls = AtomicU32::new(0);
        let errors = std::sync::Mutex::new(errors.into_iter());
        let result = dial_with_retry("mock", || {
            let n = calls.fetch_add(1, Ordering::SeqCst) + 1;
            let next = errors.lock().unwrap().next();
            async move {
                match next {
                    Some(err) => Err(err),
                    None => Ok(n),
                }
            }
        })
        .await;
        (result, calls.load(Ordering::SeqCst))
    }

    #[tokio::test(start_paused = true)]
    async fn a_reset_dial_is_retried() {
        let start = Instant::now();
        let (result, calls) = flaky(vec![reset(), reset()]).await;
        assert_eq!(result.unwrap(), 3);
        assert_eq!(calls, 3);
        assert_eq!(start.elapsed(), Duration::from_millis(150));
    }

    #[tokio::test(start_paused = true)]
    async fn retries_stop_after_the_attempt_limit() {
        let (result, calls) = flaky(vec![reset(), reset(), reset(), reset()]).await;
        assert!(is_transient_dial_error(&result.unwrap_err()));
        assert_eq!(calls, DIAL_ATTEMPTS);
    }

    #[tokio::test(start_paused = true)]
    async fn a_final_error_is_not_retried() {
        for err in [
            RillError::Io(io::Error::from(io::ErrorKind::ConnectionRefused)),
            RillError::Io(io::Error::from(io::ErrorKind::TimedOut)),
            RillError::Dns("no address".into()),
            RillError::Proxy("auth failed".into()),
            RillError::Io(io::Error::from_raw_os_error(libc_emfile())),
        ] {
            let (result, calls) = flaky(vec![err]).await;
            assert!(result.is_err());
            assert_eq!(calls, 1);
        }
    }

    #[test]
    fn a_relay_hop_reset_is_transient() {
        let hop = RillError::RelayHopFailed {
            hop: 1,
            source: Box::new(reset()),
        };
        assert!(is_transient_dial_error(&hop));
    }

    #[cfg(unix)]
    fn libc_emfile() -> i32 {
        24
    }

    #[cfg(not(unix))]
    fn libc_emfile() -> i32 {
        10024
    }

    #[tokio::test]
    async fn a_completed_dial_passes_through_untouched() {
        let ok = with_dial_timeout("mock", async { Ok(7u8) }).await.unwrap();
        assert_eq!(ok, 7);
    }

    #[tokio::test]
    async fn a_failed_dial_keeps_its_own_error() {
        let err = with_dial_timeout::<_, ()>("mock", async {
            Err(RillError::Proxy("connection refused".into()))
        })
        .await
        .unwrap_err();
        assert!(matches!(err, RillError::Proxy(_)), "got {err:?}");
    }

    /// A server that accepts and then never speaks must not park the caller.
    #[tokio::test(start_paused = true)]
    async fn a_stalled_dial_expires_as_timed_out() {
        let start = tokio::time::Instant::now();
        let err = with_dial_timeout::<_, ()>("🇭🇰 HK-01", pending())
            .await
            .unwrap_err();

        let RillError::Io(io_err) = err else {
            panic!("expected an io error, got {err:?}");
        };
        assert_eq!(io_err.kind(), io::ErrorKind::TimedOut);
        assert!(io_err.to_string().contains("🇭🇰 HK-01"));
        assert_eq!(start.elapsed(), DIAL_TIMEOUT);
    }

    /// The bound is a ceiling, not a delay: a dial that finishes just under it
    /// is not slowed down, and one that finishes just over it is cut.
    #[tokio::test(start_paused = true)]
    async fn the_bound_is_exclusive_to_slow_dials() {
        let just_in_time = with_dial_timeout("mock", async {
            tokio::time::sleep(DIAL_TIMEOUT - Duration::from_millis(1)).await;
            Ok(())
        })
        .await;
        assert!(just_in_time.is_ok());

        let too_slow = with_dial_timeout("mock", async {
            tokio::time::sleep(DIAL_TIMEOUT + Duration::from_millis(1)).await;
            Ok(())
        })
        .await;
        assert!(too_slow.is_err());
    }
    #[tokio::test(start_paused = true)]
    async fn nested_dials_share_the_original_budget() {
        let start = Instant::now();
        with_dial_timeout::<_, ()>("outer", async {
            tokio::time::sleep(Duration::from_secs(3)).await;
            with_dial_timeout("inner", async {
                assert_eq!(dial_deadline(), Some(start + DIAL_TIMEOUT));
                pending().await
            })
            .await
        })
        .await
        .unwrap_err();
        assert_eq!(start.elapsed(), DIAL_TIMEOUT);
        assert!(
            dial_deadline().is_none(),
            "deadline must not leak out of its scope"
        );
    }
}
