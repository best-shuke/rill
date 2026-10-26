//! Racing TCP connection attempts across a host's addresses (RFC 8305).
//!
//! A hostname with several addresses used to be dialed one address at a
//! time: a blackholed first address (a dead CDN edge, an IPv6 route that
//! drops SYNs) burned the whole 5 s [`DIAL_TIMEOUT`] before the next one was
//! ever tried, so the connection failed although a working address was
//! sitting in the list. mihomo races the address families (`dualStackDialContext`,
//! 300 ms fallback) and, with `tcp-concurrent: true`, every address at once.
//!
//! [`race_connect`] follows RFC 8305 instead: families interleaved (§4), one
//! attempt every [`CONNECTION_ATTEMPT_DELAY`] (§5), the next attempt started
//! at once when one fails, first success wins and the losers are dropped
//! (closing their sockets). A healthy first address costs nothing extra; a
//! dead one costs 250 ms instead of the dial. `tcp-concurrent: true`
//! ([`set_tcp_concurrent`]) starts every attempt at once, as in mihomo.
//!
//! [`DIAL_TIMEOUT`]: crate::DIAL_TIMEOUT

use std::future::Future;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use futures_util::stream::{FuturesUnordered, StreamExt};

/// RFC 8305 §5 "Connection Attempt Delay": how long an attempt runs alone
/// before the next address is tried alongside it. 250 ms is the RFC's
/// recommended value.
pub const CONNECTION_ATTEMPT_DELAY: Duration = Duration::from_millis(250);

/// `tcp-concurrent` (mihomo's top-level key): start every attempt at once.
static TCP_CONCURRENT: AtomicBool = AtomicBool::new(false);

/// Apply the top-level `tcp-concurrent` setting.
pub fn set_tcp_concurrent(enabled: bool) {
    TCP_CONCURRENT.store(enabled, Ordering::Relaxed);
}

/// Whether `tcp-concurrent` is on.
pub fn tcp_concurrent() -> bool {
    TCP_CONCURRENT.load(Ordering::Relaxed)
}

/// RFC 8305 §4 ordering: alternate address families, starting with the
/// family of the resolver's first (preferred) address, keeping the
/// resolver's order within each family.
pub fn interleave_families(addrs: &[SocketAddr]) -> Vec<SocketAddr> {
    let Some(first) = addrs.first() else {
        return Vec::new();
    };
    let first_v4 = first.is_ipv4();
    let mut preferred = addrs.iter().filter(|a| a.is_ipv4() == first_v4);
    let mut other = addrs.iter().filter(|a| a.is_ipv4() != first_v4);
    let mut out = Vec::with_capacity(addrs.len());
    loop {
        let a = preferred.next();
        let b = other.next();
        if a.is_none() && b.is_none() {
            return out;
        }
        out.extend(a.copied());
        out.extend(b.copied());
    }
}

/// Connect to the first of `addrs` that answers, racing them per RFC 8305
/// (see the module docs). `connect` runs one attempt; `keep_err` folds a
/// failure into the error reported when every attempt fails (callers pass
/// their `prefer_errno` so an errno-backed failure is kept).
///
/// A single address is awaited directly, with no extra allocation. Returns
/// `Err(None)` only for an empty `addrs`.
pub async fn race_connect<T, E, F, Fut>(
    addrs: &[SocketAddr],
    connect: F,
    keep_err: impl FnMut(Option<E>, E) -> Option<E>,
) -> Result<T, Option<E>>
where
    F: FnMut(SocketAddr) -> Fut,
    Fut: Future<Output = Result<T, E>>,
{
    let delay = if tcp_concurrent() {
        Duration::ZERO
    } else {
        CONNECTION_ATTEMPT_DELAY
    };
    race_with_delay(addrs, delay, connect, keep_err).await
}

async fn race_with_delay<T, E, F, Fut>(
    addrs: &[SocketAddr],
    delay: Duration,
    mut connect: F,
    mut keep_err: impl FnMut(Option<E>, E) -> Option<E>,
) -> Result<T, Option<E>>
where
    F: FnMut(SocketAddr) -> Fut,
    Fut: Future<Output = Result<T, E>>,
{
    match addrs {
        [] => return Err(None),
        [only] => return connect(*only).await.map_err(Some),
        _ => {}
    }
    let mut queue = interleave_families(addrs).into_iter();
    let mut pending = FuturesUnordered::new();
    let mut last_err = None;
    loop {
        if pending.is_empty() || delay.is_zero() {
            // Nothing running (start of the race, or every attempt so far
            // failed), or concurrent mode: start the next attempt now.
            match queue.next() {
                Some(addr) => {
                    pending.push(connect(addr));
                    if delay.is_zero() {
                        continue;
                    }
                }
                None if pending.is_empty() => return Err(last_err),
                None => {}
            }
        }
        let more = !queue.as_slice().is_empty();
        tokio::select! {
            biased;
            Some(result) = pending.next() => match result {
                Ok(conn) => return Ok(conn),
                Err(e) => {
                    last_err = keep_err(last_err, e);
                    // A failed attempt frees its slot at once (§5): the
                    // loop head starts the next one if nothing else runs,
                    // otherwise start it here.
                    if !pending.is_empty() {
                        if let Some(addr) = queue.next() {
                            pending.push(connect(addr));
                        }
                    }
                }
            },
            () = tokio::time::sleep(delay), if more => {
                if let Some(addr) = queue.next() {
                    pending.push(connect(addr));
                }
            }
        }
    }
}

/// Idle time before the first keepalive probe on an outbound TCP socket.
pub const KEEPALIVE_IDLE: Duration = Duration::from_secs(30);
/// Interval between keepalive probes once they start.
pub const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(15);

/// Turn on TCP keepalive for an outbound connection, so a peer that vanished
/// without a FIN or RST (a NAT that dropped the mapping, a proxy server that
/// rebooted, a network the host left) is detected in about two minutes
/// instead of the kernel's two hours. mihomo gets the same from Go's default
/// 15 s dialer keepalive. Best effort: failure is ignored.
pub fn set_keepalive(stream: &tokio::net::TcpStream) {
    #[cfg(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "windows"
    ))]
    {
        let keepalive = socket2::TcpKeepalive::new()
            .with_time(KEEPALIVE_IDLE)
            .with_interval(KEEPALIVE_INTERVAL);
        #[cfg(any(target_os = "linux", target_os = "android", target_os = "macos"))]
        let keepalive = keepalive.with_retries(4);
        let _ = socket2::SockRef::from(stream).set_tcp_keepalive(&keepalive);
    }
    #[cfg(not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "windows"
    )))]
    let _ = stream;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::sync::{Arc, Mutex};
    use tokio::time::Instant;

    fn v4(last: u8) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, last)), 443)
    }

    fn v6(last: u16) -> SocketAddr {
        SocketAddr::new(
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, last)),
            443,
        )
    }

    #[test]
    fn interleave_alternates_from_the_preferred_family() {
        assert_eq!(
            interleave_families(&[v4(1), v4(2), v4(3), v6(1)]),
            vec![v4(1), v6(1), v4(2), v4(3)]
        );
        assert_eq!(
            interleave_families(&[v6(1), v6(2), v4(1), v4(2)]),
            vec![v6(1), v4(1), v6(2), v4(2)]
        );
        assert!(interleave_families(&[]).is_empty());
    }

    /// Per-address scripted outcome: how long the attempt takes and whether
    /// it succeeds. Records the instant each attempt started.
    async fn scripted(
        addrs: &[SocketAddr],
        script: impl Fn(SocketAddr) -> (u64, bool),
    ) -> (
        Result<SocketAddr, Option<&'static str>>,
        Vec<(SocketAddr, u64)>,
    ) {
        scripted_with_delay(addrs, CONNECTION_ATTEMPT_DELAY, script).await
    }

    async fn scripted_with_delay(
        addrs: &[SocketAddr],
        delay: Duration,
        script: impl Fn(SocketAddr) -> (u64, bool),
    ) -> (
        Result<SocketAddr, Option<&'static str>>,
        Vec<(SocketAddr, u64)>,
    ) {
        let start = Instant::now();
        let started = Arc::new(Mutex::new(Vec::new()));
        let log = Arc::clone(&started);
        let result = race_with_delay(
            addrs,
            delay,
            |addr| {
                let (ms, ok) = script(addr);
                log.lock()
                    .unwrap()
                    .push((addr, start.elapsed().as_millis() as u64));
                async move {
                    tokio::time::sleep(Duration::from_millis(ms)).await;
                    if ok {
                        Ok(addr)
                    } else {
                        Err("refused")
                    }
                }
            },
            |_, e| Some(e),
        )
        .await;
        let started = started.lock().unwrap().clone();
        (result, started)
    }

    #[tokio::test(start_paused = true)]
    async fn a_blackholed_first_address_costs_one_attempt_delay() {
        // The first address never answers; the second connects in 20 ms.
        let (result, started) = scripted(&[v4(1), v4(2)], |a| {
            if a == v4(1) {
                (60_000, false)
            } else {
                (20, true)
            }
        })
        .await;
        assert_eq!(result.unwrap(), v4(2));
        assert_eq!(started, vec![(v4(1), 0), (v4(2), 250)]);
    }

    #[tokio::test(start_paused = true)]
    async fn a_refused_attempt_starts_the_next_at_once() {
        let (result, started) = scripted(&[v4(1), v4(2)], |a| {
            if a == v4(1) {
                (10, false)
            } else {
                (10, true)
            }
        })
        .await;
        assert_eq!(result.unwrap(), v4(2));
        assert_eq!(started, vec![(v4(1), 0), (v4(2), 10)]);
    }

    #[tokio::test(start_paused = true)]
    async fn a_fast_first_address_starts_nothing_else() {
        let (result, started) = scripted(&[v4(1), v6(1), v4(2)], |_| (30, true)).await;
        assert_eq!(result.unwrap(), v4(1));
        assert_eq!(started, vec![(v4(1), 0)]);
    }

    #[tokio::test(start_paused = true)]
    async fn every_failure_reports_the_kept_error() {
        let (result, started) = scripted(&[v4(1), v6(1)], |_| (5, false)).await;
        assert_eq!(result.unwrap_err(), Some("refused"));
        assert_eq!(started.len(), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn tcp_concurrent_starts_every_attempt_at_once() {
        // `tcp-concurrent: true` maps to a zero attempt delay.
        let (result, started) = scripted_with_delay(&[v4(1), v4(2), v4(3)], Duration::ZERO, |a| {
            if a == v4(3) {
                (5, true)
            } else {
                (50, false)
            }
        })
        .await;
        assert_eq!(result.unwrap(), v4(3));
        assert_eq!(started, vec![(v4(1), 0), (v4(2), 0), (v4(3), 0)]);
    }

    #[tokio::test]
    async fn empty_and_single_address_inputs() {
        let empty: Result<(), Option<&str>> =
            race_connect(&[], |_| async { Ok(()) }, |_, e| Some(e)).await;
        assert_eq!(empty.unwrap_err(), None);
        let single = race_connect(
            &[v4(9)],
            |a| async move { Ok::<_, &str>(a) },
            |_, e| Some(e),
        )
        .await;
        assert_eq!(single.unwrap(), v4(9));
    }
}
