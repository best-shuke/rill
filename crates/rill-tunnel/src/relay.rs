//! Bidirectional relay with zero allocations at setup and no per-connection
//! idle buffers (ADR-0008 HP-1 / ADR-0011 T6). Each worker has thread-local
//! scratch (128 KiB on macOS, 32 KiB elsewhere), borrowed only during a
//! synchronous read/write poll.
//! A direction owns storage only after backpressure leaves unwritten bytes;
//! that spill buffer is retained and reused for the connection's lifetime.
//!
//! Plain kernel TCP pairs on Linux lazily switch to splice after 128 KiB per
//! direction. Pipes keep the kernel's default capacity and close on cancellation.
//! Other transports keep using the copy path. Both paths alternate directions
//! and yield after bounded cycles/bytes, count only bytes delivered to the
//! destination, and drain before propagating EOF with a write shutdown.

use std::cell::RefCell;
use std::future::{poll_fn, Future};
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;

#[cfg(target_os = "linux")]
mod splice;

/// Copy chunk size before a direction proves bulk; no buffer is held at setup.
pub const RELAY_BUF_SIZE: usize = 4 * 1024;
// macOS has no socket-to-socket splice. Larger copy chunks amortize its
// syscalls and accounting; the byte budget below still bounds every poll.
#[cfg(target_os = "macos")]
const RELAY_BULK_BUF_SIZE: usize = 128 * 1024;
#[cfg(not(target_os = "macos"))]
const RELAY_BULK_BUF_SIZE: usize = 32 * 1024;
// Promote macOS copies early enough to help medium transfers. Other targets
// keep the threshold that avoids Linux pipe setup for short connections.
#[cfg(target_os = "macos")]
const RELAY_BULK_UPGRADE_BYTES: u64 = 16 * 1024;
#[cfg(not(target_os = "macos"))]
const RELAY_BULK_UPGRADE_BYTES: u64 = 128 * 1024;
/// Bytes one socket → pipe splice may move. The kernel caps each call at the
/// pipe's free space (64 KiB by default), so this only asks for "as much as
/// fits" — Go's net package passes 1 MiB the same way — instead of halving
/// every call at the copy path's 32 KiB.
#[cfg(target_os = "linux")]
const SPLICE_CHUNK: usize = 1 << 20;

thread_local! {
    static SCRATCH: RefCell<[u8; RELAY_BULK_BUF_SIZE]> = const {
        RefCell::new([0; RELAY_BULK_BUF_SIZE])
    };
}

/// Accessor for an unbuffered, untransformed kernel TCP endpoint. Returning
/// `Some` permits bypassing the endpoint's AsyncRead/AsyncWrite implementation.
pub type TcpAccess<T> = fn(&T) -> Option<&TcpStream>;

/// Idle window granted to the surviving relay direction after the *other*
/// direction has reached EOF.
///
/// Without a bound, a peer that closes one half of the connection and then
/// holds its read side open forever pins this future — and with it both
/// underlying sockets. That surfaces as leaked CLOSE-WAIT sockets on the
/// inbound (client) side (the client sent FIN but rill never `close()`s its
/// socket) and FIN-WAIT-2 on the outbound side. The reference mihomo kernel
/// avoids this by tearing the whole relay down once *either* direction
/// completes; this linger is the equivalent, but lenient.
///
/// The window is an **idle timeout, not an absolute deadline**: it is re-armed
/// every time the surviving direction transfers more bytes, so a legitimate
/// half-closed connection that keeps streaming (e.g. a client that shuts down
/// its write side after a request, then downloads a large response) is never
/// truncated mid-transfer. Only a connection that goes genuinely silent for the
/// full window — no progress in either direction — is reaped. A normal
/// simultaneous close drains in microseconds, far inside the window.
pub const RELAY_HALF_CLOSE_LINGER: Duration = Duration::from_secs(30);

/// Upper bound on buffer fill+drain cycles executed per `poll_fn` invocation
/// across both directions before the relay voluntarily yields back to the
/// scheduler (self-waking first, so it is promptly re-polled).
///
/// Real sockets already hit tokio's per-task coop budget (128 ops) around the
/// same magnitude, but coop is an implementation detail of tokio's leaf
/// resources — custom `ProxyConn` stacks (or the in-memory streams used in
/// tests) may never return `Pending` on their own. This cap makes the yield
/// deterministic: at 4 KiB per cycle it bounds one poll at 256 KiB relayed.
const RELAY_CYCLES_PER_POLL: u32 = 64;

/// Byte-based companion to [`RELAY_CYCLES_PER_POLL`]: bulk copies grow to
/// 128 KiB on macOS (32 KiB elsewhere), and splice can move more. Yield
/// once this many bytes have moved in a poll instead, keeping
/// the pre-upgrade 256 KiB-per-poll bound regardless of buffer size.
const RELAY_BYTES_PER_POLL: u64 = 256 * 1024;

enum Cycle {
    Done,
    Progress,
    Pending,
}

struct HalfCopy {
    spill: Option<Box<[u8]>>,
    read_done: bool,
    pos: usize,
    cap: usize,
    amt: u64,
    need_flush: bool,
    #[cfg(target_os = "macos")]
    cycle_limit: usize,
    #[cfg(target_os = "linux")]
    pipe: Option<splice::Pipe>,
}

impl HalfCopy {
    fn copy_limit(&self) -> usize {
        let limit = if self.amt < RELAY_BULK_UPGRADE_BYTES {
            RELAY_BUF_SIZE
        } else {
            RELAY_BULK_BUF_SIZE
        };
        #[cfg(target_os = "macos")]
        let limit = limit.min(self.cycle_limit);
        limit
    }

    fn new() -> Self {
        Self {
            spill: None,
            read_done: false,
            pos: 0,
            cap: 0,
            amt: 0,
            need_flush: false,
            #[cfg(target_os = "macos")]
            cycle_limit: RELAY_BULK_BUF_SIZE,
            #[cfg(target_os = "linux")]
            pipe: None,
        }
    }

    fn poll_cycle<R, W, F>(
        &mut self,
        cx: &mut Context<'_>,
        mut reader: Pin<&mut R>,
        mut writer: Pin<&mut W>,
        _tcp: (TcpAccess<R>, TcpAccess<W>),
        _allow_splice: &mut bool,
        on_progress: &mut F,
    ) -> io::Result<Cycle>
    where
        R: AsyncRead + ?Sized,
        W: AsyncWrite + ?Sized,
        F: FnMut(u64),
    {
        #[cfg(target_os = "linux")]
        if self.pos == self.cap && *_allow_splice && self.amt >= RELAY_BULK_UPGRADE_BYTES {
            if let (Some(src), Some(dst)) = (
                _tcp.0(reader.as_ref().get_ref()),
                _tcp.1(writer.as_ref().get_ref()),
            ) {
                // Defer pipe creation while a bulk direction is waiting for
                // input. Readiness may be spurious; poll_fill clears it.
                if self.pipe.is_none() && !self.read_done {
                    match src.poll_read_ready(cx) {
                        Poll::Pending => return Ok(Cycle::Pending),
                        Poll::Ready(Err(e)) => return Err(e),
                        Poll::Ready(Ok(())) => {}
                    }
                    match splice::Pipe::new() {
                        Ok(pipe) => self.pipe = Some(pipe),
                        // Descriptor/memory pressure must not break a relay
                        // that can still make progress through userspace.
                        Err(_) => *_allow_splice = false,
                    }
                }
                if *_allow_splice {
                    match self.poll_splice(cx, src, dst, on_progress) {
                        Ok(Cycle::Done) => return shutdown(cx, writer),
                        Ok(cycle) => return Ok(cycle),
                        Err(e) if splice::unsupported(&e) => *_allow_splice = false,
                        Err(e) => return Err(e),
                    }
                }
            }
        }

        // Owned storage is only needed if a previous poll could not drain its
        // read. Taking it temporarily avoids aliasing self while polling I/O.
        if let Some(mut spill) = self.spill.take() {
            let result = self.poll_copy(cx, reader, writer, &mut spill, on_progress);
            self.spill = Some(spill);
            return result;
        }
        SCRATCH.with(|scratch| {
            // A custom stream can recursively poll another relay. In that rare
            // case use temporary stack scratch instead of panicking on RefCell.
            match scratch.try_borrow_mut() {
                Ok(mut buf) => {
                    self.poll_scratch(cx, reader.as_mut(), writer.as_mut(), &mut *buf, on_progress)
                }
                Err(_) => self.poll_reentrant(cx, reader, writer, on_progress),
            }
        })
    }

    #[inline(never)]
    fn poll_reentrant<R: AsyncRead + ?Sized, W: AsyncWrite + ?Sized, F: FnMut(u64)>(
        &mut self,
        cx: &mut Context<'_>,
        reader: Pin<&mut R>,
        writer: Pin<&mut W>,
        on_progress: &mut F,
    ) -> io::Result<Cycle> {
        self.poll_scratch(
            cx,
            reader,
            writer,
            &mut [0; RELAY_BULK_BUF_SIZE],
            on_progress,
        )
    }

    fn poll_scratch<R: AsyncRead + ?Sized, W: AsyncWrite + ?Sized, F: FnMut(u64)>(
        &mut self,
        cx: &mut Context<'_>,
        reader: Pin<&mut R>,
        writer: Pin<&mut W>,
        buf: &mut [u8],
        on_progress: &mut F,
    ) -> io::Result<Cycle> {
        let result = self.poll_copy(cx, reader, writer, buf, on_progress);
        if result.is_ok() && self.pos < self.cap {
            let remaining = self.cap - self.pos;
            let mut spill = vec![0; RELAY_BULK_BUF_SIZE].into_boxed_slice();
            spill[..remaining].copy_from_slice(&buf[self.pos..self.cap]);
            self.spill = Some(spill);
            self.pos = 0;
            self.cap = remaining;
        }
        result
    }

    #[cfg(target_os = "linux")]
    fn poll_splice<F: FnMut(u64)>(
        &mut self,
        cx: &mut Context<'_>,
        src: &TcpStream,
        dst: &TcpStream,
        on_progress: &mut F,
    ) -> io::Result<Cycle> {
        let Some(pipe) = &mut self.pipe else {
            // EOF was already observed before reaching the bulk threshold.
            return Ok(Cycle::Done);
        };
        if pipe.buffered == 0 && !self.read_done {
            match pipe.poll_fill(cx, src, SPLICE_CHUNK) {
                Poll::Pending => return Ok(Cycle::Pending),
                Poll::Ready(Err(e)) => return Err(e),
                Poll::Ready(Ok(0)) => self.read_done = true,
                Poll::Ready(Ok(_)) => {}
            }
        }
        while pipe.buffered != 0 {
            match pipe.poll_drain(cx, dst) {
                Poll::Pending => return Ok(Cycle::Pending),
                Poll::Ready(Err(e)) => return Err(e),
                Poll::Ready(Ok(0)) => return Err(write_zero()),
                Poll::Ready(Ok(n)) => {
                    self.amt += n as u64;
                    on_progress(n as u64);
                }
            }
        }
        Ok(if self.read_done {
            Cycle::Done
        } else {
            Cycle::Progress
        })
    }

    fn poll_copy<R: AsyncRead + ?Sized, W: AsyncWrite + ?Sized, F: FnMut(u64)>(
        &mut self,
        cx: &mut Context<'_>,
        mut reader: Pin<&mut R>,
        mut writer: Pin<&mut W>,
        buf: &mut [u8],
        on_progress: &mut F,
    ) -> io::Result<Cycle> {
        if self.pos == self.cap && !self.read_done {
            self.pos = 0;
            self.cap = 0;
            // Keep the original small-flow and bulk fairness granularity.
            let limit = self.copy_limit();
            let mut rb = ReadBuf::new(&mut buf[..limit]);
            #[cfg(target_os = "linux")]
            if let Some(pipe) = &mut self.pipe {
                if pipe.buffered != 0 {
                    let n = pipe.read(rb.initialize_unfilled())?;
                    rb.advance(n);
                }
                if pipe.buffered == 0 {
                    self.pipe = None;
                }
            }
            // A failed pipe→socket splice can leave already-read bytes in the
            // pipe. Forward those first, without rereading/reordering the socket.
            if rb.filled().is_empty() {
                match reader.as_mut().poll_read(cx, &mut rb) {
                    Poll::Ready(Ok(())) => self.read_done = rb.filled().is_empty(),
                    Poll::Ready(Err(e)) => return Err(e),
                    Poll::Pending => {
                        if self.need_flush {
                            match writer.as_mut().poll_flush(cx) {
                                Poll::Ready(Ok(())) => self.need_flush = false,
                                Poll::Ready(Err(e)) => return Err(e),
                                Poll::Pending => return Ok(Cycle::Pending),
                            }
                        }
                        return Ok(Cycle::Pending);
                    }
                }
            }
            self.cap = rb.filled().len();
        }
        #[cfg(target_os = "macos")]
        let cycle_start = self.amt;
        while self.pos < self.cap {
            let end = self.cap;
            #[cfg(target_os = "macos")]
            let end = {
                let remaining = self.cycle_limit - (self.amt - cycle_start) as usize;
                if remaining == 0 {
                    return Ok(Cycle::Progress);
                }
                end.min(self.pos + remaining)
            };
            match writer.as_mut().poll_write(cx, &buf[self.pos..end]) {
                Poll::Ready(Ok(0)) => return Err(write_zero()),
                Poll::Ready(Ok(n)) => {
                    self.pos += n;
                    self.amt += n as u64;
                    on_progress(n as u64);
                    self.need_flush = true;
                }
                Poll::Ready(Err(e)) => return Err(e),
                Poll::Pending => return Ok(Cycle::Pending),
            }
        }
        if self.read_done {
            return shutdown(cx, writer);
        }
        Ok(Cycle::Progress)
    }
}

fn write_zero() -> io::Error {
    io::Error::new(io::ErrorKind::WriteZero, "write zero bytes to writer")
}

fn shutdown<W: AsyncWrite + ?Sized>(
    cx: &mut Context<'_>,
    writer: Pin<&mut W>,
) -> io::Result<Cycle> {
    match writer.poll_shutdown(cx) {
        Poll::Ready(Ok(())) => Ok(Cycle::Done),
        Poll::Ready(Err(e)) => Err(e),
        Poll::Pending => Ok(Cycle::Pending),
    }
}

/// Compatibility entry point for callers with existing scratch arrays. Storage
/// is now shared per worker; supplied buffers are not retained or used.
pub async fn copy_bidirectional_buf<A, B>(
    a: &mut A,
    b: &mut B,
    buf_a_to_b: &mut [u8],
    buf_b_to_a: &mut [u8],
) -> io::Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin + ?Sized,
    B: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    copy_bidirectional_buf_tracked(a, b, buf_a_to_b, buf_b_to_a, |_| {}, |_| {}).await
}

/// Compatibility tracked entry point; prefer [`copy_bidirectional_tracked`]
/// for relays without caller-owned buffers and with optional kernel TCP access.
pub async fn copy_bidirectional_buf_tracked<A, B, FA, FB>(
    a: &mut A,
    b: &mut B,
    _buf_a_to_b: &mut [u8],
    _buf_b_to_a: &mut [u8],
    on_a_to_b: FA,
    on_b_to_a: FB,
) -> io::Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin + ?Sized,
    B: AsyncRead + AsyncWrite + Unpin + ?Sized,
    FA: FnMut(u64),
    FB: FnMut(u64),
{
    copy_bidirectional_tracked(a, b, |_| None, |_| None, on_a_to_b, on_b_to_a).await
}

/// Relay without allocating buffers at setup. TCP accessors opt into Linux
/// splice only when both endpoints safely expose an untransformed TcpStream.
/// Callbacks count bytes after successful destination writes, including splice.
/// Dropping this future releases all spill buffers and any lazily-created pipes.
pub async fn copy_bidirectional_tracked<A, B, FA, FB>(
    a: &mut A,
    b: &mut B,
    a_tcp: TcpAccess<A>,
    b_tcp: TcpAccess<B>,
    mut on_a_to_b: FA,
    mut on_b_to_a: FB,
) -> io::Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin + ?Sized,
    B: AsyncRead + AsyncWrite + Unpin + ?Sized,
    FA: FnMut(u64),
    FB: FnMut(u64),
{
    let mut a_to_b = HalfCopy::new();
    let mut b_to_a = HalfCopy::new();
    let mut allow_splice = true;
    let mut a_done = false;
    let mut b_done = false;

    // Linger timer reaping a half-closed-then-stuck connection. Created up front
    // so it can be pinned on the stack (no per-relay heap allocation), but not
    // polled — and therefore not registered with the timer driver — until one
    // direction has finished and the other is still running. See
    // `RELAY_HALF_CLOSE_LINGER`.
    let linger = tokio::time::sleep(RELAY_HALF_CLOSE_LINGER);
    tokio::pin!(linger);
    let mut linger_armed = false;
    // Bytes transferred by the surviving direction when the linger was last
    // (re)armed. Used to re-arm the idle window on every byte of progress so an
    // active half-closed transfer is never truncated. See `RELAY_HALF_CLOSE_LINGER`.
    let mut linger_progress: u64 = 0;

    poll_fn(move |cx| {
        // Fair interleave (#345): alternate single fill+drain cycles between
        // the directions instead of draining one to `Pending` before touching
        // the other. Loop while either direction reports `Progress`, up to
        // `RELAY_CYCLES_PER_POLL` progress cycles per poll.
        //
        // Once a direction returns `Pending` it is parked for the REST of this
        // poll: it can only become ready again by waking the task (which
        // re-enters this closure), so re-polling it every iteration would just
        // burn a readiness check + waker re-registration per 4 KiB cycle of
        // the busy direction. A readiness event that fires while we are still
        // looping marks the task notified and triggers an immediate re-poll,
        // so no wakeup is lost by parking.
        let mut cycles: u32 = 0;
        let poll_start_bytes = a_to_b.amt + b_to_a.amt;
        let mut a_parked = false;
        let mut b_parked = false;
        loop {
            // Share the remaining budget between active directions. Limiting
            // the actual reads/writes avoids an early self-wake when a stream
            // has transferred many small messages and is eligible for bulk
            // buffers, but its next read still only contains a small message.
            #[cfg(target_os = "macos")]
            {
                let active = u64::from(!a_done && !a_parked) + u64::from(!b_done && !b_parked);
                let remaining = RELAY_BYTES_PER_POLL - (a_to_b.amt + b_to_a.amt - poll_start_bytes);
                let allowance = remaining / active.max(1);
                if allowance == 0 {
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
                a_to_b.cycle_limit = allowance as usize;
                b_to_a.cycle_limit = allowance as usize;
            }
            let mut progressed = false;

            if !a_done && !a_parked {
                let a_pin = Pin::new(&mut *a);
                let b_pin = Pin::new(&mut *b);
                match a_to_b.poll_cycle(
                    cx,
                    a_pin,
                    b_pin,
                    (a_tcp, b_tcp),
                    &mut allow_splice,
                    &mut on_a_to_b,
                ) {
                    Ok(Cycle::Done) => a_done = true,
                    Ok(Cycle::Progress) => {
                        progressed = true;
                        cycles += 1;
                    }
                    Ok(Cycle::Pending) => a_parked = true,
                    Err(e) => return Poll::Ready(Err(e)),
                }
            }

            if !b_done && !b_parked {
                let a_pin = Pin::new(&mut *a);
                let b_pin = Pin::new(&mut *b);
                match b_to_a.poll_cycle(
                    cx,
                    b_pin,
                    a_pin,
                    (b_tcp, a_tcp),
                    &mut allow_splice,
                    &mut on_b_to_a,
                ) {
                    Ok(Cycle::Done) => b_done = true,
                    Ok(Cycle::Progress) => {
                        progressed = true;
                        cycles += 1;
                    }
                    Ok(Cycle::Pending) => b_parked = true,
                    Err(e) => return Poll::Ready(Err(e)),
                }
            }

            if a_done && b_done {
                return Poll::Ready(Ok((a_to_b.amt, b_to_a.amt)));
            }

            if !progressed {
                break;
            }

            if cycles >= RELAY_CYCLES_PER_POLL
                || (a_to_b.amt + b_to_a.amt) - poll_start_bytes >= RELAY_BYTES_PER_POLL
            {
                // Yield to sibling tasks; self-wake so the scheduler re-polls
                // this relay promptly. The byte bound keeps one poll at
                // ~256 KiB even after a bulk buffer upgrade.
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
        }

        // Exactly one direction has finished while the other is still open.
        // Arm the idle window on that transition and re-arm it on every byte the
        // surviving direction makes progress, then let it race that direction:
        // whichever resolves first ends the relay. Because the window resets on
        // progress, an actively-streaming half-closed connection is never
        // truncated — only one that goes silent for the full window is reaped.
        // The surviving direction is re-polled above on every wake, so if it
        // drains before the timer fires we still return the full byte counts.
        if a_done || b_done {
            let surviving_amt = if a_done { b_to_a.amt } else { a_to_b.amt };
            if !linger_armed || surviving_amt != linger_progress {
                linger_armed = true;
                linger_progress = surviving_amt;
                linger
                    .as_mut()
                    .reset(tokio::time::Instant::now() + RELAY_HALF_CLOSE_LINGER);
            }
            if linger.as_mut().poll(cx).is_ready() {
                return Poll::Ready(Ok((a_to_b.amt, b_to_a.amt)));
            }
        }

        Poll::Pending
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    #[tokio::test]
    async fn roundtrip_small() {
        let (mut a, mut b) = duplex(64);
        let (mut a2, mut b2) = duplex(64);

        // Write some data into the pipe ends that will be relayed.
        use tokio::io::AsyncWriteExt;
        a.write_all(b"hello").await.unwrap();
        a.shutdown().await.unwrap();
        b2.write_all(b"world").await.unwrap();
        b2.shutdown().await.unwrap();

        let mut buf1 = [0u8; RELAY_BUF_SIZE];
        let mut buf2 = [0u8; RELAY_BUF_SIZE];
        let (up, down) = copy_bidirectional_buf(&mut b, &mut a2, &mut buf1, &mut buf2)
            .await
            .unwrap();

        assert_eq!(up, 5, "a→b direction");
        assert_eq!(down, 5, "b→a direction");
    }

    // Data integrity across the bulk chunk-size transition and backpressure:
    // stream several multiples of the threshold through both directions.
    #[tokio::test]
    async fn bulk_copy_survives_backpressure_and_chunk_size_transition() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        const TOTAL: usize = (RELAY_BULK_UPGRADE_BYTES as usize + RELAY_BULK_BUF_SIZE) * 4;

        let (mut client, mut a) = duplex(16 * 1024);
        let (mut b, mut upstream) = duplex(16 * 1024);

        let relay = tokio::spawn(async move {
            let mut buf1 = [0u8; RELAY_BUF_SIZE];
            let mut buf2 = [0u8; RELAY_BUF_SIZE];
            copy_bidirectional_buf(&mut a, &mut b, &mut buf1, &mut buf2).await
        });

        let pattern: Vec<u8> = (0..TOTAL).map(|i| (i % 251) as u8).collect();

        // client → upstream
        let tx = {
            let pattern = pattern.clone();
            tokio::spawn(async move {
                client.write_all(&pattern).await.unwrap();
                client.shutdown().await.unwrap();
                client
            })
        };
        let mut received = vec![0u8; TOTAL];
        upstream.read_exact(&mut received).await.unwrap();
        assert_eq!(
            received, pattern,
            "client→upstream bytes must survive the upgrade"
        );

        // upstream → client, past the threshold in the other direction too.
        // Write and read concurrently: the duplex pipes are far smaller than
        // TOTAL, so a sequential write-then-read would deadlock and trip the
        // half-close linger instead of exercising the upgrade.
        let tx_back = {
            let pattern = pattern.clone();
            tokio::spawn(async move {
                upstream.write_all(&pattern).await.unwrap();
                upstream.shutdown().await.unwrap();
            })
        };
        let mut client = tx.await.unwrap();
        let mut back = vec![0u8; TOTAL];
        client.read_exact(&mut back).await.unwrap();
        assert_eq!(
            back, pattern,
            "upstream→client bytes must survive the upgrade"
        );
        tx_back.await.unwrap();

        let (up, down) = relay.await.unwrap().unwrap();
        assert_eq!(up, TOTAL as u64);
        assert_eq!(down, TOTAL as u64);
    }

    // Regression: a peer that half-closes (sends EOF on its write side) and
    // then holds its read side open forever must not pin the relay. Before the
    // half-close linger, `copy_bidirectional_buf` waited for *both* directions
    // to EOF, so this hung indefinitely — surfacing in production as leaked
    // CLOSE-WAIT (inbound) / FIN-WAIT-2 (outbound) sockets.
    #[tokio::test(start_paused = true)]
    async fn half_closed_peer_does_not_pin_relay() {
        use tokio::io::AsyncWriteExt;

        // `a` is the relay's view of the "client": the client sends a byte then
        // closes its write side, so a→b sees EOF. `b` is the relay's view of the
        // "upstream", whose far end (`_upstream_held_open`) never sends and never
        // closes, so b→a would otherwise block forever. The underscore-prefixed
        // binding is kept (not dropped) for the whole test so `b` never sees EOF.
        let (mut client, mut a) = duplex(64);
        let (mut b, _upstream_held_open) = duplex(64);

        client.write_all(b"x").await.unwrap();
        client.shutdown().await.unwrap();

        let mut buf1 = [0u8; RELAY_BUF_SIZE];
        let mut buf2 = [0u8; RELAY_BUF_SIZE];

        // With paused time the linger only elapses via the runtime's auto-advance
        // once the future is genuinely stalled, so completion proves the timer —
        // not real wall-clock — drove teardown.
        let (up, down) = tokio::time::timeout(
            RELAY_HALF_CLOSE_LINGER * 4,
            copy_bidirectional_buf(&mut a, &mut b, &mut buf1, &mut buf2),
        )
        .await
        .expect("relay must tear down within the linger window, not hang")
        .expect("relay returns Ok after the linger reaps the stuck direction");

        assert_eq!(up, 1, "the client's byte was relayed before teardown");
        assert_eq!(down, 0, "upstream never sent anything");
    }

    // Regression: a legitimate half-closed connection that keeps actively
    // streaming on the surviving direction must NOT be truncated by the linger.
    // The client shuts down its write side, then the upstream streams for far
    // longer than one linger window, with each gap shorter than the window. An
    // absolute-deadline linger would cut this off at `RELAY_HALF_CLOSE_LINGER`;
    // the idle-timeout linger re-arms on every chunk and lets it all through.
    #[tokio::test(start_paused = true)]
    async fn active_half_closed_transfer_is_not_truncated() {
        use tokio::io::AsyncWriteExt;

        let (mut client, mut a) = duplex(64);
        let (mut b, mut upstream) = duplex(64);

        // Client sends one byte then half-closes — a→b sees EOF, arming the linger.
        client.write_all(b"x").await.unwrap();
        client.shutdown().await.unwrap();

        // Upstream streams 6 chunks spaced at half the linger window (total span
        // 3× the window), then closes. No single gap reaches the window, so the
        // idle timer keeps getting re-armed and never reaps the live transfer.
        let feeder = tokio::spawn(async move {
            for _ in 0..6 {
                tokio::time::sleep(RELAY_HALF_CLOSE_LINGER / 2).await;
                upstream.write_all(b"yy").await.unwrap();
            }
            upstream.shutdown().await.unwrap();
        });

        let mut buf1 = [0u8; RELAY_BUF_SIZE];
        let mut buf2 = [0u8; RELAY_BUF_SIZE];

        // Drain `a` (the relay writes upstream bytes here) so the duplex buffer
        // never backpressures and the relay can run to upstream's clean EOF.
        let drain = tokio::spawn(async move {
            use tokio::io::AsyncReadExt;
            let mut sink = Vec::new();
            client.read_to_end(&mut sink).await.unwrap();
            sink.len()
        });

        let (up, down) = copy_bidirectional_buf(&mut a, &mut b, &mut buf1, &mut buf2)
            .await
            .expect("relay completes via upstream EOF, not a truncating linger");

        feeder.await.unwrap();
        let drained = drain.await.unwrap();

        assert_eq!(up, 1, "the client's byte was relayed");
        assert_eq!(
            down, 12,
            "every upstream byte must be relayed — the active transfer is not truncated"
        );
        assert_eq!(drained, 12, "client received the full upstream stream");
    }

    // Regression for #345: under symmetric load, neither direction may
    // monopolize the relay. The old `poll_copy` drained the entire a→b
    // direction to `Pending` before b→a was polled at all, so every a→b
    // progress event fired before the first b→a event. The interleaved relay
    // alternates one buffer cycle per direction, so both directions must show
    // progress from the very start of the transfer.
    #[tokio::test]
    async fn directions_interleave_under_symmetric_load() {
        use tokio::io::AsyncWriteExt;

        // 8 relay-buffers of data queued in EACH direction before the relay
        // starts, with enough duplex capacity that no write ever backpressures
        // — progress order is then determined purely by relay poll order.
        let total = RELAY_BUF_SIZE * 8;
        let (mut client, mut a) = duplex(total * 2);
        let (mut b, mut upstream) = duplex(total * 2);

        client.write_all(&vec![1u8; total]).await.unwrap();
        client.shutdown().await.unwrap();
        upstream.write_all(&vec![2u8; total]).await.unwrap();
        upstream.shutdown().await.unwrap();

        let mut buf1 = [0u8; RELAY_BUF_SIZE];
        let mut buf2 = [0u8; RELAY_BUF_SIZE];

        // Record the order of write-progress events per direction.
        let events = std::cell::RefCell::new(Vec::new());
        let (up, down) = copy_bidirectional_buf_tracked(
            &mut a,
            &mut b,
            &mut buf1,
            &mut buf2,
            |n| events.borrow_mut().push(('a', n)),
            |n| events.borrow_mut().push(('b', n)),
        )
        .await
        .unwrap();

        assert_eq!(up as usize, total, "a→b relayed everything");
        assert_eq!(down as usize, total, "b→a relayed everything");

        let events = events.into_inner();
        let first_b = events
            .iter()
            .position(|e| e.0 == 'b')
            .expect("b→a made progress");
        let last_a = events
            .iter()
            .rposition(|e| e.0 == 'a')
            .expect("a→b made progress");
        assert!(
            first_b < last_a,
            "b→a must progress before a→b fully drains (first b event at \
             index {first_b}, last a event at index {last_a})"
        );
        assert!(
            first_b <= 2,
            "with fair interleaving b→a's first progress arrives within the \
             first few cycles, not at index {first_b}"
        );
    }

    #[tokio::test]
    async fn empty_streams() {
        let (mut a, mut b) = duplex(64);
        let (mut a2, mut b2) = duplex(64);

        use tokio::io::AsyncWriteExt;
        a.shutdown().await.unwrap();
        b2.shutdown().await.unwrap();

        let mut buf1 = [0u8; RELAY_BUF_SIZE];
        let mut buf2 = [0u8; RELAY_BUF_SIZE];
        let (up, down) = copy_bidirectional_buf(&mut b, &mut a2, &mut buf1, &mut buf2)
            .await
            .unwrap();
        assert_eq!(up, 0);
        assert_eq!(down, 0);
    }
}

#[cfg(all(test, target_os = "linux"))]
mod linux_tests;

#[cfg(test)]
mod scratch_tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn idle_and_immediate_writes_need_no_owned_buffer() {
        let (mut client, mut src) = tokio::io::duplex(64);
        let (mut dst, mut upstream) = tokio::io::duplex(64);
        let mut half = HalfCopy::new();
        let mut allow = true;
        poll_fn(|cx| {
            assert!(matches!(
                half.poll_cycle(
                    cx,
                    Pin::new(&mut src),
                    Pin::new(&mut dst),
                    (|_| None, |_| None),
                    &mut allow,
                    &mut |_| {}
                )
                .unwrap(),
                Cycle::Pending
            ));
            Poll::Ready(())
        })
        .await;
        assert!(half.spill.is_none());
        client.write_all(b"hello").await.unwrap();
        poll_fn(|cx| {
            assert!(matches!(
                half.poll_cycle(
                    cx,
                    Pin::new(&mut src),
                    Pin::new(&mut dst),
                    (|_| None, |_| None),
                    &mut allow,
                    &mut |_| {}
                )
                .unwrap(),
                Cycle::Progress
            ));
            Poll::Ready(())
        })
        .await;
        let mut bytes = [0; 5];
        upstream.read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes, b"hello");
        assert!(half.spill.is_none());
    }

    #[tokio::test]
    async fn pending_write_spills_only_the_unwritten_bytes() {
        let (mut client, mut src) = tokio::io::duplex(64);
        let (mut dst, mut upstream) = tokio::io::duplex(1);
        client.write_all(b"hello").await.unwrap();
        client.shutdown().await.unwrap();
        let mut half = HalfCopy::new();
        let mut allow = true;
        let mut delivered = 0;
        poll_fn(|cx| {
            assert!(matches!(
                half.poll_cycle(
                    cx,
                    Pin::new(&mut src),
                    Pin::new(&mut dst),
                    (|_| None, |_| None),
                    &mut allow,
                    &mut |n| delivered += n
                )
                .unwrap(),
                Cycle::Pending
            ));
            Poll::Ready(())
        })
        .await;
        assert_eq!(delivered, 1);
        assert_eq!(half.cap, 4);
        assert_eq!(&half.spill.as_ref().unwrap()[..4], b"ello");
        let storage = half.spill.as_ref().unwrap().as_ptr();
        // A different connection on this worker can overwrite all scratch
        // before the blocked writer wakes, without corrupting retained bytes.
        SCRATCH.with(|scratch| scratch.borrow_mut().fill(99));
        let copy = poll_fn(|cx| loop {
            match half
                .poll_cycle(
                    cx,
                    Pin::new(&mut src),
                    Pin::new(&mut dst),
                    (|_| None, |_| None),
                    &mut allow,
                    &mut |n| delivered += n,
                )
                .unwrap()
            {
                Cycle::Done => return Poll::Ready(()),
                Cycle::Pending => return Poll::Pending,
                Cycle::Progress => {}
            }
        });
        let read = async {
            let mut bytes = Vec::new();
            upstream.read_to_end(&mut bytes).await.unwrap();
            bytes
        };
        let ((), bytes) = tokio::join!(copy, read);
        assert_eq!(bytes, b"hello");
        assert_eq!(delivered, 5);
        assert_eq!(half.spill.as_ref().unwrap().as_ptr(), storage);
    }

    #[tokio::test]
    async fn always_ready_streams_yield_within_cycle_and_byte_budgets() {
        struct Endless(usize);
        impl AsyncRead for Endless {
            fn poll_read(
                self: Pin<&mut Self>,
                _: &mut Context<'_>,
                buf: &mut ReadBuf<'_>,
            ) -> Poll<io::Result<()>> {
                let n = buf.remaining().min(self.0);
                buf.initialize_unfilled().fill(0);
                buf.advance(n);
                Poll::Ready(Ok(()))
            }
        }
        impl AsyncWrite for Endless {
            fn poll_write(
                self: Pin<&mut Self>,
                _: &mut Context<'_>,
                bytes: &[u8],
            ) -> Poll<io::Result<usize>> {
                Poll::Ready(Ok(bytes.len()))
            }
            fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
                Poll::Ready(Ok(()))
            }
            fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
                Poll::Ready(Ok(()))
            }
        }
        for read_cap in [usize::MAX, 4096] {
            let mut a = Endless(read_cap);
            let mut b = Endless(read_cap);
            let up = std::cell::Cell::new(0);
            let down = std::cell::Cell::new(0);
            let relay = copy_bidirectional_tracked(
                &mut a,
                &mut b,
                |_| None,
                |_| None,
                |n| up.set(up.get() + n),
                |n| down.set(down.get() + n),
            );
            tokio::pin!(relay);
            for _ in 0..3 {
                let before = up.get() + down.get();
                let mut cx = Context::from_waker(std::task::Waker::noop());
                assert!(relay.as_mut().poll(&mut cx).is_pending());
                assert_eq!(up.get(), down.get(), "directions must alternate fairly");
                assert!(up.get() + down.get() - before <= RELAY_BYTES_PER_POLL);
                if read_cap == 4096 {
                    assert!(
                        up.get() + down.get() - before >= 128 * 1024,
                        "small reads must not yield early after becoming bulk eligible"
                    );
                }
            }
        }
    }
}
