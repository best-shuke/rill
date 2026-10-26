//! macOS read-ahead and bulk write batching below framed proxy codecs.
//! Idle streams own no buffers; small writes go straight to the transport.

use std::cell::RefCell;
use std::io;
use std::pin::Pin;
use std::task::{ready, Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

const READ_CAPACITY: usize = 32 * 1024;
const WRITE_CAPACITY: usize = 64 * 1024;
// A full AEAD-v1 record is 0x3fff payload bytes plus its length and tags.
const BATCH_MIN: usize = 16 * 1024;

thread_local! {
    static READ_SCRATCH: RefCell<[u8; READ_CAPACITY]> = const {
        RefCell::new([0; READ_CAPACITY])
    };
}

pub(crate) struct RecordIo<T> {
    inner: T,
    read: Option<Box<[u8]>>,
    pos: usize,
    cap: usize,
    write: Vec<u8>,
    written: usize,
    draining: bool,
}

impl<T> RecordIo<T> {
    pub(crate) fn new(inner: T) -> Self {
        Self {
            inner,
            read: None,
            pos: 0,
            cap: 0,
            write: Vec::new(),
            written: 0,
            draining: false,
        }
    }
}

#[cfg(feature = "ss")]
impl RecordIo<tokio::net::TcpStream> {
    pub(crate) fn into_split(
        self,
    ) -> (
        RecordIo<tokio::net::tcp::OwnedReadHalf>,
        RecordIo<tokio::net::tcp::OwnedWriteHalf>,
    ) {
        let (read, write) = self.inner.into_split();
        let mut reader = RecordIo::new(read);
        reader.read = self.read;
        reader.pos = self.pos;
        reader.cap = self.cap;
        let mut writer = RecordIo::new(write);
        writer.write = self.write;
        writer.written = self.written;
        writer.draining = self.draining;
        (reader, writer)
    }
}

impl<T: AsyncRead + Unpin> RecordIo<T> {
    fn poll_read_buffer(
        &mut self,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
        storage: &mut [u8],
    ) -> Poll<io::Result<()>> {
        if self.pos == self.cap {
            self.pos = 0;
            self.cap = 0;
            let mut input = ReadBuf::new(storage);
            ready!(Pin::new(&mut self.inner).poll_read(cx, &mut input))?;
            self.cap = input.filled().len();
        }
        let n = out.remaining().min(self.cap - self.pos);
        out.put_slice(&storage[self.pos..self.pos + n]);
        self.pos += n;
        Poll::Ready(Ok(()))
    }

    fn poll_read_scratch(
        &mut self,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
        scratch: &mut [u8],
    ) -> Poll<io::Result<()>> {
        let result = self.poll_read_buffer(cx, out, scratch);
        if result.is_ready() && self.pos < self.cap {
            let remaining = self.cap - self.pos;
            let mut storage = vec![0; READ_CAPACITY].into_boxed_slice();
            storage[..remaining].copy_from_slice(&scratch[self.pos..self.cap]);
            self.read = Some(storage);
            self.pos = 0;
            self.cap = remaining;
        }
        result
    }

    #[inline(never)]
    fn poll_read_reentrant(
        &mut self,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.poll_read_scratch(cx, out, &mut [0; READ_CAPACITY])
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for RecordIo<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if out.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if this.pos == this.cap && out.remaining() >= READ_CAPACITY {
            return Pin::new(&mut this.inner).poll_read(cx, out);
        }
        if let Some(mut storage) = this.read.take() {
            let result = this.poll_read_buffer(cx, out, &mut storage);
            this.read = Some(storage);
            return result;
        }
        READ_SCRATCH.with(|scratch| match scratch.try_borrow_mut() {
            Ok(mut storage) => this.poll_read_scratch(cx, out, &mut *storage),
            Err(_) => this.poll_read_reentrant(cx, out),
        })
    }
}

impl<T: AsyncWrite + Unpin> RecordIo<T> {
    fn poll_drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.draining = !self.write.is_empty();
        while self.written < self.write.len() {
            let n = ready!(Pin::new(&mut self.inner).poll_write(cx, &self.write[self.written..]))?;
            if n == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            self.written += n;
        }
        self.write.clear();
        self.written = 0;
        self.draining = false;
        Poll::Ready(Ok(()))
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for RecordIo<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        // A read-side flush can be pending when another write arrives.
        // Preserve the exact retry slice required by TLS transports.
        if this.draining {
            ready!(this.poll_drain(cx))?;
        }
        if this.write.capacity() == 0 {
            if !(BATCH_MIN..WRITE_CAPACITY).contains(&buf.len()) {
                return Pin::new(&mut this.inner).poll_write(cx, buf);
            }
            this.write.reserve_exact(WRITE_CAPACITY);
        }
        if this.write.len() + buf.len() > WRITE_CAPACITY {
            ready!(this.poll_drain(cx))?;
        }
        if buf.len() >= WRITE_CAPACITY {
            return Pin::new(&mut this.inner).poll_write(cx, buf);
        }
        this.write.extend_from_slice(buf);
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_drain(cx))?;
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_drain(cx))?;
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::poll_fn;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn idle_read_and_small_writes_need_no_buffers() {
        let (a, mut b) = tokio::io::duplex(64);
        let mut io = RecordIo::new(a);
        poll_fn(|cx| {
            let mut bytes = [0; 2];
            assert!(Pin::new(&mut io)
                .poll_read(cx, &mut ReadBuf::new(&mut bytes))
                .is_pending());
            Poll::Ready(())
        })
        .await;
        io.write_all(b"hello").await.unwrap();
        let mut bytes = [0; 5];
        b.read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes, b"hello");
        assert!(io.read.is_none());
        assert_eq!(io.write.capacity(), 0);
    }

    #[tokio::test]
    async fn read_ahead_survives_scratch_reuse_and_eof() {
        let (a, mut b) = tokio::io::duplex(65536);
        let mut io = RecordIo::new(a);
        let expected: Vec<u8> = (0..10000).map(|i| (i % 251) as u8).collect();
        b.write_all(&expected).await.unwrap();
        b.shutdown().await.unwrap();
        let mut first = [0; 2];
        io.read_exact(&mut first).await.unwrap();
        assert_eq!(first, expected[..2]);
        assert!(io.read.is_some());
        READ_SCRATCH.with(|scratch| scratch.borrow_mut().fill(99));
        let mut rest = Vec::new();
        io.read_to_end(&mut rest).await.unwrap();
        assert_eq!(rest, expected[2..]);
    }

    #[tokio::test]
    async fn bulk_writes_batch_and_shutdown_drains_under_backpressure() {
        let (a, mut b) = tokio::io::duplex(13);
        let mut io = RecordIo::new(a);
        let block: Vec<u8> = (0..BATCH_MIN + 34).map(|i| (i % 251) as u8).collect();
        for _ in 0..3 {
            io.write_all(&block).await.unwrap();
        }
        assert_eq!(io.write.len(), block.len() * 3);
        assert!(io.write.capacity() >= WRITE_CAPACITY);
        let send = async {
            io.write_all(&block).await.unwrap();
            io.shutdown().await.unwrap();
        };
        let recv = async {
            let mut bytes = Vec::new();
            b.read_to_end(&mut bytes).await.unwrap();
            assert_eq!(bytes, block.repeat(4));
        };
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            tokio::join!(send, recv);
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn large_reads_and_writes_bypass_buffers() {
        let (a, mut b) = tokio::io::duplex(WRITE_CAPACITY * 2);
        let mut io = RecordIo::new(a);
        let block = vec![19; WRITE_CAPACITY];
        io.write_all(&block).await.unwrap();
        assert_eq!(io.write.capacity(), 0);
        let mut received = vec![0; WRITE_CAPACITY];
        b.read_exact(&mut received).await.unwrap();
        assert_eq!(received, block);
        b.write_all(&block).await.unwrap();
        io.read_exact(&mut received).await.unwrap();
        assert_eq!(received, block);
        assert!(io.read.is_none());
    }

    #[tokio::test]
    async fn pending_flush_keeps_its_retry_slice_until_drained() {
        let (a, mut b) = tokio::io::duplex(1);
        let mut io = RecordIo::new(a);
        let block: Vec<u8> = (0..BATCH_MIN).map(|i| (i % 251) as u8).collect();
        io.write_all(&block).await.unwrap();
        poll_fn(|cx| {
            assert!(Pin::new(&mut io).poll_flush(cx).is_pending());
            assert!(io.draining);
            assert!(Pin::new(&mut io).poll_write(cx, &[7]).is_pending());
            assert_eq!(io.write, block, "do not extend a pending TLS write");
            Poll::Ready(())
        })
        .await;
        let send = async {
            io.write_all(&[7]).await.unwrap();
            io.shutdown().await.unwrap();
        };
        let recv = async {
            let mut received = Vec::new();
            b.read_to_end(&mut received).await.unwrap();
            assert_eq!(&received[..block.len()], block);
            assert_eq!(&received[block.len()..], &[7]);
        };
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            tokio::join!(send, recv);
        })
        .await
        .unwrap();
    }
}
