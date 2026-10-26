//! Combine ready plaintext records without waiting for another record.
//! Used above SS/Trojan codecs, never below Vision's TLS switch boundary.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, ReadBuf};

pub(crate) fn poll_read<T: AsyncRead + Unpin>(
    stream: &mut T,
    error: &mut Option<io::Error>,
    cx: &mut Context<'_>,
    out: &mut ReadBuf<'_>,
) -> Poll<io::Result<()>> {
    if out.remaining() == 0 {
        return Poll::Ready(Ok(()));
    }
    if let Some(error) = error.take() {
        return Poll::Ready(Err(error));
    }
    let start = out.filled().len();
    loop {
        let before = out.filled().len();
        match Pin::new(&mut *stream).poll_read(cx, out) {
            Poll::Ready(Ok(())) => {
                let received = out.filled().len() - before;
                if received < 8192
                    || out.remaining() == 0
                    || out.filled().len() - start >= 128 * 1024
                {
                    return Poll::Ready(Ok(()));
                }
            }
            Poll::Pending if out.filled().len() != start => return Poll::Ready(Ok(())),
            Poll::Ready(Err(next)) if out.filled().len() != start => {
                *error = Some(next);
                return Poll::Ready(Ok(()));
            }
            result => return result,
        }
    }
}

#[cfg(feature = "trojan")]
pub(crate) struct CoalescedRead<T> {
    inner: T,
    error: Option<io::Error>,
}

#[cfg(feature = "trojan")]
impl<T> CoalescedRead<T> {
    pub(crate) fn new(inner: T) -> Self {
        Self { inner, error: None }
    }
}

#[cfg(feature = "trojan")]
impl<T: AsyncRead + Unpin> AsyncRead for CoalescedRead<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        poll_read(&mut this.inner, &mut this.error, cx, out)
    }
}

#[cfg(feature = "trojan")]
impl<T: tokio::io::AsyncWrite + Unpin> tokio::io::AsyncWrite for CoalescedRead<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, data)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write_vectored(cx, data)
    }
}

#[cfg(feature = "trojan")]
impl<T: AsyncRead + tokio::io::AsyncWrite + Unpin + Send + Sync> rill_common::ProxyConn
    for CoalescedRead<T>
{
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Records {
        size: usize,
        records: usize,
        calls: usize,
        fail: bool,
    }

    impl AsyncRead for Records {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _: &mut Context<'_>,
            out: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            self.calls += 1;
            if self.records == 0 {
                return if self.fail {
                    Poll::Ready(Err(io::ErrorKind::InvalidData.into()))
                } else {
                    Poll::Pending
                };
            }
            let n = self.size.min(out.remaining());
            out.initialize_unfilled()[..n].fill(0x5a);
            out.advance(n);
            self.records -= 1;
            Poll::Ready(Ok(()))
        }
    }

    #[test]
    fn bulk_records_return_when_next_record_is_pending() {
        let mut stream = Records {
            size: 16384,
            records: 2,
            calls: 0,
            fail: false,
        };
        let mut bytes = [0; 65536];
        let mut out = ReadBuf::new(&mut bytes);
        let mut error = None;
        let mut cx = Context::from_waker(std::task::Waker::noop());
        assert!(poll_read(&mut stream, &mut error, &mut cx, &mut out).is_ready());
        assert_eq!(out.filled(), &[0x5a; 32768]);
        assert_eq!(stream.calls, 3);
    }

    #[test]
    fn small_reply_returns_without_probing_for_another_record() {
        let mut stream = Records {
            size: 4096,
            records: 2,
            calls: 0,
            fail: false,
        };
        let mut bytes = [0; 16384];
        let mut out = ReadBuf::new(&mut bytes);
        let mut cx = Context::from_waker(std::task::Waker::noop());
        assert!(poll_read(&mut stream, &mut None, &mut cx, &mut out).is_ready());
        assert_eq!(out.filled().len(), 4096);
        assert_eq!(stream.calls, 1);
    }

    #[test]
    fn error_follows_valid_prefix_and_survives_empty_read() {
        let mut stream = Records {
            size: 16384,
            records: 1,
            calls: 0,
            fail: true,
        };
        let mut bytes = [0; 32768];
        let mut out = ReadBuf::new(&mut bytes);
        let mut error = None;
        let mut cx = Context::from_waker(std::task::Waker::noop());
        assert!(poll_read(&mut stream, &mut error, &mut cx, &mut out).is_ready());
        assert_eq!(out.filled(), &[0x5a; 16384]);
        let mut empty = ReadBuf::new(&mut []);
        assert!(matches!(
            poll_read(&mut stream, &mut error, &mut cx, &mut empty),
            Poll::Ready(Ok(()))
        ));
        let mut out = ReadBuf::new(&mut bytes);
        assert!(
            matches!(poll_read(&mut stream, &mut error, &mut cx, &mut out), Poll::Ready(Err(e)) if e.kind() == io::ErrorKind::InvalidData)
        );
        assert!(out.filled().is_empty());
    }
}
