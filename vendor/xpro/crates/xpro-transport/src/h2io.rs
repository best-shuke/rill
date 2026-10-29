use bytes::{Buf, Bytes};
use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use xpro_protocol::invalid;
/// H2 flow-control credit is returned only as bytes are consumed by the reader.
pub struct H2Io {
    recv: h2::RecvStream,
    send: h2::SendStream<Bytes>,
    pending: Bytes,
    closed: bool,
}
impl H2Io {
    pub fn new(recv: h2::RecvStream, send: h2::SendStream<Bytes>) -> Self {
        Self {
            recv,
            send,
            pending: Bytes::new(),
            closed: false,
        }
    }
}
impl AsyncRead for H2Io {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        loop {
            if !self.pending.is_empty() {
                let n = buf.remaining().min(self.pending.len());
                buf.put_slice(&self.pending[..n]);
                self.pending.advance(n);
                self.recv
                    .flow_control()
                    .release_capacity(n)
                    .map_err(io::Error::other)?;
                return Poll::Ready(Ok(()));
            }
            match std::task::ready!(self.recv.poll_data(cx)) {
                Some(Ok(bytes)) => self.pending = bytes,
                Some(Err(e)) => return Poll::Ready(Err(io::Error::other(e))),
                None => return Poll::Ready(Ok(())),
            }
        }
    }
}
impl AsyncWrite for H2Io {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.closed {
            return Poll::Ready(Err(invalid("write after H2 shutdown")));
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let requested = buf.len().min(16384);
        self.send.reserve_capacity(requested);
        let n = match std::task::ready!(self.send.poll_capacity(cx)) {
            Some(Ok(n)) => n.min(requested),
            Some(Err(e)) => return Poll::Ready(Err(io::Error::other(e))),
            None => {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "H2 stream closed",
                )))
            }
        };
        if n == 0 {
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        self.send
            .send_data(Bytes::copy_from_slice(&buf[..n]), false)
            .map_err(io::Error::other)?;
        Poll::Ready(Ok(n))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        if !self.closed {
            self.send
                .send_data(Bytes::new(), true)
                .map_err(io::Error::other)?;
            self.closed = true;
        }
        Poll::Ready(Ok(()))
    }
}
impl Drop for H2Io {
    fn drop(&mut self) {
        if !self.closed {
            self.send.send_reset(h2::Reason::CANCEL);
        }
    }
}
