//! Demand-driven VMess records: no worker tasks or plaintext duplex queues.

use super::{
    body::BodyCipher,
    header::{self, Security},
};
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{ready, Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

#[derive(Clone, Copy)]
enum ReadState {
    HeaderLength,
    HeaderBody(usize),
    Length,
    Body(usize),
    Plaintext,
    Eof,
}

type Transport = crate::record_io::RecordIo<Box<dyn rill_transport::Stream>>;

pub(super) struct VmessConn {
    inner: Option<Transport>,
    read_cipher: BodyCipher,
    write_cipher: BodyCipher,
    response_key: [u8; 16],
    response_iv: [u8; 16],
    response_v: u8,
    state: ReadState,
    header_length: [u8; 18],
    length: [u8; 2],
    read_buf: Vec<u8>,
    read_pos: usize,
    write_pos: usize,
    write_closed: bool,
    shutdown_deadline: Option<Pin<Box<tokio::time::Sleep>>>,
}

fn closed() -> io::Error {
    io::ErrorKind::BrokenPipe.into()
}
fn truncated() -> io::Error {
    io::Error::new(io::ErrorKind::UnexpectedEof, "vmess: truncated record")
}

fn poll_fill<S: AsyncRead + Unpin>(
    stream: &mut S,
    cx: &mut Context<'_>,
    buf: &mut [u8],
    pos: &mut usize,
) -> Poll<io::Result<bool>> {
    while *pos < buf.len() {
        let mut read = ReadBuf::new(&mut buf[*pos..]);
        ready!(Pin::new(&mut *stream).poll_read(cx, &mut read))?;
        let n = read.filled().len();
        if n == 0 {
            return Poll::Ready(Ok(false));
        }
        *pos += n;
    }
    Poll::Ready(Ok(true))
}

impl VmessConn {
    pub(super) fn new(
        stream: Box<dyn rill_transport::Stream>,
        security: Security,
        key: [u8; 16],
        iv: [u8; 16],
        response_v: u8,
    ) -> Self {
        let (response_key, response_iv) = header::response_body_keys(&key, &iv);
        Self {
            inner: Some(crate::record_io::RecordIo::new(stream)),
            read_cipher: BodyCipher::from_response_keys(security, &response_key, &response_iv),
            write_cipher: BodyCipher::new_writer(security, &key, &iv),
            response_key,
            response_iv,
            response_v,
            state: ReadState::HeaderLength,
            header_length: [0; 18],
            length: [0; 2],
            read_buf: Vec::new(),
            read_pos: 0,
            write_pos: 0,
            write_closed: false,
            shutdown_deadline: None,
        }
    }

    fn fail(&mut self, error: &io::Error) {
        if self.inner.take().is_some() {
            tracing::warn!(%error, "vmess: record stream closed");
        }
        self.state = ReadState::Eof;
    }

    fn poll_drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let inner = self.inner.as_mut().ok_or_else(closed)?;
        let frame = self.write_cipher.pending_record();
        while self.write_pos < frame.len() {
            let n = ready!(Pin::new(&mut *inner).poll_write(cx, &frame[self.write_pos..]))?;
            if n == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            self.write_pos += n;
        }
        self.write_cipher.finish_record();
        self.write_pos = 0;
        Poll::Ready(Ok(()))
    }

    fn poll_flush_inner(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        ready!(self.poll_drain(cx))?;
        Pin::new(self.inner.as_mut().ok_or_else(closed)?).poll_flush(cx)
    }

    fn poll_read_inner(
        &mut self,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // A pending upload must not prevent downloads from freeing peer buffers.
        if !self.write_closed {
            if let Poll::Ready(Err(error)) = self.poll_flush_inner(cx) {
                return Poll::Ready(Err(error));
            }
        }
        let mut empty_records = 0;
        loop {
            let inner = self.inner.as_mut().ok_or_else(closed)?;
            match self.state {
                ReadState::HeaderLength => {
                    if !ready!(poll_fill(
                        inner,
                        cx,
                        &mut self.header_length,
                        &mut self.read_pos
                    ))? {
                        return Poll::Ready(Err(truncated()));
                    }
                    let len = header::open_response_length(
                        &mut self.header_length,
                        &self.response_key,
                        &self.response_iv,
                    )?;
                    self.read_buf.resize(len + 16, 0);
                    self.read_pos = 0;
                    self.state = ReadState::HeaderBody(len + 16);
                }
                ReadState::HeaderBody(len) => {
                    if !ready!(poll_fill(
                        inner,
                        cx,
                        &mut self.read_buf[..len],
                        &mut self.read_pos
                    ))? {
                        return Poll::Ready(Err(truncated()));
                    }
                    header::open_response_header(
                        &mut self.read_buf,
                        &self.response_key,
                        &self.response_iv,
                        self.response_v,
                    )?;
                    self.read_buf.clear();
                    self.read_pos = 0;
                    self.state = ReadState::Length;
                }
                ReadState::Length => {
                    if !ready!(poll_fill(inner, cx, &mut self.length, &mut self.read_pos))? {
                        if self.read_pos != 0 {
                            return Poll::Ready(Err(truncated()));
                        }
                        self.state = ReadState::Eof;
                        return Poll::Ready(Ok(()));
                    }
                    let len = usize::from(u16::from_be_bytes(self.length));
                    if len == 0 {
                        self.state = ReadState::Eof;
                        return Poll::Ready(Ok(()));
                    }
                    self.read_buf.resize(len, 0);
                    self.read_pos = 0;
                    self.state = ReadState::Body(len);
                }
                ReadState::Body(len) => {
                    if !ready!(poll_fill(
                        inner,
                        cx,
                        &mut self.read_buf[..len],
                        &mut self.read_pos
                    ))? {
                        return Poll::Ready(Err(truncated()));
                    }
                    self.read_cipher.open_record(&mut self.read_buf)?;
                    self.read_pos = 0;
                    self.state = ReadState::Plaintext;
                }
                ReadState::Plaintext => {
                    let n = out.remaining().min(self.read_buf.len() - self.read_pos);
                    out.put_slice(&self.read_buf[self.read_pos..self.read_pos + n]);
                    self.read_pos += n;
                    if self.read_pos == self.read_buf.len() {
                        self.read_pos = 0;
                        self.state = ReadState::Length;
                    }
                    if n != 0 {
                        if n < 8192 || out.remaining() == 0 {
                            return Poll::Ready(Ok(()));
                        }
                        continue;
                    }
                    empty_records += 1;
                    if empty_records == 32 {
                        cx.waker().wake_by_ref();
                        return Poll::Pending;
                    }
                }
                ReadState::Eof => return Poll::Ready(Ok(())),
            }
        }
    }
}

impl AsyncRead for VmessConn {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if out.remaining() == 0 || matches!(this.state, ReadState::Eof) {
            return Poll::Ready(Ok(()));
        }
        let start = out.filled().len();
        match this.poll_read_inner(cx, out) {
            Poll::Pending if out.filled().len() != start => Poll::Ready(Ok(())),
            Poll::Ready(Err(error)) => {
                // Preserve the task-backed stream's fatal-read EOF contract;
                // retiring the transport also makes subsequent uploads fail.
                this.fail(&error);
                Poll::Ready(Ok(()))
            }
            result => result,
        }
    }
}

impl AsyncWrite for VmessConn {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.write_closed {
            return Poll::Ready(Err(closed()));
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        ready!(this.poll_drain(cx))?;
        let n = buf.len().min(BodyCipher::max_plaintext());
        this.write_cipher.prepare_record(&buf[..n])?;
        // The bounded frame owns accepted plaintext under backpressure.
        // Retry it before consuming any subsequent application bytes.
        if let Poll::Ready(Err(error)) = this.poll_drain(cx) {
            this.fail(&error);
            return Poll::Ready(Err(error));
        }
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut().poll_flush_inner(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.write_closed {
            return Poll::Ready(Ok(()));
        }
        let result = match this.poll_flush_inner(cx) {
            Poll::Ready(Ok(())) => {
                Pin::new(this.inner.as_mut().ok_or_else(closed)?).poll_shutdown(cx)
            }
            result => result,
        };
        match result {
            Poll::Ready(Ok(())) => {
                this.write_closed = true;
                this.shutdown_deadline = None;
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(error)) => {
                this.fail(&error);
                Poll::Ready(Err(error))
            }
            Poll::Pending => {
                let deadline = this
                    .shutdown_deadline
                    .get_or_insert_with(|| Box::pin(tokio::time::sleep(Duration::from_secs(30))));
                if deadline.as_mut().poll(cx).is_ready() {
                    let error =
                        io::Error::new(io::ErrorKind::TimedOut, "vmess: shutdown drain timed out");
                    this.fail(&error);
                    Poll::Ready(Err(error))
                } else {
                    Poll::Pending
                }
            }
        }
    }
}

impl rill_common::ProxyConn for VmessConn {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::poll_fn;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn client(stream: tokio::io::DuplexStream) -> VmessConn {
        VmessConn::new(
            Box::new(stream),
            Security::Aes128Gcm,
            [17; 16],
            [34; 16],
            90,
        )
    }

    async fn response(payloads: &[&[u8]]) -> Vec<u8> {
        let mut wire = header::tests::seal_response_header(&[17; 16], &[34; 16], 90);
        let mut cipher = BodyCipher::server_mirror(Security::Aes128Gcm, &[17; 16], &[34; 16]);
        for payload in payloads {
            cipher.write_record(&mut wire, payload).await.unwrap();
        }
        wire
    }

    #[tokio::test]
    async fn fragmented_header_and_body_survive_cancelled_reads() {
        let (a, mut b) = tokio::io::duplex(1);
        let mut app = client(a);
        let payload: Vec<u8> = (0..4096).map(|i| (i % 251) as u8).collect();
        let wire = response(&[&payload]).await;
        let sender = tokio::spawn(async move {
            for byte in wire {
                b.write_all(&[byte]).await.unwrap();
                tokio::task::yield_now().await;
            }
            b.shutdown().await.unwrap();
        });
        let receive = async {
            let mut received = Vec::new();
            loop {
                let mut byte = [0];
                let result = poll_fn(|cx| {
                    let mut out = ReadBuf::new(&mut byte);
                    Poll::Ready(
                        Pin::new(&mut app)
                            .poll_read(cx, &mut out)
                            .map_ok(|()| out.filled().len()),
                    )
                })
                .await;
                match result {
                    Poll::Pending => tokio::task::yield_now().await,
                    Poll::Ready(Ok(0)) => break,
                    Poll::Ready(Ok(_)) => received.push(byte[0]),
                    Poll::Ready(Err(e)) => panic!("{e}"),
                }
            }
            assert_eq!(received, payload);
        };
        tokio::time::timeout(Duration::from_secs(3), receive)
            .await
            .unwrap();
        sender.await.unwrap();
    }

    #[tokio::test]
    async fn available_bulk_records_coalesce_without_waiting_for_more() {
        let (a, mut b) = tokio::io::duplex(65536);
        let mut app = client(a);
        let payload = vec![42; BodyCipher::max_plaintext()];
        b.write_all(&response(&[&payload, &payload]).await)
            .await
            .unwrap();
        let mut received = vec![0; 65536];
        let n = tokio::time::timeout(Duration::from_secs(1), app.read(&mut received))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(n, payload.len() * 2);
        assert_eq!(&received[..n], payload.repeat(2));
        let mut byte = [0];
        assert!(
            tokio::time::timeout(Duration::from_millis(10), app.read(&mut byte))
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn backpressured_upload_still_allows_a_download() {
        let (a, mut b) = tokio::io::duplex(32);
        let mut app = client(a);
        app.write_all(&vec![1; BodyCipher::max_plaintext()])
            .await
            .unwrap();
        let wire = response(&[b"reply"]).await;
        let send = async {
            b.write_all(&wire).await.unwrap();
        };
        let recv = async {
            let mut data = [0; 5];
            app.read_exact(&mut data).await.unwrap();
            assert_eq!(&data, b"reply");
        };
        tokio::time::timeout(Duration::from_secs(1), async {
            tokio::join!(send, recv);
        })
        .await
        .unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn shutdown_of_a_wedged_writer_has_a_deadline() {
        let (a, _b) = tokio::io::duplex(1);
        let mut app = client(a);
        app.write_all(b"pending payload").await.unwrap();
        let error = app.shutdown().await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(app.inner.is_none());
    }
}
