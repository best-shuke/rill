//! A bounded, lazy second worker for CPU-bound full-duplex SS streams.
//!
//! The public shadowsocks codecs retain salt replay checks, framing and AEAD
//! authentication. Short and idle streams run inline; only established bulk
//! downloads split the TCP socket and move their existing decoder to a worker.

use crate::record_io::RecordIo;
use shadowsocks::config::ServerConfig;
use shadowsocks::context::SharedContext;
use shadowsocks::relay::tcprelay::crypto_io::{DecryptedReader, EncryptedWriter, StreamType};
use shadowsocks::relay::Address;
use std::future::poll_fn;
use std::io;
use std::pin::Pin;
use std::task::{ready, Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{tcp::OwnedWriteHalf, TcpStream};
use tokio::sync::{mpsc, Semaphore};
use tokio::task::JoinHandle;

const BULK_THRESHOLD: usize = 2 * 1024 * 1024;
const CHUNK: usize = 128 * 1024;
// Leave cores for the relay writers, DNS, and latency-sensitive connections.
static READ_WORKERS: Semaphore = Semaphore::const_new(4);

enum Transport {
    Inline(RecordIo<TcpStream>),
    Split(RecordIo<OwnedWriteHalf>),
}

enum WriteState {
    Address(Address),
    Connecting(bytes::BytesMut, usize),
    Connected,
}

struct Download {
    task: JoinHandle<()>,
    ready: mpsc::Receiver<io::Result<Vec<u8>>>,
    recycle: mpsc::Sender<Vec<u8>>,
    current: Vec<u8>,
    pos: usize,
}

impl Drop for Download {
    fn drop(&mut self) {
        self.task.abort();
    }
}

pub(super) struct PlainAeadConn {
    io: Option<Transport>,
    reader: Option<DecryptedReader>,
    writer: EncryptedWriter,
    context: SharedContext,
    state: WriteState,
    received: usize,
    download: Option<Box<Download>>,
}

impl PlainAeadConn {
    pub(super) fn new(
        stream: TcpStream,
        context: SharedContext,
        config: &ServerConfig,
        address: Address,
    ) -> Self {
        let method = config.method();
        debug_assert_eq!(method, shadowsocks::crypto::CipherKind::CHACHA20_POLY1305);
        let mut salt = [0; 32];
        context.generate_nonce(method, &mut salt, true);
        Self {
            io: Some(Transport::Inline(RecordIo::new(stream))),
            reader: Some(DecryptedReader::new(
                StreamType::Client,
                method,
                config.key(),
            )),
            writer: EncryptedWriter::new(StreamType::Client, method, config.key(), &salt),
            context,
            state: WriteState::Address(address),
            received: 0,
            download: None,
        }
    }

    fn promote(&mut self) {
        if self.received < BULK_THRESHOLD || self.download.is_some() {
            return;
        }
        let Ok(permit) = READ_WORKERS.try_acquire() else {
            return;
        };
        let Some(Transport::Inline(transport)) = self.io.take() else {
            unreachable!("unpromoted connection owns its TCP transport");
        };
        let (mut stream, writer) = transport.into_split();
        self.io = Some(Transport::Split(writer));
        let mut reader = self.reader.take().expect("unpromoted decoder");
        let context = std::sync::Arc::clone(&self.context);
        let (send, ready) = mpsc::channel(1);
        let (recycle, mut recycled) = mpsc::channel::<Vec<u8>>(2);
        let task = tokio::spawn(async move {
            let _permit = permit;
            let mut failure = None;
            loop {
                if let Some(error) = failure.take() {
                    let _ = send.send(Err(error)).await;
                    break;
                }
                let mut data = recycled.try_recv().unwrap_or_else(|_| vec![0; CHUNK]);
                data.resize(CHUNK, 0);
                let result = poll_fn(|cx| {
                    let mut out = ReadBuf::new(&mut data);
                    loop {
                        let before = out.filled().len();
                        match reader.poll_read_decrypted(cx, &context, &mut stream, &mut out) {
                            Poll::Ready(Ok(())) => {
                                if out.filled().len() == before || out.remaining() == 0 {
                                    return Poll::Ready(Ok(out.filled().len()));
                                }
                            }
                            Poll::Pending if out.filled().is_empty() => return Poll::Pending,
                            Poll::Pending => return Poll::Ready(Ok(out.filled().len())),
                            Poll::Ready(Err(e)) if !out.filled().is_empty() => {
                                failure = Some(io::Error::from(e));
                                return Poll::Ready(Ok(out.filled().len()));
                            }
                            Poll::Ready(Err(e)) => return Poll::Ready(Err(io::Error::from(e))),
                        }
                    }
                })
                .await;
                let terminal = !matches!(result, Ok(n) if n > 0);
                let message = result.map(|n| {
                    data.truncate(n);
                    data
                });
                if send.send(message).await.is_err() || terminal {
                    break;
                }
            }
        });
        self.download = Some(Box::new(Download {
            task,
            ready,
            recycle,
            current: Vec::new(),
            pos: 0,
        }));
    }

    fn poll_encrypted(&mut self, cx: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
        match self.io.as_mut().expect("live transport") {
            Transport::Inline(io) => self.writer.poll_write_encrypted(cx, io, data),
            Transport::Split(io) => self.writer.poll_write_encrypted(cx, io, data),
        }
        .map_err(Into::into)
    }
}

impl AsyncRead for PlainAeadConn {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if out.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        this.promote();
        if let Some(download) = &mut this.download {
            if download.pos == download.current.len() {
                if !download.current.is_empty() {
                    let _ = download
                        .recycle
                        .try_send(std::mem::take(&mut download.current));
                }
                // poll_recv can yield here. Leave a consistent empty state
                // before handing control back to the caller.
                download.pos = 0;
                download.current = match ready!(download.ready.poll_recv(cx)) {
                    Some(data) => data?,
                    None => return Poll::Ready(Ok(())),
                };
                download.pos = 0;
            }
            let n = out.remaining().min(download.current.len() - download.pos);
            out.put_slice(&download.current[download.pos..download.pos + n]);
            download.pos += n;
            return Poll::Ready(Ok(()));
        }
        let Some(Transport::Inline(io)) = this.io.as_mut() else {
            unreachable!("inline decoder owns inline transport");
        };
        let before = out.filled().len();
        ready!(this
            .reader
            .as_mut()
            .expect("inline decoder")
            .poll_read_decrypted(cx, &this.context, io, out))?;
        this.received = this.received.saturating_add(out.filled().len() - before);
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for PlainAeadConn {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if let WriteState::Address(address) = &this.state {
            let mut first = bytes::BytesMut::with_capacity(address.serialized_len() + data.len());
            address.write_to_buf(&mut first);
            first.extend_from_slice(data);
            this.state = WriteState::Connecting(first, data.len());
        }
        if let WriteState::Connecting(first, accepted) = &mut this.state {
            let result = match this.io.as_mut().expect("live transport") {
                Transport::Inline(io) => this.writer.poll_write_encrypted(cx, io, first),
                Transport::Split(io) => this.writer.poll_write_encrypted(cx, io, first),
            };
            ready!(result)?;
            let n = *accepted;
            this.state = WriteState::Connected;
            return Poll::Ready(Ok(n));
        }
        this.poll_encrypted(cx, data)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut().io.as_mut().expect("live transport") {
            Transport::Inline(io) => Pin::new(io).poll_flush(cx),
            Transport::Split(io) => Pin::new(io).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut().io.as_mut().expect("live transport") {
            Transport::Inline(io) => Pin::new(io).poll_shutdown(cx),
            Transport::Split(io) => Pin::new(io).poll_shutdown(cx),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shadowsocks::config::ServerType;
    use shadowsocks::context::Context as SsContext;
    use shadowsocks::relay::tcprelay::proxy_stream::ProxyServerStream;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn pair() -> (PlainAeadConn, ProxyServerStream<TcpStream>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let (client, server) = tokio::join!(
            TcpStream::connect(listener.local_addr().unwrap()),
            listener.accept()
        );
        let config = ServerConfig::new(
            ("127.0.0.1", 8388),
            "parallel-test",
            shadowsocks::crypto::CipherKind::CHACHA20_POLY1305,
        )
        .unwrap();
        let client = PlainAeadConn::new(
            client.unwrap(),
            SsContext::new_shared(ServerType::Local),
            &config,
            Address::DomainNameAddress("echo.test".into(), 443),
        );
        let server = ProxyServerStream::from_stream(
            SsContext::new_shared(ServerType::Server),
            server.unwrap().0,
            config.method(),
            config.key(),
        );
        (client, server)
    }

    #[tokio::test]
    async fn short_connection_keeps_inline_decoder() {
        let (mut client, mut server) = pair().await;
        let peer = tokio::spawn(async move {
            assert_eq!(
                server.handshake().await.unwrap(),
                Address::DomainNameAddress("echo.test".into(), 443)
            );
            let mut request = [0; 4];
            server.read_exact(&mut request).await.unwrap();
            assert_eq!(&request, b"ping");
            server.write_all(b"pong").await.unwrap();
        });
        client.write_all(b"ping").await.unwrap();
        client.flush().await.unwrap();
        let mut reply = [0; 4];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"pong");
        assert!(client.download.is_none());
        peer.await.unwrap();
    }

    #[tokio::test]
    async fn deferred_header_still_supports_server_first_protocols() {
        let (client, mut server) = pair().await;
        let mut client = super::super::SsConn::new(client);
        let peer = tokio::spawn(async move {
            server.handshake().await.unwrap();
            server.write_all(b"banner").await.unwrap();
        });
        let mut banner = [0; 6];
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            client.read_exact(&mut banner),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(&banner, b"banner");
        peer.await.unwrap();
    }

    #[tokio::test]
    async fn promotion_preserves_read_ahead_and_write_half_close() {
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            let (mut client, mut server) = pair().await;
            let peer = tokio::spawn(async move {
                server.handshake().await.unwrap();
                let mut request = Vec::new();
                server.read_to_end(&mut request).await.unwrap();
                assert_eq!(&request, b"request");
                let data: Vec<u8> = (0..(CHUNK * 3 + 77)).map(|n| n as u8).collect();
                server.write_all(&data).await.unwrap();
                server.shutdown().await.unwrap();
                data
            });
            client.write_all(b"request").await.unwrap();
            client.shutdown().await.unwrap();
            // Leave plaintext in the decoder and ciphertext in RecordIo when
            // ownership changes; neither may disappear across the split.
            let mut first = [0; 1];
            client.read_exact(&mut first).await.unwrap();
            client.received = BULK_THRESHOLD;
            let mut data = first.to_vec();
            client.read_to_end(&mut data).await.unwrap();
            assert!(client.download.is_some());
            assert_eq!(data, peer.await.unwrap());
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn dropping_promoted_connection_aborts_silent_reader() {
        let (mut client, mut server) = pair().await;
        let peer = tokio::spawn(async move {
            server.handshake().await.unwrap();
            let mut data = [0; 1];
            server.read_exact(&mut data).await.unwrap();
            server
        });
        client.write_all(b"x").await.unwrap();
        client.flush().await.unwrap();
        let mut server = peer.await.unwrap();
        client.received = BULK_THRESHOLD;
        client.promote();
        let aborted = client.download.as_ref().unwrap().task.abort_handle();
        drop(client);
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            let mut data = [0; 1];
            assert_eq!(server.read(&mut data).await.unwrap(), 0);
            while !aborted.is_finished() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn promoted_upstream_eof_keeps_upload_usable() {
        let (mut client, mut server) = pair().await;
        let peer = tokio::spawn(async move {
            server.handshake().await.unwrap();
            let mut first = [0; 1];
            server.read_exact(&mut first).await.unwrap();
            server.write_all(b"response").await.unwrap();
            server.shutdown().await.unwrap();
            let mut upload = [0; 6];
            server.read_exact(&mut upload).await.unwrap();
            assert_eq!(&upload, b"upload");
        });
        client.write_all(b"x").await.unwrap();
        client.flush().await.unwrap();
        client.received = BULK_THRESHOLD;
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        assert_eq!(&response, b"response");
        client.write_all(b"upload").await.unwrap();
        client.flush().await.unwrap();
        peer.await.unwrap();
    }

    #[tokio::test]
    async fn decoder_failure_delivers_valid_prefix_before_error() {
        let (mut client, mut server) = pair().await;
        let peer = tokio::spawn(async move {
            server.handshake().await.unwrap();
            let mut first = [0; 1];
            server.read_exact(&mut first).await.unwrap();
            server.write_all(&[0x5a; 8192]).await.unwrap();
            server.flush().await.unwrap();
            // A forged encrypted length follows a valid record.
            server.get_mut().write_all(&[0; 34]).await.unwrap();
        });
        client.write_all(b"x").await.unwrap();
        client.flush().await.unwrap();
        client.received = BULK_THRESHOLD;
        let mut response = Vec::new();
        assert!(client.read_to_end(&mut response).await.is_err());
        assert_eq!(response, vec![0x5a; 8192]);
        peer.await.unwrap();
    }
}
