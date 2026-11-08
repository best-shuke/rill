//! V2Ray's HTTP header camouflage for raw TCP (`network: http`).
//!
//! The first write goes out as the body of a fake HTTP/1.1 request (method,
//! a random path from the list, `Host` and the configured headers); the
//! first read discards the server's HTTP response line and headers. Every
//! byte after that passes through untouched.
//!
//! upstream: `transport/vmess/http.go`

use std::pin::Pin;
use std::task::{Context, Poll};

use async_trait::async_trait;
use rand::Rng;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::{Result, Stream, Transport};

/// Response headers larger than this are taken for a broken peer.
const MAX_RESPONSE_HEADER: usize = 64 * 1024;

/// `http-opts` of a VMess node.
#[derive(Debug, Clone)]
pub struct HttpHeaderConfig {
    /// Request method; `GET` when empty.
    pub method: String,
    /// `Host` when `headers` has none: the server address.
    pub host: String,
    /// Candidate request paths; one is picked per connection (`/` if none).
    pub paths: Vec<String>,
    /// Header name → candidate values; one value is picked per connection.
    pub headers: Vec<(String, Vec<String>)>,
}

pub struct HttpHeaderLayer {
    config: std::sync::Arc<HttpHeaderConfig>,
}

impl HttpHeaderLayer {
    pub fn new(config: HttpHeaderConfig) -> Self {
        Self {
            config: std::sync::Arc::new(config),
        }
    }
}

#[async_trait]
impl Transport for HttpHeaderLayer {
    async fn connect(&self, inner: Box<dyn Stream>) -> Result<Box<dyn Stream>> {
        Ok(Box::new(HttpHeaderStream {
            inner,
            config: std::sync::Arc::clone(&self.config),
            write: WriteState::Handshake,
            read: ReadState::Header(Vec::new()),
        }))
    }
}

fn pick<'a>(list: &'a [String], rng: &mut impl Rng) -> Option<&'a str> {
    if list.is_empty() {
        None
    } else {
        Some(&list[rng.random_range(0..list.len())])
    }
}

/// The request head for a first write of `body_len` bytes.
fn request_head(config: &HttpHeaderConfig, body_len: usize) -> Vec<u8> {
    let mut rng = rand::rng();
    let method = if config.method.is_empty() {
        "GET"
    } else {
        &config.method
    };
    let path = pick(&config.paths, &mut rng).unwrap_or("/");
    let host = config
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("host"))
        .and_then(|(_, v)| pick(v, &mut rng))
        .unwrap_or(&config.host);
    let mut head = format!("{method} {path} HTTP/1.1\r\nHost: {host}\r\n");
    for (name, values) in &config.headers {
        if name.eq_ignore_ascii_case("host") || name.eq_ignore_ascii_case("content-length") {
            continue;
        }
        if let Some(value) = pick(values, &mut rng) {
            head.push_str(name);
            head.push_str(": ");
            head.push_str(value);
            head.push_str("\r\n");
        }
    }
    head.push_str("Content-Length: ");
    head.push_str(&body_len.to_string());
    head.push_str("\r\n\r\n");
    head.into_bytes()
}

enum WriteState {
    Handshake,
    /// The request (head + first payload) is being written; `body_len`
    /// bytes of the caller's buffer are reported once it all went out.
    Sending {
        buf: Vec<u8>,
        pos: usize,
        body_len: usize,
    },
    Passthrough,
}

enum ReadState {
    /// Bytes of the response head read so far.
    Header(Vec<u8>),
    /// Bytes after the head that arrived with it, then the raw stream.
    Leftover(Vec<u8>, usize),
    Passthrough,
}

struct HttpHeaderStream {
    inner: Box<dyn Stream>,
    config: std::sync::Arc<HttpHeaderConfig>,
    write: WriteState,
    read: ReadState,
}

impl AsyncRead for HttpHeaderStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        loop {
            match &mut this.read {
                ReadState::Passthrough => return Pin::new(&mut this.inner).poll_read(cx, out),
                ReadState::Leftover(buf, pos) => {
                    let n = (buf.len() - *pos).min(out.remaining());
                    out.put_slice(&buf[*pos..*pos + n]);
                    *pos += n;
                    if *pos == buf.len() {
                        this.read = ReadState::Passthrough;
                    }
                    return Poll::Ready(Ok(()));
                }
                ReadState::Header(head) => {
                    let mut chunk = [0u8; 4096];
                    let mut rb = ReadBuf::new(&mut chunk);
                    std::task::ready!(Pin::new(&mut this.inner).poll_read(cx, &mut rb))?;
                    let got = rb.filled();
                    if got.is_empty() {
                        return Poll::Ready(Err(std::io::Error::new(
                            std::io::ErrorKind::UnexpectedEof,
                            "http header camouflage: connection closed in the response head",
                        )));
                    }
                    let scan_from = head.len().saturating_sub(3);
                    head.extend_from_slice(got);
                    if let Some(end) = head[scan_from..]
                        .windows(4)
                        .position(|w| w == b"\r\n\r\n")
                        .map(|i| scan_from + i + 4)
                    {
                        let rest = head.split_off(end);
                        this.read = if rest.is_empty() {
                            ReadState::Passthrough
                        } else {
                            ReadState::Leftover(rest, 0)
                        };
                        continue;
                    }
                    if head.len() > MAX_RESPONSE_HEADER {
                        return Poll::Ready(Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "http header camouflage: response head too large",
                        )));
                    }
                }
            }
        }
    }
}

impl AsyncWrite for HttpHeaderStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        loop {
            match &mut this.write {
                WriteState::Passthrough => return Pin::new(&mut this.inner).poll_write(cx, data),
                WriteState::Handshake => {
                    let mut buf = request_head(&this.config, data.len());
                    buf.extend_from_slice(data);
                    this.write = WriteState::Sending {
                        buf,
                        pos: 0,
                        body_len: data.len(),
                    };
                }
                WriteState::Sending { buf, pos, body_len } => {
                    while *pos < buf.len() {
                        let n = std::task::ready!(
                            Pin::new(&mut this.inner).poll_write(cx, &buf[*pos..])
                        )?;
                        if n == 0 {
                            return Poll::Ready(Err(std::io::ErrorKind::WriteZero.into()));
                        }
                        *pos += n;
                    }
                    let n = *body_len;
                    this.write = WriteState::Passthrough;
                    return Poll::Ready(Ok(n));
                }
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn first_write_is_a_request_and_first_read_skips_the_response_head() {
        let (client, mut server) = tokio::io::duplex(1 << 16);
        let layer = HttpHeaderLayer::new(HttpHeaderConfig {
            method: String::new(),
            host: "1.2.3.4".into(),
            paths: vec!["/a".into()],
            headers: vec![
                ("Host".into(), vec!["www.example.com".into()]),
                ("Connection".into(), vec!["keep-alive".into()]),
            ],
        });
        let mut stream = layer.connect(Box::new(client)).await.unwrap();
        stream.write_all(b"hello").await.unwrap();
        stream.write_all(b" world").await.unwrap();

        let mut got = vec![0u8; 512];
        let n = server.read(&mut got).await.unwrap();
        let text = String::from_utf8_lossy(&got[..n]).to_string();
        assert!(
            text.starts_with("GET /a HTTP/1.1\r\nHost: www.example.com\r\n"),
            "{text}"
        );
        assert!(text.contains("Connection: keep-alive\r\n"));
        assert!(text.contains("Content-Length: 5\r\n\r\nhello"), "{text}");

        server
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\npayload")
            .await
            .unwrap();
        let mut buf = [0u8; 7];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"payload");
        server.write_all(b"-more").await.unwrap();
        let mut more = [0u8; 5];
        stream.read_exact(&mut more).await.unwrap();
        assert_eq!(&more, b"-more");
    }
}
