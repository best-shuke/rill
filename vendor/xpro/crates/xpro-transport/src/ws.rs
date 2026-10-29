use crate::Io;
use bytes::{Buf, Bytes};
use futures_util::{Sink, Stream};
use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    time::{Instant, Sleep},
};
use tokio_tungstenite::{
    tungstenite::{protocol::WebSocketConfig, Message},
    WebSocketStream,
};
use xpro_protocol::invalid;
pub fn ws_config() -> WebSocketConfig {
    WebSocketConfig::default()
        .max_message_size(Some(64 * 1024))
        .max_frame_size(Some(64 * 1024))
        .write_buffer_size(0)
        .max_write_buffer_size(128 * 1024)
}
/// Binary messages form a byte stream; TLS record and message boundaries are independent.
#[derive(Clone, Copy, Debug)]
pub struct Heartbeat {
    pub idle: Duration,
    pub timeout: Duration,
}
impl Default for Heartbeat {
    fn default() -> Self {
        Self {
            idle: Duration::from_secs(30),
            timeout: Duration::from_secs(15),
        }
    }
}
impl Heartbeat {
    pub fn validate(self) -> io::Result<()> {
        if self.idle.is_zero()
            || self.timeout.is_zero()
            || self.idle > Duration::from_secs(3600)
            || self.timeout > Duration::from_secs(3600)
        {
            Err(invalid(
                "heartbeat durations must be between 0 and 3600 seconds",
            ))
        } else {
            Ok(())
        }
    }
}
pub struct WsIo<S> {
    ws: WebSocketStream<S>,
    pending: Bytes,
    timer: Pin<Box<Sleep>>,
    pong_deadline: Option<Instant>,
    need_ping: bool,
    heartbeat: Heartbeat,
}
impl<S> WsIo<S> {
    pub fn new(ws: WebSocketStream<S>) -> Self {
        Self::with_heartbeat(ws, Heartbeat::default())
    }
    pub fn with_heartbeat(ws: WebSocketStream<S>, heartbeat: Heartbeat) -> Self {
        Self {
            heartbeat,
            ws,
            pending: Bytes::new(),
            timer: Box::pin(tokio::time::sleep(heartbeat.idle)),
            pong_deadline: None,
            need_ping: false,
        }
    }
}
impl<S: Io> WsIo<S> {
    fn housekeeping(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.timer.as_mut().poll(cx).is_ready() {
            if self.pong_deadline.is_some() {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "WebSocket heartbeat timed out",
                )));
            }
            self.need_ping = true;
        }
        if self.need_ping {
            std::task::ready!(Pin::new(&mut self.ws).poll_ready(cx)).map_err(io::Error::other)?;
            Pin::new(&mut self.ws)
                .start_send(Message::Ping(Bytes::from_static(b"xpro")))
                .map_err(io::Error::other)?;
            self.need_ping = false;
            let deadline = Instant::now() + self.heartbeat.timeout;
            self.pong_deadline = Some(deadline);
            self.timer.as_mut().reset(deadline);
        }
        std::task::ready!(Pin::new(&mut self.ws).poll_flush(cx)).map_err(io::Error::other)?;
        Poll::Ready(Ok(()))
    }
    fn activity(&mut self) {
        if self.pong_deadline.is_none() {
            self.timer
                .as_mut()
                .reset(Instant::now() + self.heartbeat.idle);
        }
    }
}
use std::future::Future;
impl<S: Io> AsyncRead for WsIo<S> {
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
                return Poll::Ready(Ok(()));
            }
            // Continue polling reads even if a control frame write is backpressured.
            if let Poll::Ready(Err(e)) = self.housekeeping(cx) {
                return Poll::Ready(Err(e));
            }
            match std::task::ready!(Pin::new(&mut self.ws).poll_next(cx)) {
                Some(Ok(Message::Binary(v))) => {
                    self.activity();
                    self.pending = v;
                }
                Some(Ok(Message::Ping(_))) => {
                    self.activity();
                }
                Some(Ok(Message::Pong(v))) => {
                    if v.as_ref() == b"xpro" {
                        self.pong_deadline = None;
                        self.activity();
                    }
                }
                Some(Ok(Message::Close(_))) | None => return Poll::Ready(Ok(())),
                Some(Ok(_)) => {
                    return Poll::Ready(Err(invalid("WebSocket requires binary messages")))
                }
                Some(Err(e)) => return Poll::Ready(Err(io::Error::other(e))),
            }
        }
    }
}
impl<S: Io> AsyncWrite for WsIo<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        std::task::ready!(self.housekeeping(cx))?;
        std::task::ready!(Pin::new(&mut self.ws).poll_ready(cx)).map_err(io::Error::other)?;
        let n = buf.len().min(16384);
        Pin::new(&mut self.ws)
            .start_send(Message::Binary(Bytes::copy_from_slice(&buf[..n])))
            .map_err(io::Error::other)?;
        self.activity();
        Poll::Ready(Ok(n))
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.ws)
            .poll_flush(cx)
            .map_err(io::Error::other)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.ws)
            .poll_close(cx)
            .map_err(io::Error::other)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::SinkExt;
    use tokio::io::AsyncReadExt;
    use tokio_tungstenite::tungstenite::protocol::Role;

    #[tokio::test(start_paused = true)]
    async fn idle_peer_without_pong_times_out() {
        let (a, _b) = tokio::io::duplex(4096);
        let ws = WebSocketStream::from_raw_socket(a, Role::Client, Some(ws_config())).await;
        let mut stream = WsIo::new(ws);
        let job = tokio::spawn(async move { stream.read_u8().await });
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(30)).await;
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(15)).await;
        assert_eq!(
            job.await.unwrap().unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
    }
    #[tokio::test]
    async fn binary_messages_are_an_ordered_byte_stream_and_text_is_rejected() {
        let (a, b) = tokio::io::duplex(4096);
        let client = WebSocketStream::from_raw_socket(a, Role::Client, Some(ws_config())).await;
        let mut server = WebSocketStream::from_raw_socket(b, Role::Server, Some(ws_config())).await;
        let mut stream = WsIo::new(client);
        server
            .send(Message::Binary(Bytes::from_static(b"a")))
            .await
            .unwrap();
        server
            .send(Message::Binary(Bytes::from_static(b"bcdef")))
            .await
            .unwrap();
        let mut bytes = [0; 6];
        stream.read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes, b"abcdef");
        server
            .send(Message::Text("not a TLS byte stream".into()))
            .await
            .unwrap();
        assert_eq!(
            stream.read_u8().await.unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }
}
