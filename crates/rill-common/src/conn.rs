use crate::error::Result;
use bytes::Bytes;
use std::net::SocketAddr;
use tokio::io::{AsyncRead, AsyncWrite};

pub trait ProxyConn: AsyncRead + AsyncWrite + Unpin + Send + Sync {
    /// Opt into kernel TCP relaying. Return `Some` only for an unbuffered,
    /// untransformed stream: bypassing `AsyncRead`/`AsyncWrite` must be safe.
    fn as_tcp_stream(&self) -> Option<&tokio::net::TcpStream> {
        None
    }

    fn remote_destination(&self) -> String {
        String::new()
    }
}

impl ProxyConn for tokio::net::TcpStream {
    fn as_tcp_stream(&self) -> Option<&tokio::net::TcpStream> {
        Some(self)
    }
}

// Impl for Box<dyn ProxyConn>
impl<T: ProxyConn + ?Sized> ProxyConn for Box<T> {
    fn as_tcp_stream(&self) -> Option<&tokio::net::TcpStream> {
        (**self).as_tcp_stream()
    }
}

#[async_trait::async_trait]
pub trait ProxyPacketConn: Send + Sync {
    /// Per-packet conns return the real wire source; bound conns may
    /// report the bound remote or an unspecified address when the
    /// underlying transport carries no source information. Consumers
    /// filtering on the source must skip the check for unspecified
    /// addresses or they would wedge bound conns.
    async fn read_packet(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr)>;
    async fn write_packet(&self, buf: &[u8], addr: &SocketAddr) -> Result<usize>;
    fn local_addr(&self) -> Result<SocketAddr>;
    fn close(&self) -> Result<()>;
}

pub struct UdpPacket {
    pub data: Bytes,
    pub addr: SocketAddr,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn boxed_plain_tcp_preserves_kernel_socket_access() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (client, accepted) =
            tokio::join!(tokio::net::TcpStream::connect(addr), listener.accept());
        let _accepted = accepted.unwrap();
        let client = client.unwrap();
        assert!(std::ptr::eq(client.as_tcp_stream().unwrap(), &client));
        let conn: Box<dyn ProxyConn> = Box::new(client);
        let nested: Box<dyn ProxyConn> = Box::new(conn);
        assert_eq!(nested.as_tcp_stream().unwrap().peer_addr().unwrap(), addr);
    }
}
