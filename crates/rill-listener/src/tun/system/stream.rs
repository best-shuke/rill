//! Join kernel and lwIP accepts before the common TUN routing path.

use std::io;
use std::net::SocketAddr;

use futures::StreamExt;
use rill_common::ProxyConn;

use super::{Lease, System};

pub(in crate::tun) enum TcpStream {
    Lwip(lwip::TcpStream),
    #[cfg(target_os = "linux")]
    Kernel(tokio::net::TcpStream, Lease),
}

impl TcpStream {
    pub async fn sniff(&mut self) -> io::Result<Vec<u8>> {
        match self {
            Self::Lwip(stream) => super::super::sniff_first_payload(stream).await,
            #[cfg(target_os = "linux")]
            Self::Kernel(stream, _) => {
                // Preserve the plain TcpStream and leave the first bytes
                // in its receive queue for sniffing/routing and splice.
                let mut buf = [0; super::super::TUN_FIRST_READ];
                match tokio::time::timeout(super::super::TUN_SNIFF_WINDOW, stream.peek(&mut buf))
                    .await
                {
                    Ok(Ok(0)) => Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "peer closed before sending payload",
                    )),
                    Ok(Err(e)) => Err(e),
                    Ok(Ok(_)) | Err(_) => Ok(Vec::new()),
                }
            }
        }
    }

    pub fn into_connection(self, prefix: Vec<u8>) -> (Box<dyn ProxyConn>, Option<Lease>) {
        match self {
            Self::Lwip(stream) => (
                Box::new(super::super::TunTcpConn {
                    prefix,
                    pos: 0,
                    inner: std::sync::Mutex::new(stream),
                }),
                None,
            ),
            #[cfg(target_os = "linux")]
            Self::Kernel(stream, lease) => (Box::new(stream), Some(lease)),
        }
    }
}

pub(in crate::tun) async fn accept_tcp(
    lwip: &mut lwip::TcpListener,
    system: Option<&System>,
) -> io::Result<(TcpStream, SocketAddr, SocketAddr)> {
    let kernel = async {
        #[cfg(target_os = "linux")]
        if let Some(system) = system {
            let (stream, flow, lease) = system.accept().await?;
            return Ok((TcpStream::Kernel(stream, lease), flow.src, flow.dst));
        }
        #[cfg(not(target_os = "linux"))]
        let _ = system;
        std::future::pending().await
    };
    tokio::select! {
        result = kernel => result,
        accepted = lwip.next() => accepted
            .map(|(stream, src, dst)| (TcpStream::Lwip(stream), src, dst))
            .ok_or_else(|| io::Error::other("netstack TCP listener closed")),
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use crate::tun::system::nat::{Flow, Nat};
    use parking_lot::Mutex;
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn pair() -> (tokio::net::TcpStream, TcpStream) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client = tokio::net::TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (stream, src) = listener.accept().await.unwrap();
        let nat = Arc::new(Mutex::new(Nat::new()));
        let flow = Flow {
            src,
            dst: "198.18.1.2:443".parse().unwrap(),
        };
        let port = nat
            .lock()
            .port(flow, true, std::time::Instant::now())
            .unwrap();
        let (_, lease) = Nat::accept(&nat, port).unwrap();
        (client, TcpStream::Kernel(stream, lease))
    }

    #[tokio::test]
    async fn kernel_sniff_preserves_payload_for_plain_stream_relay() {
        let (mut client, mut stream) = pair().await;
        client.write_all(b"first payload").await.unwrap();
        let prefix = stream.sniff().await.unwrap();
        assert!(prefix.is_empty());
        let (mut conn, _lease) = stream.into_connection(prefix);
        let mut payload = [0; 13];
        conn.read_exact(&mut payload).await.unwrap();
        assert_eq!(&payload, b"first payload");
    }

    #[tokio::test]
    async fn kernel_silence_keeps_server_first_connection_usable() {
        let (mut client, mut stream) = pair().await;
        assert!(stream.sniff().await.unwrap().is_empty());
        let (mut conn, _lease) = stream.into_connection(Vec::new());
        conn.write_all(b"banner").await.unwrap();
        let mut banner = [0; 6];
        client.read_exact(&mut banner).await.unwrap();
        assert_eq!(&banner, b"banner");
    }

    #[tokio::test]
    async fn kernel_eof_before_payload_is_dropped() {
        let (client, mut stream) = pair().await;
        drop(client);
        assert_eq!(
            stream.sniff().await.unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );
    }
}
