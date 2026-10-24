use std::net::SocketAddr;
use tokio::net::TcpStream;

use crate::socks5_client::{socks5_connect, CONNECT_TIMEOUT};

/// How a workload reaches its echo target through the proxy under test.
#[derive(Debug, Clone, Copy)]
pub enum Dial {
    /// SOCKS5 CONNECT through the proxy's mixed listener (W1–W3).
    Socks5(SocketAddr),
    /// Plain TCP connect: the kernel routes the target into the proxy.
    /// The `tun` workload dials a fake IP whose range is routed into the
    /// TUN device, so every byte crosses the proxy's userspace stack.
    #[cfg_attr(
        not(target_os = "linux"),
        allow(dead_code, reason = "only the Linux-only tun workload dials directly")
    )]
    Direct,
}

impl Dial {
    pub async fn connect(self, target: SocketAddr) -> std::io::Result<TcpStream> {
        match self {
            Dial::Socks5(proxy) => socks5_connect(proxy, target).await,
            Dial::Direct => tokio::time::timeout(CONNECT_TIMEOUT, async {
                let stream = TcpStream::connect(target).await?;
                // Same Nagle/delayed-ACK guard as the SOCKS5 path.
                stream.set_nodelay(true)?;
                Ok(stream)
            })
            .await
            .map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    format!("connect to {target} timed out"),
                )
            })?,
        }
    }
}
