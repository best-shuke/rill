//! DNS over TCP (RFC 1035 §4.2.2): what `dns.listen` serves beside UDP, as
//! mihomo does — a stub resolver retries a truncated answer over TCP — and
//! what the TUN inbound's `dns-hijack: tcp://…:53` answers.
//!
//! Each length-prefixed message is answered the way the UDP server answers a
//! datagram — locally when the resolver can decide it (hosts, fake-IP, fresh
//! cache), otherwise through [`DnsServer::handle_query`] — and the connection
//! stays open for further queries until the client closes it or goes idle.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tracing::{debug, warn};

use crate::resolver::Resolver;
use crate::server::{DnsServer, LocalAnswer, ResolverSlot};

/// A client that sends nothing for this long is done with the connection.
const IDLE: Duration = Duration::from_secs(10);

/// Connections served at once on a listen socket; beyond it new ones are
/// closed, as the UDP side drops queries past its in-flight cap.
const MAX_CONNECTIONS: usize = 256;

/// Accept and serve connections on `listener` until the future is dropped.
/// Each connection answers from the resolver generation current when it
/// was accepted.
pub(crate) async fn accept_loop(listener: TcpListener, resolver: ResolverSlot) -> Infallible {
    let connections = Arc::new(tokio::sync::Semaphore::new(MAX_CONNECTIONS));
    let mut backoff = rill_common::ErrorBackoff::new();
    loop {
        let (stream, src) = match listener.accept().await {
            Ok(accepted) => {
                backoff.succeeded();
                accepted
            }
            Err(e) => {
                if backoff.failed(&e).await {
                    warn!("DNS TCP accept error: {e}");
                }
                continue;
            }
        };
        let Ok(permit) = Arc::clone(&connections).try_acquire_owned() else {
            debug!("DNS TCP: {MAX_CONNECTIONS} connections open, closing one from {src}");
            continue;
        };
        let resolver = Arc::clone(&resolver.read());
        tokio::spawn(async move {
            let _permit = permit;
            serve(stream, resolver, src).await;
        });
    }
}

/// Serve DNS-over-TCP queries on `stream` until EOF, error or idleness.
pub async fn serve<S>(mut stream: S, resolver: Arc<Resolver>, src: SocketAddr)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    loop {
        let mut len = [0u8; 2];
        match tokio::time::timeout(IDLE, stream.read_exact(&mut len)).await {
            Ok(Ok(_)) => {}
            // EOF between messages is the normal end of the conversation.
            Ok(Err(_)) | Err(_) => return,
        }
        let mut query = vec![0u8; usize::from(u16::from_be_bytes(len))];
        if tokio::time::timeout(IDLE, stream.read_exact(&mut query))
            .await
            .map_or(true, |read| read.is_err())
        {
            debug!("DNS TCP: {src} closed mid-message");
            return;
        }
        let response = match DnsServer::try_answer_local(&query, &resolver) {
            LocalAnswer::Answer(response) => response,
            LocalAnswer::Drop => return,
            LocalAnswer::Upstream => match DnsServer::handle_query(&query, &resolver).await {
                Ok(response) => response,
                Err(e) => {
                    debug!("DNS TCP: unanswerable query from {src}: {e}");
                    return;
                }
            },
        };
        let Ok(response_len) = u16::try_from(response.len()) else {
            debug!(
                "DNS TCP: {}-byte response does not fit TCP framing",
                response.len()
            );
            return;
        };
        let mut framed = Vec::with_capacity(response.len() + 2);
        framed.extend_from_slice(&response_len.to_be_bytes());
        framed.extend_from_slice(&response);
        if stream.write_all(&framed).await.is_err() || stream.flush().await.is_err() {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rill_common::DnsMode;

    fn resolver_with_host(name: &str, ip: &str) -> Resolver {
        let mut hosts = rill_trie::DomainTrie::new();
        hosts.insert(
            name,
            crate::resolver::HostEntry::Addresses(vec![ip.parse().unwrap()]),
        );
        // Any other name would go upstream to a TEST-NET address that never
        // answers.
        Resolver::new(
            vec!["192.0.2.1:53".parse().unwrap()],
            Vec::new(),
            DnsMode::Normal,
            hosts,
            true,
            true,
        )
    }

    fn query(id: u16, name: &str) -> Vec<u8> {
        let mut q = Vec::new();
        q.extend_from_slice(&id.to_be_bytes());
        q.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
        for label in name.split('.') {
            q.push(label.len() as u8);
            q.extend_from_slice(label.as_bytes());
        }
        q.extend_from_slice(&[0, 0, 1, 0, 1]);
        q
    }

    async fn ask<S: AsyncRead + AsyncWrite + Unpin>(
        stream: &mut S,
        id: u16,
        name: &str,
    ) -> Vec<u8> {
        let q = query(id, name);
        stream
            .write_all(&(q.len() as u16).to_be_bytes())
            .await
            .unwrap();
        stream.write_all(&q).await.unwrap();
        let mut len = [0u8; 2];
        stream.read_exact(&mut len).await.unwrap();
        let mut resp = vec![0u8; usize::from(u16::from_be_bytes(len))];
        stream.read_exact(&mut resp).await.unwrap();
        resp
    }

    /// Two framed queries on one connection, both answered from hosts, in
    /// order, with their own ids; the server then ends on client EOF.
    #[tokio::test]
    async fn answers_framed_queries_until_eof() {
        let resolver = Arc::new(resolver_with_host("hijack.test", "10.9.8.7"));
        let (client, server) = tokio::io::duplex(4096);
        let task = tokio::spawn(serve(server, resolver, "127.0.0.1:5353".parse().unwrap()));
        let (mut rd, mut wr) = tokio::io::split(client);
        for id in [0x1111u16, 0x2222] {
            let q = query(id, "hijack.test");
            wr.write_all(&(q.len() as u16).to_be_bytes()).await.unwrap();
            wr.write_all(&q).await.unwrap();
        }
        for id in [0x1111u16, 0x2222] {
            let mut len = [0u8; 2];
            rd.read_exact(&mut len).await.unwrap();
            let mut resp = vec![0u8; usize::from(u16::from_be_bytes(len))];
            rd.read_exact(&mut resp).await.unwrap();
            assert_eq!(u16::from_be_bytes([resp[0], resp[1]]), id);
            assert!(
                resp.windows(4).any(|w| w == [10, 9, 8, 7]),
                "answer carries the hosts address"
            );
        }
        // The split halves share one duplex; shutting the write half down
        // is what delivers EOF to the server.
        wr.shutdown().await.unwrap();
        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("server ends on EOF")
            .unwrap();
    }

    /// `dns.listen` answers over TCP on the port its UDP socket bound, and
    /// stops listening on both once the serve future is dropped.
    #[tokio::test]
    async fn listen_address_serves_tcp_beside_udp() {
        let resolver = Arc::new(resolver_with_host("tcp.test", "10.1.2.3"));
        let bound = DnsServer::new(resolver, "127.0.0.1:0".parse().unwrap())
            .bind()
            .await
            .unwrap();
        let addr = bound.local_addr().unwrap();
        let serving = tokio::spawn(bound.run());

        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let resp = ask(&mut stream, 0x4242, "tcp.test").await;
        assert_eq!(&resp[..2], &[0x42, 0x42]);
        assert_eq!(&resp[resp.len() - 4..], &[10, 1, 2, 3]);

        let udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        udp.send_to(&query(0x4343, "tcp.test"), addr).await.unwrap();
        let mut buf = [0u8; 512];
        let (n, _) = tokio::time::timeout(Duration::from_secs(5), udp.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf[n - 4..n], &[10, 1, 2, 3]);

        serving.abort();
        let _ = serving.await;
        tokio::net::TcpListener::bind(addr)
            .await
            .expect("the TCP port is free once the server stops");
    }
}
