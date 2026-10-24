//! `dns-hijack: tcp://…:53` — answer DNS over TCP in-process.
//!
//! A hijacked TCP :53 flow never reaches the router: each length-prefixed
//! message (RFC 1035 §4.2.2) is answered the way the UDP hijack answers a
//! datagram — locally when the resolver can decide it (hosts, fake-IP,
//! fresh cache), otherwise through `DnsServer::handle_query` — and the
//! connection stays open for further queries until the client closes it or
//! goes idle.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use rill_dns::server::{DnsServer, LocalAnswer};
use rill_dns::Resolver;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tracing::debug;

/// A client that sends nothing for this long is done with the connection.
const IDLE: Duration = Duration::from_secs(10);

/// Serve DNS-over-TCP queries on `stream` until EOF, error or idleness.
pub(super) async fn serve<S>(mut stream: S, resolver: Arc<Resolver>, src: SocketAddr)
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
            debug!("tun dns-hijack tcp: {src} closed mid-message");
            return;
        }
        let response = match DnsServer::try_answer_local(&query, &resolver) {
            LocalAnswer::Answer(response) => response,
            LocalAnswer::Drop => return,
            LocalAnswer::Upstream => match DnsServer::handle_query(&query, &resolver).await {
                Ok(response) => response,
                Err(e) => {
                    debug!("tun dns-hijack tcp: unanswerable query from {src}: {e}");
                    return;
                }
            },
        };
        let Ok(response_len) = u16::try_from(response.len()) else {
            debug!(
                "tun dns-hijack tcp: {}-byte response does not fit TCP framing",
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

    /// Two framed queries on one connection, both answered from hosts, in
    /// order, with their own ids; the server then ends on client EOF.
    #[tokio::test]
    async fn answers_framed_queries_until_eof() {
        let resolver = Arc::new(crate::test_resolver_with_host("hijack.test", "10.9.8.7"));
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
}
