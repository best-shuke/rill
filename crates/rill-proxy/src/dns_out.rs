//! mihomo's `type: dns` outbound: a connection routed to it is answered by
//! rill's own resolver — DNS over TCP on a stream, one DNS message per
//! datagram over UDP — instead of leaving the process.
//!
//! upstream: `adapter/outbound/dns.go`. Rules such as
//! `DST-PORT,53,dns-out` use it to capture DNS sent to arbitrary servers.

use async_trait::async_trait;
use rill_common::{
    AdapterType, Metadata, ProxyAdapter, ProxyConn, ProxyHealth, ProxyPacketConn, Result, RillError,
};
use smol_str::SmolStr;
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Largest DNS message over TCP (two-byte length prefix).
const MAX_TCP_MESSAGE: usize = u16::MAX as usize;
/// Answers queued for a UDP reader that is not reading.
const UDP_BACKLOG: usize = 64;

pub struct DnsOutAdapter {
    name: SmolStr,
    resolver: Option<rill_dns::ResolverSlot>,
    health: ProxyHealth,
}

impl DnsOutAdapter {
    /// `resolver` is the live resolver generation; without one every query
    /// is answered SERVFAIL (a config's first build pass has none yet).
    pub fn new(name: &str, resolver: Option<rill_dns::ResolverSlot>) -> Self {
        Self {
            name: name.into(),
            resolver,
            health: ProxyHealth::new(),
        }
    }

    fn resolver(&self) -> Result<std::sync::Arc<rill_dns::Resolver>> {
        self.resolver
            .as_ref()
            .map(|slot| std::sync::Arc::clone(&slot.read()))
            .ok_or_else(|| RillError::Proxy(format!("{}: no resolver", self.name)))
    }
}

async fn answer(resolver: &rill_dns::Resolver, query: &[u8]) -> Option<Vec<u8>> {
    match rill_dns::DnsServer::handle_query(query, resolver).await {
        Ok(response) => Some(response),
        Err(e) => {
            tracing::debug!("dns outbound: query dropped: {e}");
            None
        }
    }
}

#[async_trait]
impl ProxyAdapter for DnsOutAdapter {
    fn name(&self) -> &str {
        &self.name
    }

    fn adapter_type(&self) -> AdapterType {
        AdapterType::Dns
    }

    fn addr(&self) -> &str {
        ""
    }

    fn support_udp(&self) -> bool {
        true
    }

    async fn dial_tcp(&self, _metadata: &Metadata) -> Result<Box<dyn ProxyConn>> {
        let resolver = self.resolver()?;
        let (client, mut server) = tokio::io::duplex(MAX_TCP_MESSAGE + 2);
        tokio::spawn(async move {
            let mut buf = vec![0u8; MAX_TCP_MESSAGE];
            loop {
                let mut len = [0u8; 2];
                if server.read_exact(&mut len).await.is_err() {
                    return;
                }
                let len = usize::from(u16::from_be_bytes(len));
                if server.read_exact(&mut buf[..len]).await.is_err() {
                    return;
                }
                let Some(response) = answer(&resolver, &buf[..len]).await else {
                    return;
                };
                let Ok(rlen) = u16::try_from(response.len()) else {
                    return;
                };
                if server.write_all(&rlen.to_be_bytes()).await.is_err()
                    || server.write_all(&response).await.is_err()
                {
                    return;
                }
            }
        });
        Ok(Box::new(crate::StreamConn(Box::new(client))))
    }

    async fn dial_udp(&self, _metadata: &Metadata) -> Result<Box<dyn ProxyPacketConn>> {
        let (tx, rx) = tokio::sync::mpsc::channel(UDP_BACKLOG);
        Ok(Box::new(DnsPacketConn {
            resolver: self.resolver()?,
            tx,
            rx: tokio::sync::Mutex::new(rx),
        }))
    }

    fn health(&self) -> &ProxyHealth {
        &self.health
    }
}

struct DnsPacketConn {
    resolver: std::sync::Arc<rill_dns::Resolver>,
    tx: tokio::sync::mpsc::Sender<(Vec<u8>, SocketAddr)>,
    rx: tokio::sync::Mutex<tokio::sync::mpsc::Receiver<(Vec<u8>, SocketAddr)>>,
}

#[async_trait]
impl ProxyPacketConn for DnsPacketConn {
    async fn read_packet(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr)> {
        let (response, from) = self
            .rx
            .lock()
            .await
            .recv()
            .await
            .ok_or_else(|| RillError::Proxy("dns outbound closed".into()))?;
        let n = response.len().min(buf.len());
        buf[..n].copy_from_slice(&response[..n]);
        Ok((n, from))
    }

    async fn write_packet(&self, buf: &[u8], addr: &SocketAddr) -> Result<usize> {
        let resolver = std::sync::Arc::clone(&self.resolver);
        let tx = self.tx.clone();
        let query = buf.to_vec();
        let from = *addr;
        // Answer off the caller's task so one slow upstream does not hold
        // up the next query of the same flow.
        tokio::spawn(async move {
            if let Some(response) = answer(&resolver, &query).await {
                let _ = tx.try_send((response, from));
            }
        });
        Ok(buf.len())
    }

    fn local_addr(&self) -> Result<SocketAddr> {
        Ok(SocketAddr::from(([0, 0, 0, 0], 0)))
    }

    fn close(&self) -> Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    fn resolver() -> rill_dns::ResolverSlot {
        let mut hosts = rill_trie::DomainTrie::new();
        hosts.insert(
            "example.test",
            rill_dns::HostEntry::Addresses(vec!["1.2.3.4".parse::<IpAddr>().unwrap()]),
        );
        let resolver = rill_dns::Resolver::new(
            Vec::new(),
            Vec::new(),
            rill_common::DnsMode::Normal,
            hosts,
            true,
            false,
        );
        rill_dns::new_resolver_slot(std::sync::Arc::new(resolver))
    }

    /// An A query for `example.test`, id 0x1234.
    fn query() -> Vec<u8> {
        let mut q = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        for label in ["example", "test"] {
            q.push(label.len() as u8);
            q.extend_from_slice(label.as_bytes());
        }
        q.extend_from_slice(&[0, 0, 1, 0, 1]);
        q
    }

    fn assert_answers_hosts_entry(response: &[u8]) {
        assert_eq!(&response[..2], &[0x12, 0x34], "same id");
        assert_ne!(response[2] & 0x80, 0, "a response");
        assert_eq!(
            u16::from_be_bytes([response[6], response[7]]),
            1,
            "one answer"
        );
        assert_eq!(&response[response.len() - 4..], &[1, 2, 3, 4]);
    }

    #[tokio::test]
    async fn tcp_queries_are_answered_by_the_resolver() {
        let out = DnsOutAdapter::new("dns-out", Some(resolver()));
        assert_eq!(out.adapter_type(), AdapterType::Dns);
        let mut conn = out.dial_tcp(&Metadata::default()).await.unwrap();
        let q = query();
        for _ in 0..2 {
            conn.write_all(&(q.len() as u16).to_be_bytes())
                .await
                .unwrap();
            conn.write_all(&q).await.unwrap();
            let mut len = [0u8; 2];
            conn.read_exact(&mut len).await.unwrap();
            let mut response = vec![0u8; usize::from(u16::from_be_bytes(len))];
            conn.read_exact(&mut response).await.unwrap();
            assert_answers_hosts_entry(&response);
        }
    }

    #[tokio::test]
    async fn udp_queries_are_answered_by_the_resolver() {
        let out = DnsOutAdapter::new("dns-out", Some(resolver()));
        let conn = out.dial_udp(&Metadata::default()).await.unwrap();
        let server: SocketAddr = "8.8.8.8:53".parse().unwrap();
        conn.write_packet(&query(), &server).await.unwrap();
        let mut buf = [0u8; 512];
        let (n, from) = conn.read_packet(&mut buf).await.unwrap();
        assert_eq!(from, server, "the answer comes from the queried server");
        assert_answers_hosts_entry(&buf[..n]);
    }

    #[tokio::test]
    async fn without_a_resolver_dialing_fails() {
        let out = DnsOutAdapter::new("dns-out", None);
        assert!(out.dial_tcp(&Metadata::default()).await.is_err());
    }
}
