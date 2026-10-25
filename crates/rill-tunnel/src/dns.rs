//! DNS housekeeping uses the same live rule selection as ordinary connections.
use crate::TunnelInner;
use rill_common::{
    AdapterType, DelayHistory, Metadata, Proxy, ProxyAdapter, ProxyConn, ProxyHealth,
    ProxyPacketConn, Result, RillError,
};
use std::sync::{Arc, Weak};

pub(crate) struct DnsRuleProxy {
    tunnel: Weak<TunnelInner>,
    health: ProxyHealth,
}

impl DnsRuleProxy {
    pub(crate) fn new(tunnel: &Arc<TunnelInner>) -> Self {
        Self {
            tunnel: Arc::downgrade(tunnel),
            health: ProxyHealth::new(),
        }
    }
}

#[async_trait::async_trait]
impl ProxyAdapter for DnsRuleProxy {
    fn name(&self) -> &str {
        "RULES"
    }
    fn adapter_type(&self) -> AdapterType {
        AdapterType::Direct
    }
    fn addr(&self) -> &str {
        ""
    }
    fn support_udp(&self) -> bool {
        true
    }
    async fn dial_tcp(&self, metadata: &Metadata) -> Result<Box<dyn ProxyConn>> {
        let tunnel = self
            .tunnel
            .upgrade()
            .ok_or_else(|| RillError::Dns("DNS routing tunnel stopped".into()))?;
        let target = tunnel
            .resolve_proxy(metadata)
            .await
            .ok_or_else(|| RillError::Dns("no matching DNS outbound".into()))?;
        // Retain the route generation while a dialer-proxy chain establishes.
        let connection = target.adapter.dial_tcp(metadata).await;
        drop(target);
        connection
    }
    async fn dial_udp(&self, metadata: &Metadata) -> Result<Box<dyn ProxyPacketConn>> {
        let tunnel = self
            .tunnel
            .upgrade()
            .ok_or_else(|| RillError::Dns("DNS routing tunnel stopped".into()))?;
        let target = tunnel
            .resolve_proxy(metadata)
            .await
            .ok_or_else(|| RillError::Dns("no matching DNS outbound".into()))?;
        let connection = target.adapter.dial_udp(metadata).await;
        drop(target);
        connection
    }
    fn health(&self) -> &ProxyHealth {
        &self.health
    }
}

impl Proxy for DnsRuleProxy {
    fn alive(&self) -> bool {
        true
    }
    fn alive_for_url(&self, _: &str) -> bool {
        true
    }
    fn last_delay(&self) -> u16 {
        0
    }
    fn last_delay_for_url(&self, _: &str) -> u16 {
        0
    }
    fn delay_history(&self) -> Vec<DelayHistory> {
        Vec::new()
    }
}
