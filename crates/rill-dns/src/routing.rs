//! DNS outbounds that are not ordinary proxies: the deferred `#RULES` router
//! (config builds its clients before the tunnel exists) and the stand-in for
//! a `#name` that names no proxy.
use parking_lot::RwLock;
use rill_common::{
    AdapterType, DelayHistory, Metadata, Proxy, ProxyAdapter, ProxyConn, ProxyHealth,
    ProxyPacketConn, Result, RillError,
};
use std::sync::Arc;

#[derive(Default)]
pub struct RoutingDnsProxy {
    target: RwLock<Option<Arc<dyn Proxy>>>,
    health: ProxyHealth,
}

impl RoutingDnsProxy {
    pub fn install(&self, target: Arc<dyn Proxy>) {
        *self.target.write() = Some(target);
    }

    fn target(&self) -> Result<Arc<dyn Proxy>> {
        self.target
            .read()
            .clone()
            .ok_or_else(|| RillError::Dns("DNS rule routing is not installed yet".into()))
    }
}

#[async_trait::async_trait]
impl ProxyAdapter for RoutingDnsProxy {
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
        self.target()?.dial_tcp(metadata).await
    }
    async fn dial_udp(&self, metadata: &Metadata) -> Result<Box<dyn ProxyPacketConn>> {
        self.target()?.dial_udp(metadata).await
    }
    fn health(&self) -> &ProxyHealth {
        &self.health
    }
}

impl Proxy for RoutingDnsProxy {
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

/// Stands in for a `#name` DNS outbound that names no proxy. Every exchange
/// through it fails — never a direct query — while the config still loads,
/// as in mihomo, which reports the missing proxy at query time.
pub struct MissingDnsOutbound {
    name: String,
    health: ProxyHealth,
}

impl MissingDnsOutbound {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_owned(),
            health: ProxyHealth::new(),
        }
    }

    fn error(&self) -> RillError {
        RillError::Dns(format!("DNS outbound '{}' is not defined", self.name))
    }
}

#[async_trait::async_trait]
impl ProxyAdapter for MissingDnsOutbound {
    fn name(&self) -> &str {
        &self.name
    }
    fn adapter_type(&self) -> AdapterType {
        AdapterType::Reject
    }
    fn addr(&self) -> &str {
        ""
    }
    fn support_udp(&self) -> bool {
        false
    }
    async fn dial_tcp(&self, _: &Metadata) -> Result<Box<dyn ProxyConn>> {
        Err(self.error())
    }
    async fn dial_udp(&self, _: &Metadata) -> Result<Box<dyn ProxyPacketConn>> {
        Err(self.error())
    }
    fn health(&self) -> &ProxyHealth {
        &self.health
    }
}

impl Proxy for MissingDnsOutbound {
    fn alive(&self) -> bool {
        false
    }
    fn alive_for_url(&self, _: &str) -> bool {
        false
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
