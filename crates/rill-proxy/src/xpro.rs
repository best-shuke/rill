//! XPro/1 outbound; every physical socket goes through rill's injected dialer.
use async_trait::async_trait;
use rill_common::{
    AdapterType, Metadata, ProxyAdapter, ProxyConn, ProxyHealth, ProxyPacketConn, Result, RillError,
};
use std::{io, sync::Arc};
pub use xpro_client::{
    xpro_protocol::{Destination, DeviceKey, Profile},
    Config, Heartbeat, InnerTls,
};
struct Dialer(Arc<dyn crate::dialer::TcpDialer>);
#[async_trait]
impl xpro_client::Dialer for Dialer {
    async fn dial(&self, host: &str, port: u16) -> io::Result<xpro_client::xpro_transport::BoxIo> {
        let stream = self.0.dial(host, port, false).await?;
        Ok(Box::new(stream))
    }
}
pub struct XproAdapter {
    name: Box<str>,
    addr: Box<str>,
    client: xpro_client::Client,
    health: ProxyHealth,
}
impl XproAdapter {
    pub fn new(
        name: &str,
        config: Config,
        dialer: Arc<dyn crate::dialer::TcpDialer>,
    ) -> Result<Self> {
        if dialer.is_proxy() {
            return Err(RillError::NotSupported(
                "XPro dialer-proxy chaining is not supported".into(),
            ));
        }
        let addr = if config.server.contains(':') {
            format!("[{}]:{}", config.server, config.port)
        } else {
            format!("{}:{}", config.server, config.port)
        }
        .into_boxed_str();
        let client = xpro_client::Client::new(config, Arc::new(Dialer(dialer)))
            .map_err(|_| RillError::Config("invalid XPro endpoint or CA configuration".into()))?;
        Ok(Self {
            name: name.into(),
            addr,
            client,
            health: ProxyHealth::new(),
        })
    }
}
#[async_trait]
impl ProxyAdapter for XproAdapter {
    fn name(&self) -> &str {
        &self.name
    }
    fn addr(&self) -> &str {
        &self.addr
    }
    fn adapter_type(&self) -> AdapterType {
        AdapterType::Xpro
    }
    fn support_udp(&self) -> bool {
        false
    }
    fn health(&self) -> &ProxyHealth {
        &self.health
    }
    fn reset_sessions(&self) {
        self.client.reset();
    }
    async fn dial_tcp(&self, metadata: &Metadata) -> Result<Box<dyn ProxyConn>> {
        let host = if metadata.host.is_empty() {
            metadata
                .dst_ip
                .ok_or_else(|| RillError::Config("XPro destination is missing".into()))?
                .to_string()
        } else {
            metadata.host.to_string()
        };
        let host = canonical_host(&host)?;
        let target = Destination::new(host, metadata.dst_port)
            .map_err(|_| RillError::Config("invalid XPro destination".into()))?;
        let connection = self.client.tcp(target).await.map_err(|e| match e.kind() {
            io::ErrorKind::PermissionDenied => RillError::ProxyAuthFailed,
            io::ErrorKind::InvalidData => RillError::Proxy("XPro protocol error".into()),
            io::ErrorKind::WouldBlock => RillError::Io(rill_common::error::local_resource_limit(
                "XPro stream limit",
            )),
            _ => RillError::Io(e),
        })?;
        Ok(Box::new(crate::StreamConn(Box::new(connection))))
    }
    async fn dial_udp(&self, _: &Metadata) -> Result<Box<dyn ProxyPacketConn>> {
        Err(RillError::UdpNotSupported)
    }
}

fn canonical_host(host: &str) -> Result<String> {
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return Ok(ip.to_string());
    }
    // XPro/1 encodes relative names only; an absolute FQDN (`example.com.`,
    // as sniffed or sent by some clients) names the same host.
    let host = host.strip_suffix('.').unwrap_or(host);
    Ok(url::Host::parse(host)
        .map_err(|_| RillError::Config("invalid XPro destination".into()))?
        .to_string()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_owned())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn destinations_preserve_ip_literals_and_convert_idna() {
        for (input, expected) in [
            ("2606:4700::1111", "2606:4700::1111"),
            ("[2606:4700::1111]", "2606:4700::1111"),
            ("1.2.3.4", "1.2.3.4"),
            ("EXAMPLE.COM", "example.com"),
            ("example.com.", "example.com"),
            ("例子.测试", "xn--fsqu00a.xn--0zwm56d"),
        ] {
            let host = canonical_host(input).unwrap();
            assert_eq!(host, expected);
            let dest = Destination::new(host, 443).unwrap();
            assert_eq!(Destination::decode(&dest.encode().unwrap()).unwrap(), dest);
        }
    }
}
