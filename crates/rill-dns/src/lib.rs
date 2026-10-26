//! DNS resolver, cache, snooping, and FakeIP for the rill proxy kernel.
//!
//! Caching resolver with IP-to-domain reverse mapping, optional FakeIP
//! allocation, and a DNS server used by transparent proxy and TUN.

pub mod cache;
pub mod client;
#[cfg(feature = "doh-h2")]
mod doh;
pub mod fakeip;
pub mod host_resolver_hook;
pub mod resolver;
pub mod routing;
pub mod server;
pub mod tcp;
pub mod upstream;

pub use cache::{DnsCache, DnsCacheSnapshotEntry, ReverseSnapshotEntry};
pub use client::{
    reset_pooled_connections, set_socket_factory, ClientError, DnsClient, SocketFactory,
};
pub use fakeip::{FileStore, MemoryStore, Pool, PoolError, Skipper, SkipperMode, Store};
pub use host_resolver_hook::ResolverHostHook;
pub use resolver::{
    BootstrapError, DomainGate, FallbackFilter, GeoIpTrusted, HostEntry, NameserverPolicy,
    PolicyEntry, Resolver,
};
pub use server::{new_resolver_slot, BoundDnsServer, DnsServer, LocalAnswer, ResolverSlot};
pub use upstream::{HostOrIp, NameServerEntry, NameServerParseError, NameServerUrl};
