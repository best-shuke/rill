//! Shared BoringSSL TLS, H2 and WebSocket byte-stream transports.
mod h2io;
mod tls;
mod ws;
pub use h2io::*;
pub use tls::*;
use tokio::io::{AsyncRead, AsyncWrite};
pub use ws::*;
pub trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}
pub type BoxIo = Box<dyn Io>;
