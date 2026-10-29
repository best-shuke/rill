//! XPro/1 canonical encoding and authentication. All integers are big endian.
mod auth;
mod frame;
mod session;
pub use auth::*;
pub use frame::*;
pub use session::*;
use std::io;
pub fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
pub fn denied() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "XPro authentication rejected",
    )
}
pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
pub fn random<const N: usize>() -> io::Result<[u8; N]> {
    let mut value = [0; N];
    boring::rand::rand_bytes(&mut value).map_err(io::Error::other)?;
    Ok(value)
}
