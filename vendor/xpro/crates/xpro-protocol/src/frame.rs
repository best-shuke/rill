use crate::invalid;
use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
pub const MAX_DATA: usize = 16384;
pub const MAX_CONTROL: usize = 4096;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Kind {
    AuthOpen = 1,
    Connected = 2,
    Data = 3,
    HalfClose = 4,
    Close = 5,
    Error = 6,
}
impl TryFrom<u8> for Kind {
    type Error = io::Error;
    fn try_from(v: u8) -> io::Result<Self> {
        Ok(match v {
            1 => Self::AuthOpen,
            2 => Self::Connected,
            3 => Self::Data,
            4 => Self::HalfClose,
            5 => Self::Close,
            6 => Self::Error,
            _ => return Err(invalid("unknown frame type")),
        })
    }
}
#[derive(Debug, PartialEq, Eq)]
pub struct Frame {
    pub kind: Kind,
    pub payload: Vec<u8>,
}
impl Frame {
    pub fn new(kind: Kind, payload: Vec<u8>) -> Self {
        Self { kind, payload }
    }
    pub fn validate(&self) -> io::Result<()> {
        validate_length(self.kind, self.payload.len())
    }
    pub async fn read<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<Self> {
        let mut h = [0u8; 6];
        r.read_exact(&mut h).await?;
        let kind = Kind::try_from(h[0])?;
        if h[1] != 0 {
            return Err(invalid("nonzero reserved flags"));
        }
        let length = u32::from_be_bytes(h[2..].try_into().unwrap()) as usize;
        validate_length(kind, length)?; // Before allocation.
        let mut payload = vec![0; length];
        r.read_exact(&mut payload).await?;
        Ok(Self { kind, payload })
    }
    pub async fn write<W: AsyncWrite + Unpin>(&self, w: &mut W) -> io::Result<()> {
        self.validate()?;
        let mut h = [0u8; 6];
        h[0] = self.kind as u8;
        h[2..].copy_from_slice(&(self.payload.len() as u32).to_be_bytes());
        w.write_all(&h).await?;
        w.write_all(&self.payload).await?;
        w.flush().await
    }
}
fn validate_length(kind: Kind, n: usize) -> io::Result<()> {
    let valid = match kind {
        Kind::Data => (1..=MAX_DATA).contains(&n),
        Kind::AuthOpen => (1..=MAX_CONTROL).contains(&n),
        Kind::Error => n == 2,
        _ => n == 0,
    };
    if valid {
        Ok(())
    } else {
        Err(invalid("invalid frame length"))
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Destination {
    pub host: String,
    pub port: u16,
}
impl Destination {
    pub fn new(host: impl Into<String>, port: u16) -> io::Result<Self> {
        let value = Self {
            host: host.into(),
            port,
        };
        value.encode()?;
        Ok(value)
    }
    pub fn encode(&self) -> io::Result<Vec<u8>> {
        if self.port == 0 {
            return Err(invalid("zero destination port"));
        }
        let mut v = Vec::with_capacity(260);
        match self.host.parse::<IpAddr>() {
            Ok(IpAddr::V4(ip)) => {
                v.push(1);
                v.extend(ip.octets());
            }
            Ok(IpAddr::V6(ip)) => {
                v.push(2);
                v.extend(ip.octets());
            }
            Err(_) => {
                // Canonical A-label only: no absolute trailing dot, empty label or wildcard.
                if self.host.len() > 253
                    || self.host.is_empty()
                    || self.host.split('.').any(|s| {
                        s.is_empty()
                            || s.len() > 63
                            || s.starts_with('-')
                            || s.ends_with('-')
                            || !s
                                .bytes()
                                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
                    })
                {
                    return Err(invalid(
                        "destination must be a canonical ASCII domain or IP",
                    ));
                }
                v.push(3);
                v.push(self.host.len() as u8);
                v.extend(self.host.as_bytes());
            }
        }
        v.extend(self.port.to_be_bytes());
        Ok(v)
    }
    pub fn decode(v: &[u8]) -> io::Result<Self> {
        let host = match v.first() {
            Some(1) if v.len() == 7 => {
                Ipv4Addr::from(<[u8; 4]>::try_from(&v[1..5]).unwrap()).to_string()
            }
            Some(2) if v.len() == 19 => {
                Ipv6Addr::from(<[u8; 16]>::try_from(&v[1..17]).unwrap()).to_string()
            }
            Some(3) if v.len() >= 4 && v.len() == v[1] as usize + 4 => {
                std::str::from_utf8(&v[2..v.len() - 2])
                    .map_err(|_| invalid("invalid domain"))?
                    .into()
            }
            _ => return Err(invalid("invalid destination encoding")),
        };
        let result = Self::new(
            host,
            u16::from_be_bytes(v[v.len() - 2..].try_into().unwrap()),
        )?;
        if result.encode()? != v {
            return Err(invalid("noncanonical destination"));
        }
        Ok(result)
    }
}
