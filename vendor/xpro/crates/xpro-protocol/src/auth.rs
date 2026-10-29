use crate::{denied, invalid, random, Destination};
use boring::hash::MessageDigest;
use std::{
    collections::{HashSet, VecDeque},
    fmt, io,
    sync::Mutex,
    time::{Duration, Instant},
};
pub const VERSION: u8 = 1;
pub const ADMISSION_DOMAIN: &[u8] = b"XPro/1 admission\0";
pub const OPEN_DOMAIN: &[u8] = b"XPro/1 open\0";
pub const AUTH_HEADER: &str = "x-xpro-admission";
pub type DeviceId = [u8; 16];
#[derive(Clone)]
pub struct DeviceKey([u8; 32]);
impl fmt::Debug for DeviceKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DeviceKey([REDACTED])")
    }
}
impl DeviceKey {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
    pub fn from_file(path: impl AsRef<std::path::Path>) -> io::Result<Self> {
        let file = std::fs::File::open(path)?;
        use std::io::Read;
        let mut bytes = Vec::new();
        file.take(33).read_to_end(&mut bytes)?;
        Ok(Self(bytes.try_into().map_err(|_| {
            invalid("device key file must contain exactly 32 raw bytes")
        })?))
    }
    pub fn mac(&self, input: &[u8]) -> io::Result<[u8; 32]> {
        let mut mac = boring::hmac::Hmac::init(&self.0, &MessageDigest::sha256())
            .map_err(io::Error::other)?;
        mac.update(input).map_err(io::Error::other)?;
        Ok(mac
            .finalize()
            .map_err(io::Error::other)?
            .try_into()
            .unwrap())
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Profile {
    H2 = 1,
    Wss = 2,
}
impl TryFrom<u8> for Profile {
    type Error = io::Error;
    fn try_from(v: u8) -> io::Result<Self> {
        match v {
            1 => Ok(Self::H2),
            2 => Ok(Self::Wss),
            _ => Err(invalid("unsupported profile")),
        }
    }
}
#[derive(Debug, Clone)]
pub struct Proof {
    pub profile: Profile,
    pub device: DeviceId,
    pub timestamp: u64,
    pub nonce: [u8; 16],
    pub mac: [u8; 32],
}
impl Proof {
    pub const SIZE: usize = 74;
    pub fn fresh(profile: Profile, device: DeviceId, timestamp: u64) -> io::Result<Self> {
        Ok(Self {
            profile,
            device,
            timestamp,
            nonce: random()?,
            mac: [0; 32],
        })
    }
    pub fn prefix(&self) -> Vec<u8> {
        let mut v = vec![VERSION, self.profile as u8];
        v.extend(self.device);
        v.extend(self.timestamp.to_be_bytes());
        v.extend(self.nonce);
        v
    }
    pub fn encode(&self) -> Vec<u8> {
        let mut v = self.prefix();
        v.extend(self.mac);
        v
    }
    pub fn decode(v: &[u8]) -> io::Result<Self> {
        if v.len() != Self::SIZE || v[0] != VERSION {
            return Err(invalid("invalid authentication envelope"));
        }
        Ok(Self {
            profile: Profile::try_from(v[1])?,
            device: v[2..18].try_into().unwrap(),
            timestamp: u64::from_be_bytes(v[18..26].try_into().unwrap()),
            nonce: v[26..42].try_into().unwrap(),
            mac: v[42..74].try_into().unwrap(),
        })
    }
    pub fn header(&self) -> String {
        hex::encode(self.encode())
    }
    pub fn from_header(v: &str) -> io::Result<Self> {
        if v.len() != Self::SIZE * 2 {
            return Err(denied());
        }
        Self::decode(&hex::decode(v).map_err(|_| denied())?)
    }
    pub fn admission_input(
        &self,
        authority: &str,
        method: &str,
        path: &str,
        exporter: Option<&[u8; 32]>,
    ) -> io::Result<Vec<u8>> {
        if (self.profile == Profile::H2) != exporter.is_some() {
            return Err(invalid("incorrect admission channel binding"));
        }
        let mut v = ADMISSION_DOMAIN.to_vec();
        v.extend(self.prefix());
        for s in [authority, method, path] {
            let len = u16::try_from(s.len()).map_err(|_| invalid("HTTP binding too long"))?;
            v.extend(len.to_be_bytes());
            v.extend(s.as_bytes());
        }
        if let Some(e) = exporter {
            v.extend(e);
        }
        Ok(v)
    }
    pub fn open_input(&self, exporter: &[u8; 32], encoded_destination: &[u8]) -> Vec<u8> {
        let mut v = OPEN_DOMAIN.to_vec();
        v.extend(self.prefix());
        v.extend(exporter);
        v.extend(encoded_destination);
        v
    }
    pub fn sign(&mut self, key: &DeviceKey, input: &[u8]) -> io::Result<()> {
        self.mac = key.mac(input)?;
        Ok(())
    }
    pub fn verify(&self, key: &DeviceKey, input: &[u8], wall_now: u64) -> io::Result<()> {
        if self.timestamp.abs_diff(wall_now) > 60
            || !boring::memcmp::eq(&self.mac, &key.mac(input)?)
        {
            return Err(denied());
        }
        Ok(())
    }
}
#[derive(Debug, Clone)]
pub struct AuthOpen {
    pub proof: Proof,
    pub destination: Destination,
}
impl AuthOpen {
    pub fn encode(&self) -> io::Result<Vec<u8>> {
        let mut v = self.proof.encode();
        v.extend(self.destination.encode()?);
        Ok(v)
    }
    pub fn decode(v: &[u8]) -> io::Result<Self> {
        if v.len() < Proof::SIZE {
            return Err(invalid("short AUTH_OPEN"));
        }
        Ok(Self {
            proof: Proof::decode(&v[..Proof::SIZE])?,
            destination: Destination::decode(&v[Proof::SIZE..])?,
        })
    }
}
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub enum Stage {
    Admission,
    Open,
}
/// Monotonic expiry; capacity pressure fails closed. Insert only AFTER MAC validation.
type ReplayKey = (Stage, DeviceId, [u8; 16]);
#[derive(Default)]
struct ReplayState {
    keys: HashSet<ReplayKey>,
    expiry: VecDeque<(Instant, ReplayKey)>,
}
pub struct ReplayCache {
    entries: Mutex<ReplayState>,
    capacity: usize,
}
impl ReplayCache {
    pub fn new(capacity: usize) -> Self {
        Self {
            entries: Mutex::new(ReplayState::default()),
            capacity,
        }
    }
    pub fn register(&self, stage: Stage, proof: &Proof) -> io::Result<()> {
        let now = Instant::now();
        let mut map = self.entries.lock().map_err(|_| denied())?;
        while map
            .expiry
            .front()
            .is_some_and(|(deadline, _)| *deadline <= now)
        {
            let (_, key) = map.expiry.pop_front().unwrap();
            map.keys.remove(&key);
        }
        let key = (stage, proof.device, proof.nonce);
        if map.keys.contains(&key) || map.keys.len() >= self.capacity {
            return Err(denied());
        }
        map.keys.insert(key);
        map.expiry.push_back((now + Duration::from_secs(180), key));
        Ok(())
    }
}
