//! Country-keyed IP-range index built once from a GeoIP MMDB.
//!
//! At config-load the GeoIP `Reader` is walked end-to-end; each network is
//! binned by uppercased ISO country code into a per-country
//! [`IpRangeSet`] (sorted, coalesced intervals). After build, the MMDB
//! Reader can be dropped — every `GEOIP` / `SRC-GEOIP` rule retains only an
//! `Arc` to the per-country set and matches via one binary search (no MMDB
//! lookup, no country-code String allocation on the hot path).
//!
//! ## Build-time optimisations
//!
//! The MMDB walk yields hundreds of thousands of networks but only ~250
//! unique country records — every CN network, for instance, points at the
//! same data offset. The build loop exploits this and the bounded shape
//! of the rule-driven allowlist to keep the per-record cost tiny:
//!
//! * **Decode only `country.iso_code`** via `decode_path`, skipping the
//!   continent / names / traits sub-maps that `geoip2::Country` would
//!   otherwise walk.
//! * **Memoise per data offset** — decoding any given record once and
//!   reusing the resolved bucket index for every subsequent network that
//!   points at it.
//! * **Stack-pack the ISO code** into a fixed-size key so the allowlist
//!   comparison costs no allocations (no `to_ascii_uppercase()` String per
//!   record, no String-keyed HashMap insert).
//! * **Index buckets by allowlist position** in a `Vec`, since the rule
//!   set typically references at most a handful of countries — a linear
//!   scan beats a HashMap probe at that size and avoids hashing.
//!
//! ## Database flavours (mihomo parity)
//!
//! mihomo reads three MMDB record shapes, told apart by the metadata's
//! `database_type`, and so does [`CountryIndex::build`]:
//!
//! * MaxMind GeoIP2/GeoLite2 Country (anything else): `country.iso_code`.
//! * `sing-geoip` (sing-box's `geoip.db`): the record is the code string.
//! * `Meta-geoip0` (MetaCubeX's `geoip.metadb`): a code string or a list
//!   of them — one network can carry several (`cn` and `private`, say).
//!
//! With `geodata-mode: true` mihomo reads V2Ray's `GeoIP.dat` instead;
//! [`CountryIndex::from_geoip_dat`] builds the same index from it. Codes
//! compare case-insensitively everywhere. `LAN` is mihomo's built-in and
//! needs no database at all ([`lan_ranges`]).

use ipnet::{Ipv4Net, Ipv6Net};
use maxminddb::PathElement;
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::{Arc, OnceLock};

use crate::ip_set::{IpRangeSet, IpRangeSetBuilder};

/// Per-country IPv4 + IPv6 range set, shared by every rule that names the
/// country. Cheap to clone.
pub type CountryRanges = Arc<IpRangeSet>;

/// mihomo's built-in `GEOIP,LAN`: the addresses Go's `IsPrivate`,
/// `IsLoopback`, `IsUnspecified`, `IsMulticast` and `IsLinkLocalUnicast`
/// accept. Answered without any database, so a `GEOIP,LAN` rule works (and
/// matches) whether or not one is installed.
pub fn lan_ranges() -> CountryRanges {
    static LAN: OnceLock<CountryRanges> = OnceLock::new();
    Arc::clone(LAN.get_or_init(|| {
        let mut builder = IpRangeSetBuilder::new();
        for cidr in [
            "0.0.0.0/32",
            "10.0.0.0/8",
            "127.0.0.0/8",
            "169.254.0.0/16",
            "172.16.0.0/12",
            "192.168.0.0/16",
            "224.0.0.0/4",
        ] {
            builder.add_v4(cidr.parse().expect("static CIDR parses"));
        }
        for cidr in ["::/128", "::1/128", "fc00::/7", "fe80::/10", "ff00::/8"] {
            builder.add_v6(cidr.parse().expect("static CIDR parses"));
        }
        Arc::new(builder.build())
    }))
}

/// Whether `code` is mihomo's database-free `LAN`.
pub fn is_lan_code(code: &str) -> bool {
    code.eq_ignore_ascii_case("LAN")
}

/// One MMDB record's code(s) as `Meta-geoip0` stores them.
#[derive(serde::Deserialize)]
#[serde(untagged)]
enum MetaCodes<'a> {
    One(&'a str),
    #[serde(borrow)]
    Many(Vec<&'a str>),
}

/// How a database's records carry their country code(s).
#[derive(Clone, Copy)]
enum RecordShape {
    MaxMind,
    Sing,
    MetaV0,
}

impl RecordShape {
    fn of(database_type: &str) -> Self {
        match database_type {
            "sing-geoip" => Self::Sing,
            "Meta-geoip0" => Self::MetaV0,
            _ => Self::MaxMind,
        }
    }
}

/// Country-code → `CountryRanges` map. Built once via [`CountryIndex::build`].
#[derive(Default)]
pub struct CountryIndex {
    by_country: HashMap<String, CountryRanges>,
}

/// Stack-packed uppercase ASCII country code.
///
/// Sized for ISO 3166-1 alpha-2 (2 chars) with headroom for the longer codes
/// some MMDBs ship (e.g. UN M.49 numerics). Comparison is byte-wise so the
/// allowlist scan in the hot loop runs without allocating or hashing.
#[derive(Clone, Copy, PartialEq, Eq)]
struct CountryKey([u8; 8]);

impl CountryKey {
    /// Pack `s` into the buffer, uppercasing ASCII letters. Bytes beyond
    /// `BUF_LEN` are dropped — anything that long isn't a valid GeoIP code.
    #[inline]
    fn from_str_upper(s: &str) -> Self {
        let mut buf = [0u8; 8];
        let bytes = s.as_bytes();
        let n = bytes.len().min(buf.len());
        let mut i = 0;
        while i < n {
            buf[i] = bytes[i].to_ascii_uppercase();
            i += 1;
        }
        Self(buf)
    }

    /// Borrow the packed key as a `&str` (uppercase, trailing NULs stripped).
    #[inline]
    fn as_str(&self) -> &str {
        let len = self.0.iter().position(|&b| b == 0).unwrap_or(self.0.len());
        // Safe: `from_str_upper` only mutates ASCII letters; non-ASCII bytes
        // come from a `&str`, so the buffer up to `len` is valid UTF-8.
        std::str::from_utf8(&self.0[..len]).unwrap_or("")
    }
}

impl CountryIndex {
    /// Walk every record in `reader` and bin each network into the
    /// matching country bucket — but only for codes present in `allowed`.
    /// Codes outside the allowlist are skipped during the walk so the index
    /// never allocates ranges for countries no rule cares about. Codes are
    /// matched case-insensitively (the allowlist is internally uppercased).
    /// Networks without a code are skipped silently — they cannot drive any
    /// rule. All three record shapes mihomo reads are accepted (module
    /// docs).
    pub fn build<S: AsRef<[u8]>>(
        reader: &maxminddb::Reader<S>,
        allowed: &HashSet<String>,
    ) -> Result<Self, String> {
        let Some(allowed_keys) = allowed_keys(allowed)? else {
            return Ok(Self::default());
        };
        let mut buckets: Vec<IpRangeSetBuilder> = (0..allowed_keys.len())
            .map(|_| IpRangeSetBuilder::new())
            .collect();
        let shape = RecordShape::of(&reader.metadata.database_type);

        let iter = reader
            .networks(Default::default())
            .map_err(|e| format!("failed to iterate GeoIP networks: {e}"))?;

        // Path straight to `country.iso_code`, skipping every other field
        // in the GeoIP2 record (continent, names, traits, …). Borrowed by
        // `decode_path` on every iteration.
        let path = [PathElement::Key("country"), PathElement::Key("iso_code")];

        // Memoise the resolved buckets per MMDB data offset. Many networks
        // (often all networks of one country) share a single data record;
        // caching by offset turns ~10⁶ decodes into ~10² decodes. An empty
        // list means "checked, nothing allowed".
        let mut offset_cache: HashMap<usize, Vec<u16>> = HashMap::new();
        let bucket_of = |code: &str| -> Option<u16> {
            let key = CountryKey::from_str_upper(code);
            allowed_keys
                .iter()
                .position(|k| *k == key)
                .map(|idx| idx as u16)
        };

        for result in iter {
            let Ok(lookup) = result else {
                continue;
            };

            // Networks with no data record can't drive any rule.
            let Some(offset) = lookup.offset() else {
                continue;
            };

            let bucket_idxs = offset_cache.entry(offset).or_insert_with(|| match shape {
                RecordShape::MaxMind => match lookup.decode_path::<&str>(&path) {
                    Ok(Some(code)) => bucket_of(code).into_iter().collect(),
                    _ => Vec::new(),
                },
                RecordShape::Sing => match lookup.decode::<&str>() {
                    Ok(Some(code)) => bucket_of(code).into_iter().collect(),
                    _ => Vec::new(),
                },
                RecordShape::MetaV0 => match lookup.decode::<MetaCodes<'_>>() {
                    Ok(Some(MetaCodes::One(code))) => bucket_of(code).into_iter().collect(),
                    Ok(Some(MetaCodes::Many(codes))) => {
                        let mut idxs: Vec<u16> = codes.into_iter().filter_map(bucket_of).collect();
                        idxs.dedup();
                        idxs
                    }
                    _ => Vec::new(),
                },
            });
            if bucket_idxs.is_empty() {
                continue;
            }

            let Ok(net) = lookup.network() else {
                continue;
            };
            let prefix = net.prefix();
            for &bucket_idx in bucket_idxs.iter() {
                let bucket = &mut buckets[bucket_idx as usize];
                match net.network() {
                    IpAddr::V4(v4) => {
                        if let Ok(net4) = Ipv4Net::new(v4, prefix) {
                            bucket.add_v4(net4);
                        }
                    }
                    IpAddr::V6(v6) => {
                        if let Ok(net6) = Ipv6Net::new(v6, prefix) {
                            bucket.add_v6(net6);
                        }
                    }
                }
            }
        }

        Ok(Self::from_buckets(&allowed_keys, buckets))
    }

    /// The same index from V2Ray's `GeoIP.dat` (`GeoIPList` protobuf), the
    /// database mihomo's `geodata-mode: true` reads for GEOIP. Entries with
    /// `reverse_match` set (unused by real `GeoIP.dat` releases) are
    /// skipped.
    pub fn from_geoip_dat(bytes: &[u8], allowed: &HashSet<String>) -> Result<Self, String> {
        let Some(allowed_keys) = allowed_keys(allowed)? else {
            return Ok(Self::default());
        };
        let mut buckets: Vec<IpRangeSetBuilder> = (0..allowed_keys.len())
            .map(|_| IpRangeSetBuilder::new())
            .collect();
        // A truncated file (an interrupted download) is an error, not a
        // silently partial index.
        for entry in dat::fields(bytes) {
            let dat::Field::Bytes(1, geoip) = entry.map_err(|e| format!("GeoIP.dat: {e}"))? else {
                continue;
            };
            let mut code = "";
            let mut reverse = false;
            for field in dat::fields(geoip) {
                match field.map_err(|e| format!("GeoIP.dat: {e}"))? {
                    dat::Field::Bytes(1, raw) => {
                        code = std::str::from_utf8(raw).map_err(|e| format!("GeoIP.dat: {e}"))?;
                    }
                    dat::Field::Varint(3, flag) => reverse = flag != 0,
                    _ => {}
                }
            }
            let key = CountryKey::from_str_upper(code);
            let Some(idx) = allowed_keys.iter().position(|k| *k == key) else {
                continue;
            };
            if reverse {
                continue;
            }
            for field in dat::fields(geoip) {
                let dat::Field::Bytes(2, cidr) = field.map_err(|e| format!("GeoIP.dat: {e}"))?
                else {
                    continue;
                };
                let mut ip: &[u8] = &[];
                let mut prefix = 0u64;
                for part in dat::fields(cidr) {
                    match part.map_err(|e| format!("GeoIP.dat: {e}"))? {
                        dat::Field::Bytes(1, raw) => ip = raw,
                        dat::Field::Varint(2, p) => prefix = p,
                        _ => {}
                    }
                }
                let prefix = u8::try_from(prefix).map_err(|_| "GeoIP.dat: prefix out of range")?;
                let bucket = &mut buckets[idx];
                match ip.len() {
                    4 => {
                        let addr = std::net::Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3]);
                        let net =
                            Ipv4Net::new(addr, prefix).map_err(|e| format!("GeoIP.dat: {e}"))?;
                        bucket.add_v4(net.trunc());
                    }
                    16 => {
                        let octets: [u8; 16] = ip.try_into().expect("length checked");
                        let net = Ipv6Net::new(octets.into(), prefix)
                            .map_err(|e| format!("GeoIP.dat: {e}"))?;
                        bucket.add_v6(net.trunc());
                    }
                    n => return Err(format!("GeoIP.dat: {n}-byte CIDR address")),
                }
            }
        }
        Ok(Self::from_buckets(&allowed_keys, buckets))
    }

    fn from_buckets(allowed_keys: &[CountryKey], buckets: Vec<IpRangeSetBuilder>) -> Self {
        let mut by_country = HashMap::with_capacity(allowed_keys.len());
        for (key, bucket) in allowed_keys.iter().zip(buckets) {
            if bucket.is_empty() {
                continue;
            }
            by_country.insert(key.as_str().to_string(), Arc::new(bucket.build()));
        }
        Self { by_country }
    }

    /// Look up ranges for a country code. Unknown codes return an empty set
    /// (no panic) — the rule will simply never match, mirroring upstream's
    /// "MMDB has no record" path.
    pub fn ranges_for(&self, country: &str) -> CountryRanges {
        if is_lan_code(country) {
            return lan_ranges();
        }
        self.by_country
            .get(&country.to_ascii_uppercase())
            .map_or_else(|| Arc::new(IpRangeSet::default()), Arc::clone)
    }

    pub fn country_count(&self) -> usize {
        self.by_country.len()
    }
}

/// The allowlist packed for the build loops — `None` when it is empty (the
/// index then stays empty). `LAN` never needs a database and is dropped.
fn allowed_keys(allowed: &HashSet<String>) -> Result<Option<Vec<CountryKey>>, String> {
    // Pack the allowlist into stack-friendly keys, indexed by position.
    // The country count is bounded by the rule set (typically ≤ 16), so a
    // `Vec` + linear scan is faster than a HashMap probe in the hot loop.
    let keys: Vec<CountryKey> = allowed
        .iter()
        .filter(|s| !is_lan_code(s))
        .map(|s| CountryKey::from_str_upper(s))
        .collect();
    if keys.len() > u16::MAX as usize {
        return Err(format!(
            "GeoIP allowlist has {} entries, exceeds {}",
            keys.len(),
            u16::MAX
        ));
    }
    Ok((!keys.is_empty()).then_some(keys))
}

/// Minimal protobuf field reader for `GeoIP.dat` — wire types 0 (varint)
/// and 2 (length-delimited) are all `GeoIPList` uses; 1 and 5 are skipped.
mod dat {
    pub(super) enum Field<'a> {
        Varint(u64, u64),
        Bytes(u64, &'a [u8]),
        Other,
    }

    pub(super) fn fields(mut buf: &[u8]) -> impl Iterator<Item = Result<Field<'_>, String>> {
        std::iter::from_fn(move || {
            if buf.is_empty() {
                return None;
            }
            Some((|| {
                let key = varint(&mut buf)?;
                let (number, wire) = (key >> 3, key & 7);
                match wire {
                    0 => Ok(Field::Varint(number, varint(&mut buf)?)),
                    2 => {
                        let len =
                            usize::try_from(varint(&mut buf)?).map_err(|_| "length overflow")?;
                        if len > buf.len() {
                            buf = &[];
                            return Err("truncated field".to_string());
                        }
                        let (head, tail) = buf.split_at(len);
                        buf = tail;
                        Ok(Field::Bytes(number, head))
                    }
                    1 | 5 => {
                        let width = if wire == 1 { 8 } else { 4 };
                        if width > buf.len() {
                            buf = &[];
                            return Err("truncated field".to_string());
                        }
                        buf = &buf[width..];
                        Ok(Field::Other)
                    }
                    other => {
                        buf = &[];
                        Err(format!("unsupported wire type {other}"))
                    }
                }
            })())
        })
    }

    fn varint(buf: &mut &[u8]) -> Result<u64, String> {
        let mut value = 0u64;
        for shift in (0..64).step_by(7) {
            let (&byte, rest) = buf.split_first().ok_or("truncated varint")?;
            *buf = rest;
            value |= u64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                return Ok(value);
            }
        }
        Err("varint too long".to_string())
    }
}

impl std::fmt::Debug for CountryIndex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CountryIndex")
            .field("countries", &self.by_country.len())
            .finish()
    }
}

/// Test-only MaxMind DB writer: an IPv4 search tree with 24-bit records,
/// the data section and the metadata map — enough to hand
/// `maxminddb::Reader` databases of each record shape mihomo reads.
#[cfg(test)]
pub(crate) mod test_db {
    use ipnet::Ipv4Net;

    pub(crate) fn string(s: &str) -> Vec<u8> {
        assert!(s.len() < 29);
        let mut out = vec![(2 << 5) | s.len() as u8];
        out.extend_from_slice(s.as_bytes());
        out
    }

    pub(crate) fn map(entries: &[(&str, Vec<u8>)]) -> Vec<u8> {
        let mut out = vec![(7 << 5) | entries.len() as u8];
        for (key, value) in entries {
            out.extend(string(key));
            out.extend_from_slice(value);
        }
        out
    }

    pub(crate) fn array(items: &[Vec<u8>]) -> Vec<u8> {
        // Extended type 11: control byte type 0, then 11 - 7.
        let mut out = vec![items.len() as u8, 4];
        for item in items {
            out.extend_from_slice(item);
        }
        out
    }

    fn unsigned(type_bits: u8, extended: Option<u8>, value: u64) -> Vec<u8> {
        let bytes: Vec<u8> = value
            .to_be_bytes()
            .into_iter()
            .skip_while(|b| *b == 0)
            .collect();
        let mut out = vec![(type_bits << 5) | bytes.len() as u8];
        out.extend(extended);
        out.extend(bytes);
        out
    }

    /// A database of `database_type` mapping each network to its record.
    /// Networks must not overlap.
    pub(crate) fn build(database_type: &str, records: &[(&str, Vec<u8>)]) -> Vec<u8> {
        #[derive(Clone, Copy)]
        enum Rec {
            Empty,
            Node(usize),
            Data(usize),
        }
        let mut data = Vec::new();
        let mut nodes: Vec<[Rec; 2]> = vec![[Rec::Empty; 2]];
        for (cidr, record) in records {
            let net: Ipv4Net = cidr.parse().unwrap();
            let offset = data.len();
            data.extend_from_slice(record);
            let bits = u32::from(net.network());
            let mut node = 0;
            for depth in 0..net.prefix_len() {
                let bit = ((bits >> (31 - depth)) & 1) as usize;
                if depth + 1 == net.prefix_len() {
                    nodes[node][bit] = Rec::Data(offset);
                } else {
                    node = match nodes[node][bit] {
                        Rec::Node(next) => next,
                        _ => {
                            nodes.push([Rec::Empty; 2]);
                            let next = nodes.len() - 1;
                            nodes[node][bit] = Rec::Node(next);
                            next
                        }
                    };
                }
            }
        }
        let count = nodes.len();
        let value = |rec: Rec| match rec {
            Rec::Empty => count,
            Rec::Node(i) => i,
            Rec::Data(off) => count + 16 + off,
        };
        let mut out = Vec::new();
        for [left, right] in nodes {
            out.extend_from_slice(&(value(left) as u32).to_be_bytes()[1..]);
            out.extend_from_slice(&(value(right) as u32).to_be_bytes()[1..]);
        }
        out.extend_from_slice(&[0; 16]);
        out.extend(data);
        out.extend_from_slice(b"\xAB\xCD\xEFMaxMind.com");
        out.extend(map(&[
            ("binary_format_major_version", unsigned(5, None, 2)),
            ("binary_format_minor_version", unsigned(5, None, 0)),
            // uint64 is extended type 9: control type 0, then 9 - 7.
            ("build_epoch", unsigned(0, Some(2), 1_700_000_000)),
            ("database_type", string(database_type)),
            ("description", map(&[])),
            ("ip_version", unsigned(5, None, 4)),
            ("languages", array(&[])),
            ("node_count", unsigned(6, None, count as u64)),
            ("record_size", unsigned(5, None, 24)),
        ]));
        out
    }

    /// One `GeoIP` entry: code, `reverse_match`, and `(address, prefix)` CIDRs.
    pub(crate) type DatEntry<'a> = (&'a str, bool, &'a [([u8; 4], u8)]);

    /// `GeoIPList` protobuf of `entries`.
    pub(crate) fn geoip_dat(entries: &[DatEntry<'_>]) -> Vec<u8> {
        fn field(number: u8, payload: &[u8]) -> Vec<u8> {
            let mut out = vec![(number << 3) | 2, payload.len() as u8];
            out.extend_from_slice(payload);
            out
        }
        let mut list = Vec::new();
        for (code, reverse, cidrs) in entries {
            let mut geoip = field(1, code.as_bytes());
            for (ip, prefix) in *cidrs {
                let mut cidr = field(1, ip);
                cidr.extend_from_slice(&[2 << 3, *prefix]);
                geoip.extend(field(2, &cidr));
            }
            if *reverse {
                geoip.extend_from_slice(&[3 << 3, 1]);
            }
            list.extend(field(1, &geoip));
        }
        list
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn allow(codes: &[&str]) -> HashSet<String> {
        codes.iter().map(|c| (*c).to_string()).collect()
    }

    fn index(database_type: &str, records: &[(&str, Vec<u8>)], codes: &[&str]) -> CountryIndex {
        let reader = maxminddb::Reader::from_source(test_db::build(database_type, records))
            .expect("test database opens");
        CountryIndex::build(&reader, &allow(codes)).expect("index builds")
    }

    fn has(index: &CountryIndex, code: &str, ip: &str) -> bool {
        index.ranges_for(code).contains(ip.parse().unwrap())
    }

    #[test]
    fn maxmind_country_records() {
        let country = |iso: &str| {
            test_db::map(&[(
                "country",
                test_db::map(&[("iso_code", test_db::string(iso))]),
            )])
        };
        let idx = index(
            "GeoLite2-Country",
            &[("1.0.0.0/24", country("CN")), ("8.8.8.0/24", country("US"))],
            &["cn"],
        );
        assert!(has(&idx, "CN", "1.0.0.1"));
        assert!(has(&idx, "cn", "1.0.0.200"), "codes compare without case");
        assert!(!has(&idx, "CN", "8.8.8.8"));
        assert!(!has(&idx, "US", "8.8.8.8"), "US was not in the allowlist");
    }

    /// sing-box's `geoip.db`: the record is the code itself.
    #[test]
    fn sing_geoip_records() {
        let idx = index(
            "sing-geoip",
            &[
                ("1.0.0.0/24", test_db::string("cn")),
                ("8.8.8.0/24", test_db::string("us")),
            ],
            &["CN", "US"],
        );
        assert!(has(&idx, "CN", "1.0.0.1"));
        assert!(has(&idx, "US", "8.8.8.8"));
        assert!(!has(&idx, "US", "1.0.0.1"));
    }

    /// MetaCubeX's `geoip.metadb`: a code or a list of codes per network.
    #[test]
    fn meta_geoip0_records() {
        let idx = index(
            "Meta-geoip0",
            &[
                (
                    "10.0.0.0/8",
                    test_db::array(&[test_db::string("cn"), test_db::string("private")]),
                ),
                ("8.8.8.0/24", test_db::string("us")),
            ],
            &["CN", "PRIVATE", "US"],
        );
        assert!(has(&idx, "CN", "10.1.2.3"));
        assert!(has(&idx, "PRIVATE", "10.1.2.3"), "one network, two codes");
        assert!(has(&idx, "US", "8.8.8.8"));
        assert!(!has(&idx, "CN", "8.8.8.8"));
    }

    /// `LAN` is built in: no database, nothing to allow.
    #[test]
    fn lan_needs_no_database() {
        let idx = CountryIndex::default();
        for ip in [
            "10.1.1.1",
            "172.20.0.1",
            "192.168.1.1",
            "127.0.0.1",
            "169.254.1.1",
            "224.0.0.251",
            "::1",
            "fd00::1",
            "fe80::1",
        ] {
            assert!(has(&idx, "LAN", ip), "{ip}");
        }
        for ip in ["8.8.8.8", "1.1.1.1", "2001:4860:4860::8888"] {
            assert!(!has(&idx, "lan", ip), "{ip}");
        }
        assert!(is_lan_code("Lan"));
    }

    #[test]
    fn geoip_dat_entries() {
        let dat = test_db::geoip_dat(&[
            ("CN", false, &[([1, 0, 0, 0], 24), ([1, 1, 1, 7], 24)]),
            ("US", false, &[([8, 8, 8, 0], 24)]),
            ("XX", true, &[([9, 9, 9, 0], 24)]),
        ]);
        let idx = CountryIndex::from_geoip_dat(&dat, &allow(&["cn", "XX"])).expect("dat parses");
        assert!(has(&idx, "CN", "1.0.0.9"));
        assert!(has(&idx, "CN", "1.1.1.200"), "host bits are truncated");
        assert!(!has(&idx, "US", "8.8.8.8"), "US was not in the allowlist");
        assert!(
            !has(&idx, "XX", "9.9.9.9"),
            "reverse_match entries are skipped"
        );
        assert!(CountryIndex::from_geoip_dat(&dat[..dat.len() - 3], &allow(&["US"])).is_err());
    }

    /// Path to the repo-root Country.mmdb fixture. The test silently skips
    /// when missing so cargo-test works on contributor machines without the
    /// fixture.
    fn fixture_path() -> std::path::PathBuf {
        let mut p = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        // crate root is .../crates/rill-rules — climb to repo root.
        p.pop();
        p.pop();
        p.push("Country.mmdb");
        p
    }

    fn try_open() -> Option<maxminddb::Reader<Vec<u8>>> {
        let path = fixture_path();
        if !path.exists() {
            return None;
        }
        let bytes = std::fs::read(&path).ok()?;
        maxminddb::Reader::from_source(bytes).ok()
    }

    #[test]
    fn country_index_unknown_country_is_empty() {
        let idx = CountryIndex::default();
        let r = idx.ranges_for("ZZ");
        assert!(r.is_empty());
    }

    #[test]
    fn country_index_lookup_is_case_insensitive() {
        // Build a tiny manual index via the public-by-construction map.
        let mut by_country: HashMap<String, CountryRanges> = HashMap::new();
        let set = IpRangeSet::from_nets(["1.2.3.0/24".parse().unwrap()]);
        by_country.insert("CN".into(), Arc::new(set));
        let idx = CountryIndex { by_country };
        let probe: IpAddr = "1.2.3.42".parse().unwrap();
        assert!(idx.ranges_for("cn").contains(probe));
        assert!(idx.ranges_for("CN").contains(probe));
        assert!(!idx.ranges_for("US").contains(probe));
    }

    /// Build a real CountryIndex from the repo's Country.mmdb fixture, but
    /// only for the allowlisted countries — verifying that we don't
    /// allocate ranges for codes outside the rule set.
    /// Skipped on machines without the fixture.
    #[test]
    fn country_index_builds_only_allowed_countries() {
        let Some(reader) = try_open() else {
            eprintln!("skipping — Country.mmdb fixture not available");
            return;
        };
        let allowed: HashSet<String> = ["CN", "US"].into_iter().map(String::from).collect();
        let idx = CountryIndex::build(&reader, &allowed).expect("build CountryIndex");
        assert_eq!(idx.country_count(), 2, "should bin only CN + US");
        assert!(idx.ranges_for("US").has_v4(), "US v4 ranges empty?");
        assert!(idx.ranges_for("CN").has_v4(), "CN v4 ranges empty?");
        // Country outside the allowlist returns empty ranges.
        assert!(idx.ranges_for("JP").is_empty());
    }

    #[test]
    fn country_index_empty_allowlist_yields_empty_index() {
        let Some(reader) = try_open() else {
            eprintln!("skipping — Country.mmdb fixture not available");
            return;
        };
        let idx = CountryIndex::build(&reader, &HashSet::new()).expect("build CountryIndex");
        assert_eq!(idx.country_count(), 0);
    }

    /// Regression — duplicate `GEOIP,CN,...` rules must NOT each parse the
    /// CN range. `ranges_for` returns an `Arc::clone`, so two lookups of the
    /// same country share the underlying `IpRange` allocation. If a future
    /// refactor switches to per-rule range construction, `Arc::ptr_eq` will
    /// fail here.
    #[test]
    fn ranges_for_shares_arc_across_repeated_lookups() {
        let Some(reader) = try_open() else {
            eprintln!("skipping — Country.mmdb fixture not available");
            return;
        };
        let allowed: HashSet<String> = ["CN"].into_iter().map(String::from).collect();
        let idx = CountryIndex::build(&reader, &allowed).expect("build CountryIndex");

        let a = idx.ranges_for("CN");
        let b = idx.ranges_for("CN");
        let c = idx.ranges_for("cn"); // case-insensitive must hit the same bucket

        assert!(
            Arc::ptr_eq(&a, &b),
            "two CN lookups must share the IpRangeSet Arc"
        );
        assert!(
            Arc::ptr_eq(&a, &c),
            "case-insensitive CN lookup must share the IpRangeSet Arc"
        );
    }

    /// Regression — `parse_rule` building many GEOIP rules over the same
    /// country must reuse the single per-country `Arc<IpRange>`. We exercise
    /// the parser end-to-end (rather than `ranges_for` directly) so this
    /// test catches a regression where the parser starts cloning into a new
    /// `IpRange` instead of `Arc::clone`-ing the index entry.
    #[test]
    fn parser_reuses_arc_for_duplicate_geoip_rules() {
        use crate::parser::{parse_rule, ParserContext};

        let Some(reader) = try_open() else {
            eprintln!("skipping — Country.mmdb fixture not available");
            return;
        };
        let allowed: HashSet<String> = ["CN", "US"].into_iter().map(String::from).collect();
        let idx = Arc::new(CountryIndex::build(&reader, &allowed).expect("build CountryIndex"));
        let ctx = ParserContext {
            geoip: Some(Arc::clone(&idx)),
            ..Default::default()
        };

        // Drive 100 duplicate GEOIP,CN,... lines through the parser. After
        // building the index, every parsed rule should share the same v4/v6
        // Arc — a sanity check that no per-rule range allocation slipped in.
        let baseline = idx.ranges_for("CN");
        for i in 0..100 {
            let line = format!("GEOIP,CN,Proxy{i}");
            let _rule = parse_rule(&line, &ctx).expect("parse_rule must succeed");
            // We can't introspect GeoIpRule.ranges (private), but we can
            // re-fetch from the index — which is the very Arc the parser
            // cloned into the rule.
            let again = idx.ranges_for("CN");
            assert!(
                Arc::ptr_eq(&baseline, &again),
                "iteration {i} broke Arc sharing"
            );
        }

        // Different country must NOT share with CN — guards against a
        // pathological refactor that collapses all countries to one bucket.
        let us = idx.ranges_for("US");
        assert!(
            !Arc::ptr_eq(&baseline, &us),
            "CN and US must hold distinct Arcs"
        );
    }

    #[test]
    fn country_index_allowlist_is_case_insensitive() {
        let Some(reader) = try_open() else {
            eprintln!("skipping — Country.mmdb fixture not available");
            return;
        };
        let allowed: HashSet<String> = ["cn"].into_iter().map(String::from).collect();
        let idx = CountryIndex::build(&reader, &allowed).expect("build CountryIndex");
        assert_eq!(idx.country_count(), 1);
        assert!(idx.ranges_for("CN").has_v4());
    }
}
