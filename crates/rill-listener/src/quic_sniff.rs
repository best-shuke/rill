//! QUIC SNI sniffing: the server name of a QUIC (HTTP/3) connection, read
//! from the TLS ClientHello its client Initial packets carry.
//!
//! Initial packets are encrypted with keys derived from the client's
//! Destination Connection ID alone (RFC 9001 §5.2), so anyone on the path
//! can decrypt them — which is what this does, as mihomo's QUIC sniffer
//! does. Browsers spread a post-quantum ClientHello over two or three
//! Initial packets and shuffle its CRYPTO frames, so the sniffer is fed
//! datagram by datagram and reassembles the CRYPTO stream by offset.
//!
//! QUIC v1 (RFC 9000), v2 (RFC 9369) and draft-29 are understood.

use aes::cipher::{BlockEncrypt, KeyInit};
use aes_gcm::aead::AeadInPlace;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use smol_str::SmolStr;

const V1: u32 = 0x0000_0001;
const V2: u32 = 0x6b33_43cf;
const DRAFT29: u32 = 0xff00_001d;

const SALT_V1: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
];
const SALT_V2: [u8; 20] = [
    0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb,
    0xf9, 0xbd, 0x2e, 0xd9,
];
const SALT_DRAFT29: [u8; 20] = [
    0xaf, 0xbf, 0xec, 0x28, 0x99, 0x93, 0xd2, 0x4c, 0x9e, 0x97, 0x86, 0xf1, 0x9c, 0x61, 0x11, 0xe0,
    0x43, 0x90, 0xa8, 0x99,
];

/// Give up after this many datagrams without a complete ClientHello.
pub const MAX_DATAGRAMS: usize = 4;
/// Largest CRYPTO stream the sniffer buffers.
const MAX_CRYPTO: usize = 64 * 1024;

/// What one more datagram told the sniffer.
#[derive(Debug, PartialEq, Eq)]
pub enum QuicSniff {
    /// The ClientHello is complete and named this server.
    Host(SmolStr),
    /// A QUIC Initial with part of a ClientHello: feed the next datagram.
    NeedMore,
    /// Not a QUIC client Initial, or a ClientHello without a name.
    Fail,
}

/// Per-flow reassembly state.
#[derive(Default)]
pub struct QuicSniffer {
    /// CRYPTO frame fragments as `(offset, bytes)`.
    fragments: Vec<(usize, Vec<u8>)>,
    buffered: usize,
    datagrams: usize,
}

impl QuicSniffer {
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed the next client datagram of the flow.
    pub fn feed(&mut self, datagram: &[u8]) -> QuicSniff {
        self.datagrams += 1;
        let mut rest = datagram;
        let mut any = false;
        // A datagram may coalesce several packets (Initial + 0-RTT, …).
        while let Some(packet) = LongHeader::parse(rest) {
            rest = &rest[packet.total_len..];
            if !packet.is_initial {
                continue;
            }
            let Some(plain) = decrypt_initial(datagram_slice(datagram, rest, &packet), &packet)
            else {
                return QuicSniff::Fail;
            };
            if !self.collect_crypto(&plain) {
                return QuicSniff::Fail;
            }
            any = true;
        }
        if !any {
            return QuicSniff::Fail;
        }
        match self.client_hello() {
            Some(Ok(host)) => QuicSniff::Host(host),
            Some(Err(())) => QuicSniff::Fail,
            None if self.datagrams >= MAX_DATAGRAMS => QuicSniff::Fail,
            None => QuicSniff::NeedMore,
        }
    }

    /// Walk the frames of a decrypted Initial payload; `false` on garbage.
    fn collect_crypto(&mut self, mut p: &[u8]) -> bool {
        while let Some(&ty) = p.first() {
            p = &p[1..];
            match ty {
                0x00 | 0x01 => {} // PADDING, PING
                0x02 | 0x03 => {
                    // ACK: largest, delay, range count, first range, ranges.
                    let Some(rest) = skip_varints(p, 3) else {
                        return false;
                    };
                    p = rest;
                    let Some((count, rest)) = varint(p) else {
                        return false;
                    };
                    p = rest;
                    let Some(rest) = skip_varints(p, 0) else {
                        return false;
                    };
                    p = rest;
                    let pairs = usize::try_from(count).unwrap_or(usize::MAX);
                    let Some(rest) = pairs.checked_mul(2).and_then(|n| skip_varints(p, n)) else {
                        return false;
                    };
                    p = rest;
                    if ty == 0x03 {
                        let Some(rest) = skip_varints(p, 3) else {
                            return false;
                        };
                        p = rest;
                    }
                }
                0x06 => {
                    let Some((offset, rest)) = varint(p) else {
                        return false;
                    };
                    let Some((len, rest)) = varint(rest) else {
                        return false;
                    };
                    let (Ok(offset), Ok(len)) = (usize::try_from(offset), usize::try_from(len))
                    else {
                        return false;
                    };
                    let Some(data) = rest.get(..len) else {
                        return false;
                    };
                    if offset.saturating_add(len) > MAX_CRYPTO || self.buffered + len > MAX_CRYPTO {
                        return false;
                    }
                    self.buffered += len;
                    self.fragments.push((offset, data.to_vec()));
                    p = &rest[len..];
                }
                0x1c | 0x1d => return true, // CONNECTION_CLOSE
                _ => return false,
            }
        }
        true
    }

    /// The contiguous CRYPTO stream from offset 0, as far as it goes.
    fn contiguous(&self) -> Vec<u8> {
        let mut frags: Vec<&(usize, Vec<u8>)> = self.fragments.iter().collect();
        frags.sort_by_key(|(off, _)| *off);
        let mut out: Vec<u8> = Vec::new();
        for (off, data) in frags {
            if *off > out.len() {
                break;
            }
            let skip = out.len() - off;
            if skip < data.len() {
                out.extend_from_slice(&data[skip..]);
            }
        }
        out
    }

    /// `None` while the ClientHello is incomplete; then its server name.
    fn client_hello(&self) -> Option<Result<SmolStr, ()>> {
        let stream = self.contiguous();
        if stream.len() < 4 {
            return None;
        }
        if stream[0] != 0x01 {
            return Some(Err(()));
        }
        let len =
            (usize::from(stream[1]) << 16) | (usize::from(stream[2]) << 8) | usize::from(stream[3]);
        if stream.len() < 4 + len {
            return None;
        }
        let hello = &stream[..4 + len];
        let Ok(record_len) = u16::try_from(hello.len()) else {
            return Some(Err(()));
        };
        // Present it as a TLS record so the TCP sniffer's parser reads it.
        let mut record = Vec::with_capacity(5 + hello.len());
        record.extend_from_slice(&[0x16, 0x03, 0x01]);
        record.extend_from_slice(&record_len.to_be_bytes());
        record.extend_from_slice(hello);
        Some(rill_common::sniffer::sniff_tls(&record).ok_or(()))
    }
}

/// The bytes of `packet` within `datagram`, given what follows it.
fn datagram_slice<'a>(datagram: &'a [u8], rest: &[u8], packet: &LongHeader) -> &'a [u8] {
    let end = datagram.len() - rest.len();
    &datagram[end - packet.total_len..end]
}

struct LongHeader {
    version: u32,
    is_initial: bool,
    dcid: [u8; 20],
    dcid_len: usize,
    /// Offset of the (protected) packet number.
    pn_offset: usize,
    /// Bytes of packet number plus payload.
    payload_len: usize,
    total_len: usize,
}

impl LongHeader {
    fn parse(p: &[u8]) -> Option<Self> {
        let first = *p.first()?;
        if first & 0xc0 != 0xc0 {
            return None; // short header or not QUIC
        }
        let version = u32::from_be_bytes(p.get(1..5)?.try_into().ok()?);
        let ty = (first >> 4) & 0x03;
        let is_initial = match version {
            V1 | DRAFT29 => ty == 0,
            V2 => ty == 1,
            _ => return None,
        };
        let mut pos = 5;
        let dcid_len = usize::from(*p.get(pos)?);
        if dcid_len > 20 {
            return None;
        }
        pos += 1;
        let mut dcid = [0u8; 20];
        dcid[..dcid_len].copy_from_slice(p.get(pos..pos + dcid_len)?);
        pos += dcid_len;
        let scid_len = usize::from(*p.get(pos)?);
        pos += 1 + scid_len;
        // Initial and 0-RTT/Handshake both carry Length; Retry does not.
        let retry = match version {
            V2 => ty == 0,
            _ => ty == 3,
        };
        if retry {
            return None;
        }
        if is_initial {
            let (token_len, rest) = varint(p.get(pos..)?)?;
            let token_len = usize::try_from(token_len).ok()?;
            pos = p.len() - rest.len() + token_len;
        }
        let (length, rest) = varint(p.get(pos..)?)?;
        let payload_len = usize::try_from(length).ok()?;
        let pn_offset = p.len() - rest.len();
        let total_len = pn_offset.checked_add(payload_len)?;
        if total_len > p.len() {
            return None;
        }
        Some(Self {
            version,
            is_initial,
            dcid,
            dcid_len,
            pn_offset,
            payload_len,
            total_len,
        })
    }
}

fn varint(p: &[u8]) -> Option<(u64, &[u8])> {
    let first = *p.first()?;
    let len = 1usize << (first >> 6);
    let bytes = p.get(..len)?;
    let mut v = u64::from(first & 0x3f);
    for &b in &bytes[1..] {
        v = (v << 8) | u64::from(b);
    }
    Some((v, &p[len..]))
}

fn skip_varints(mut p: &[u8], n: usize) -> Option<&[u8]> {
    for _ in 0..n {
        p = varint(p)?.1;
    }
    Some(p)
}

fn hmac_sha256(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC takes any key length");
    for part in parts {
        mac.update(part);
    }
    mac.finalize().into_bytes().into()
}

/// TLS 1.3 HKDF-Expand-Label with an empty context, for `len <= 32`.
fn expand_label(secret: &[u8; 32], label: &str, len: usize) -> Vec<u8> {
    let full = format!("tls13 {label}");
    let mut info = Vec::with_capacity(4 + full.len());
    info.extend_from_slice(&(len as u16).to_be_bytes());
    info.push(full.len() as u8);
    info.extend_from_slice(full.as_bytes());
    info.push(0);
    hmac_sha256(secret, &[&info, &[1]])[..len].to_vec()
}

/// Decrypt one client Initial packet; its plaintext frames.
fn decrypt_initial(packet: &[u8], header: &LongHeader) -> Option<Vec<u8>> {
    let (salt, prefix) = match header.version {
        V1 => (&SALT_V1, "quic"),
        V2 => (&SALT_V2, "quicv2"),
        _ => (&SALT_DRAFT29, "quic"),
    };
    let initial = hmac_sha256(salt, &[&header.dcid[..header.dcid_len]]);
    let client: [u8; 32] = expand_label(&initial, "client in", 32).try_into().ok()?;
    let key = expand_label(&client, &format!("{prefix} key"), 16);
    let iv = expand_label(&client, &format!("{prefix} iv"), 12);
    let hp = expand_label(&client, &format!("{prefix} hp"), 16);

    // Header protection: a mask from an AES-ECB of a payload sample.
    let pn_offset = header.pn_offset;
    let sample = packet.get(pn_offset + 4..pn_offset + 20)?;
    let mut mask = aes::Block::clone_from_slice(sample);
    aes::Aes128::new_from_slice(&hp)
        .ok()?
        .encrypt_block(&mut mask);
    let mut head = packet[..pn_offset + 4].to_vec();
    head[0] ^= mask[0] & 0x0f;
    let pn_len = usize::from(head[0] & 0x03) + 1;
    let mut pn: u64 = 0;
    for i in 0..pn_len {
        head[pn_offset + i] ^= mask[1 + i];
        pn = (pn << 8) | u64::from(head[pn_offset + i]);
    }
    head.truncate(pn_offset + pn_len);

    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&iv);
    for (i, b) in pn.to_be_bytes().iter().enumerate() {
        nonce[4 + i] ^= b;
    }
    let ciphertext_end = pn_offset + header.payload_len;
    let mut body = packet.get(pn_offset + pn_len..ciphertext_end)?.to_vec();
    if body.len() < 16 {
        return None;
    }
    let tag_at = body.len() - 16;
    let tag = aes_gcm::Tag::clone_from_slice(&body[tag_at..]);
    body.truncate(tag_at);
    aes_gcm::Aes128Gcm::new_from_slice(&key)
        .ok()?
        .decrypt_in_place_detached((&nonce).into(), &head, &mut body, &tag)
        .ok()?;
    Some(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Two QUIC v1 client Initials (DCID 0102030405060708) carrying one
    /// 1577-byte ClientHello for `split.example.com`: the first holds a
    /// PING and the CRYPTO ranges 300..900 and 0..300 in that order, the
    /// second 900..end. Made by an independent Python implementation of
    /// RFC 9001 packet protection whose key schedule reproduces the
    /// RFC's Appendix A.1 keys.
    const SPLIT_INITIAL_1: &str = concat!(
        "c7000000010801020304050607080000445e96f438f35b87462e9aeb6055bbfe3abb10a13b1578de4210e59ce0e689a3",
        "a43b0f50ccb1ed9499e0ff4b4c93a9d58c64d9d583a9ecf532f1ae888a52cf83902be95705ceb7b0cdb8e558aaa57b60",
        "a9fef73d7c19212732ae2f2aa537258e18b52f8d4c8fb74b8d9151173a5d3ba052eb082f3a0c53c1aa39135a9c58387f",
        "b26865732c4088627394a09a4b794b469a89c2643c906ba1cf2d77100b0ab347f6538f4bea953c7a63ae333cdf15dcfc",
        "58d6076406152f8f408febed4a04ebba9ae8083d51d8f2c20883c01ddce2978099e3babe88a0e79086084195b80ee7b9",
        "105dfec8673977d43ca40fa034895efc630e8b78d2266313aebc2476282f7abc3bd22f36f035ed5348e03294a57329c3",
        "c8da900c75b81287e5df9a009fc389198d0be1ccfe37d4c6826a842e9e3fe1dba5bb925b584aa8e1bd9e2fbfb3d88f1c",
        "076a169564c514e141eff06fb6b397a9daec4b0e4b69745a173d948aa85b23719a4840985f6256ae6f380408814da0fd",
        "f8989e966ef652f11afe050e499f7148b652b9fa15c790f3f6642359134a6d7972001311d0d52f49caf0d0cce7a149f8",
        "0419e6a712a0357257acdc54ecbc31b4f217501368c02ed471c6c735a9f17c1cc593700b963a4da3d3fd956c848064b7",
        "27fdca6333839b32bb59df0176d854cbd5d71c67d029eb62754868c25642cc3349d221361a684385f68e193408d64ccf",
        "0b7441e9d0f4fdfa256632248cc796851f3c43b0fb4d9bd37beeacb9a6c1cbba953c1f78fced24da0b26f0c01b00c7de",
        "2f1d95914a7bc2a08dd5d73ba41de63ff660336d23561725db2a577bafbb2de381cc170e0372231052398700a0539d8c",
        "072209df65ec028333aca1c7c6b977ed590f0dcf83e997a05366b85bc23b8d01d88633c379f946f521b5316a65736b2a",
        "55a281b6f4acc84549e7099cbec5b76a2d02d34cad3b031d168992445c9a6dd8a994c7317219d3e95428162feaf52751",
        "3303c11f86919998058512a04a33a590fec58f3532f0d47801f2bb7ddb74658e093738ba53a4c5953fd2eabec0ea2bf8",
        "a5277d4a38c1f99c7ca3ffbe325d9465d8b5a0be91496e0dd205ed0f3c2f335216c98beb9a4d9801c0c1512ffb35d4e7",
        "e665df314c768d4d77085a4c7bf3d5ba21709abf78a0a995afde7b7078d47325a664d47aeb466aa3e0129686f56545f6",
        "be182ce47b0676e1c5787b82c4030eeb8067e5357b246831e20353a3a5a97366c4e0edece2b1216b2515aa500ed2120c",
        "28903944b06949187922b30282be82e38e1a172aafab96e995367485c9360ff44a7fa3d71b894f58e176550a9e1b1910",
        "bf4c1ec30476c9bf5678e25cdd3ef2b8721ce6a6a9b91a9db96761b43a95f261fa14203b1f3a5414607f410bd7049522",
        "0915b27eb54edb3724413b30f51d45f31d24480920ba40bedb7eddf4432cd41ba5ed5114c744399f6771bcc423328f8b",
        "062c7ae55281d37c0702cfdf9408caccfd15f5f02d90105075d9eabe51baea7bd6336095d3ffba024651d03525cec073",
        "e9ed728f1dd71484ecadc3489bed1868998675d3821d253b004e8cb65c0fee63",
    );
    const SPLIT_INITIAL_2: &str = concat!(
        "cb000000010801020304050607080000445e3c711d8b731e7e058169ef380f64ac4c52dff4d3ae462219af04c3d36bc7",
        "c00e583b5ca9c072a03b09e825cec7015beb2cb19bbc7218ed8687497ef5ffbcfb5c29c17ef6a58056778a59cd01a68e",
        "7ecabcd50191b3a6ffa6c941ef196f685c1f02072add7fd08bc5bba50dcba1935cc9628abbf47ee8f181d5d2973f3f53",
        "8086719a7cfa432bf84b4d7016808533f49e235d867aaefa3854accb7fd7ec1bf9fd542a9a8adcaa6e8d61a1c83caac3",
        "bc71af71f9db7eb08b0a78db345217b0a3da1a0362390387116e6cb6449458236d139126414a97ccbb0d4bc64c60a620",
        "75470fe2cc6367765e3c80892da073af74fb266bba470ec3232fd5a4d5af5c8bd6b851f6784244fbc66b01e73b24196f",
        "26eadbea42494ba2c18ad40c70588ef91414cb21e91d8dd7787199e282c5c1cbe3de263c9cbae5c044cf22d2a45c8f79",
        "4d371fd507fe77256a05e17abcb322ea01bac1b4c01921a103c9aa6db1681d6a64226ff8b5990f43a762ab135d8f2959",
        "fd9b4336b712b53e9d2a11097328c8d6d5e4f93d7d8f4f62d80d8d540bbededaa4db98c45c81f3f1e1f223bf11771572",
        "b5a51883d59f211a49a6b861a87991b4f0b9411deb386dfffaaebad0a0f61617518ecfd072f83dbe9f9d1230b0e1c1df",
        "3c3bd384c8212b20eeeb76baf875c66f9868649b7b734ab0c6be8dc816601565015d247d4a85877d09af8eac23228366",
        "cf4e7a08ef1d201b6f0cc1996ecb469c366795d3faf676dbd8b1a45deeca19d13fa557a39415ac4bd0d016e374ccd496",
        "73c2354dd776713e4fba3e750eab1eb343201c1f370b530278c2b7fbc220aad709a00bbfde7a65b3a96ee5d230118b1c",
        "c3ae34a1331bbc538019622f41a6c93e10d8c6ca45e3f17e0cfa6ffb84b55fcae2e0b23d1018473fbc6a533ed0e160ed",
        "47010da090721fcfa961edc618fd5ec8a43c2e9ae855ac76972d37f03fbd4d019f268cf26b53288ddf5968205384b902",
        "2c8f06f771fa7b5b6abdeb10f46d186ff88427c2d082b9311a2bbd89083fb327a21f56d4c8031d512bb60998211f81e3",
        "3980bdb52999d6d5c50f234969f39f3be01d4b2d7055acfc10f1e851b33653a4612f7ddaed7010ee0607f090811dde04",
        "40708c8a56375e2bb2391fab233a0d68eccc75fbb2d366a0a50f32ede3cb527431a035d56f0e3f85fa8f3b24ea4899e5",
        "09c8a93051acf64a6634de494680fa073081d40d3a3ae9504c132c94cfc81ad3837c1a9217f754dc350c78c9afc65613",
        "6ff11ca38b5b79aec5589af5b6ce9532949a756ecc4e15ceefcb3e7cdcf0b48ec362c39b955991dc922219ab49935869",
        "d8f5eefc8adc1e39ad2681faa889e24202b7066d9b07dd20b8d016e9d2570c826971d552c01d36b5505d65bb81a26c57",
        "63ce995b585ab509f4e12602236bb07cadaf11e68c0f2283172d4fa26f4dd757e4ad0539f1b99acc6437f5fc312cc124",
        "3a61cbf2ee9f75a4da8286ac3724e7243d76134ebef025ef800d5d331599d877a0933327eed94bb5640eae4644a55c98",
        "3d3abb23beb41551a5bc6ada76dbf0a0d55da27fda8eb3f890dfa48c67d2853a",
    );

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn split_client_hello_is_reassembled_across_initials() {
        let mut sniffer = QuicSniffer::new();
        assert_eq!(sniffer.feed(&hex(SPLIT_INITIAL_1)), QuicSniff::NeedMore);
        assert_eq!(
            sniffer.feed(&hex(SPLIT_INITIAL_2)),
            QuicSniff::Host("split.example.com".into())
        );
    }

    #[test]
    fn coalesced_initials_in_one_datagram() {
        let mut both = hex(SPLIT_INITIAL_1);
        both.extend(hex(SPLIT_INITIAL_2));
        assert_eq!(
            QuicSniffer::new().feed(&both),
            QuicSniff::Host("split.example.com".into())
        );
    }

    #[test]
    fn a_tampered_packet_fails() {
        let mut packet = hex(SPLIT_INITIAL_1);
        let last = packet.len() - 1;
        packet[last] ^= 1;
        assert_eq!(QuicSniffer::new().feed(&packet), QuicSniff::Fail);
    }

    #[test]
    fn gives_up_after_the_datagram_budget() {
        let mut sniffer = QuicSniffer::new();
        let first = hex(SPLIT_INITIAL_1);
        for _ in 1..MAX_DATAGRAMS {
            assert_eq!(sniffer.feed(&first), QuicSniff::NeedMore);
        }
        assert_eq!(sniffer.feed(&first), QuicSniff::Fail);
    }

    #[test]
    fn non_quic_fails() {
        assert_eq!(QuicSniffer::new().feed(b"\x00\x01hello"), QuicSniff::Fail);
        assert_eq!(QuicSniffer::new().feed(&[0x40; 40]), QuicSniff::Fail);
    }

    #[test]
    fn varints() {
        assert_eq!(varint(&[0x25]).unwrap().0, 37);
        assert_eq!(varint(&[0x7b, 0xbd]).unwrap().0, 15293);
        assert_eq!(varint(&[0x9d, 0x7f, 0x3e, 0x7d]).unwrap().0, 494_878_333);
        assert!(varint(&[0x7b]).is_none());
    }

    #[test]
    fn fragments_reassemble_out_of_order() {
        let mut s = QuicSniffer::new();
        s.fragments.push((3, vec![3, 4]));
        s.fragments.push((0, vec![0, 1, 2]));
        s.fragments.push((10, vec![10]));
        assert_eq!(s.contiguous(), vec![0, 1, 2, 3, 4]);
    }
}
