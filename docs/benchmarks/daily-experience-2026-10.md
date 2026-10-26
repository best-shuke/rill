# Daily-use experience vs mihomo (2026-10)

[mihomo-gap-2026-10.md](mihomo-gap-2026-10.md) closed the bandwidth,
CPU and footprint gaps: rill 0.1.3 matches or beats mihomo v1.19.30 on
every bulk, latency, connection-rate and memory row. Below 1 Gbps none of
that is what a user notices. What they notice is how long a page waits
before its first byte — DNS and the dial — and what happens when something
on the path misbehaves. This pass compared rill and mihomo on exactly that
path, found six places where mihomo did better, and fixed them.

## Where the time goes in a daily connection

A browser request through a proxy kernel with `fake-ip` (FlowBar's default)
costs, before the first byte:

1. the client's DNS query — answered locally from the fake-IP pool, free;
2. rule matching — a real lookup when a rule needs the IP (`GEOIP`,
   `IP-CIDR` without `no-resolve`), and always for a `DIRECT` dial;
3. the dial — TCP (+ TLS / REALITY) to the proxy, or to the destination
   for `DIRECT`;
4. the request itself.

Steps 2 and 3 are where the two kernels differed.

## The gaps found

| # | Behaviour | mihomo v1.19.30 | rill 0.1.3 | rill now |
|---|---|---|---|---|
| 1 | DoH upstream transport | One HTTP/2 connection per upstream, pinged after 30 s silence, closed after 5 min idle | HTTP/1.1 `Connection: close`: TCP + TLS (+ a proxy dial for `#PROXY` upstreams) for every query | One HTTP/2 connection, same ping / idle policy; HTTP/1.1 fallback when the server does not negotiate `h2` |
| 2 | A cached answer past its TTL | Served at once (TTL 1) while a background query refreshes it | The connection or client waits for a full upstream lookup | Served at once for up to an hour past its TTL, refreshed in the background — on the dial path and from the DNS server (TTL 1) |
| 3 | A host with several addresses, the first unreachable | Families raced 300 ms apart; within a family serial, so a blackholed first IPv4 address fails the dial unless `tcp-concurrent: true` | Serial: a blackholed first address burns the 5 s dial deadline, the connection fails | RFC 8305 Happy Eyeballs: families interleaved, next attempt after 250 ms or at once on failure; `tcp-concurrent: true` starts all at once |
| 4 | A dial cut by a reset / early EOF | Retried up to 10 times inside the 5 s deadline — every error, so a refused port is held for seconds | Failed at once | Retried up to 3 times (50, 100 ms) for reset / abort / EOF / broken pipe only; a refusal, DNS failure or timeout returns at once |
| 5 | Nagle on `DIRECT` and DNS-upstream sockets | Off (Go default) | On: small pipelined writes wait for the peer's delayed ACK | Off |
| 6 | TCP keepalive on outbound sockets | 15 s (Go default) | None: a peer that vanished without FIN/RST is found only by the application | 30 s idle, 15 s interval, 4 probes |

`tcp-concurrent` used to be ignored; it is now read at startup and on
`PUT /configs`.

## Measurements

Host: the 4-core Neoverse-N1 VM of the earlier documents. "before" is
rill v0.1.3 (`66f5034`, built in the same session), "after" this change,
mihomo v1.19.30. The host's own traffic goes through an idle production
mihomo TUN (`stack: mixed`), which all three pay alike; the dial tests run
in a private network namespace to avoid it.

### 1. DoH lookups (`https://1.1.1.1/dns-query`, redir-host)

Thirty distinct names queried 200 ms apart, then a burst of 21 at once,
then one more after 40 s of silence. Medians in ms; the DoH round-trip
itself is ~2 ms here.

| | sequential | burst | after 40 s idle |
|---|---:|---:|---:|
| rill before | 56.0 | 64.1 | 58.0 |
| **rill after** | **3.7** | **8.6** | **4.2** |
| mihomo | 4.1 | 20.7 | 4.7 |

The burst column favours whichever kernel runs second, because Cloudflare
has then cached the names; across three alternating rounds rill's burst
median was 8.6–18.0 ms and mihomo's 7.8–20.7 ms. Before the change every
query paid a TCP and TLS handshake — ~50 ms on this 2 ms path, and a
multiple of the proxy RTT for a `#PROXY` upstream (TCP + REALITY to the
proxy, then TCP-in-tunnel + TLS to the resolver: four to five proxy round
trips per query instead of one).

### 2. A name whose TTL has run out

Local upstream that answers after 300 ms with TTL 1 (clamped to rill's
10 s floor); query, wait 12 s, query again.

| | first query | after expiry | next |
|---|---:|---:|---:|
| rill before | 301.3 ms | 301.1 ms | 0.2 ms |
| **rill after** | 301.1 ms | **0.2 ms** | 0.2 ms |
| mihomo | 301.3 ms | 0.3 ms | 0.3 ms |

### 3. First address blackholed

`he.test` resolves to `[192.0.2.1, 127.0.0.1]`; 192.0.2.1 is routed into a
dummy interface, so its SYNs vanish. `curl` through each kernel's mixed
port, `MATCH,DIRECT`, five runs each (all five identical within 5 ms).

| | result | time |
|---|---|---:|
| rill before | fails (dial deadline) | 5.00 s |
| **rill after** | 200 | **0.25 s** |
| rill after, `tcp-concurrent: true` | 200 | 0.001 s |
| mihomo | fails (dial deadline) | 5.00 s |
| mihomo, `tcp-concurrent: true` | 200 | 0.001 s |

### 4. No regression on the bulk path

`rill-bench`, SOCKS5 → DIRECT, two runs each:

| | v0.1.3 | after |
|---|---|---|
| 64 MB throughput | 12.35 / 13.42 Gbps | 13.59 / 13.08 Gbps |
| Latency p50 / p99 | 260–263 / 394–411 µs | 262–274 / 402–606 µs |
| Connections/sec | 10 370 / 10 752 | 11 069 / 10 409 |
| RSS idle | 14.2 MB | 14.6 MB |
| Stripped binary, `release` (`full`) | 19.97 MB | 20.50 MB |
| Stripped binary, `release-small` (`minimal`) | 8.67 MB | 8.74 MB |

The first build of this change was 21.02 MB: the DoH client instantiated
h2's connection machinery for its own stream type (+571 KB of h2 code).
It now goes through non-generic wrappers in `rill_transport::h2_common`
and `TlsLayer::connect_negotiated`, reusing the transport crate's
`Connection<Box<dyn Stream>, Bytes>`; h2's share of the delta is 90 KB.

In a `minimal` build nothing else uses h2's client, so the kept DoH
connection alone cost 531 KB at `opt-level = "z"`. It sits behind
rill-dns's `doh-h2` feature, which `full` (`dns-encrypted`) enables and
`minimal` leaves out: router builds keep one HTTP/1.1 connection per DoH
query and grow 64 KB (glibc aarch64 build; the ADR-0007 caps are measured
on musl).

## Still behind or not attempted

- **DoT** still opens a TLS connection per query — as mihomo does, so not
  a gap, but pipelining over a kept connection (RFC 7858 §3.3) would give
  DoT what DoH now has.
- **DoH over HTTP/3** (`#h3=true`, `prefer-h3`) is ignored; HTTP/2 is used.
- **`unified-delay`** is not implemented: url-test delays include the
  handshake, so they read higher than mihomo's with `unified-delay: true`
  (selection between members is unaffected, all carry the same overhead).
- A kept `#PROXY` DoH connection stays on the group member it was opened
  through until it closes, as in mihomo.
- The bulk-path items of [mihomo-gap-2026-10.md](mihomo-gap-2026-10.md)
  §"Still behind" (plain-VLESS splice, multi-queue TUN) are unchanged.
