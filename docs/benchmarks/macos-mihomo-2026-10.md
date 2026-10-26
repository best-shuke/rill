# macOS performance comparison, 2026-10-26

The final changes improve macOS relay, SS, Trojan and VMess throughput, and
privileged tests now cover the TUN path. They **do not establish an
across-the-board lead over mihomo**: several small-message paths, VLESS bulk,
VMess concurrent bulk and some latency tails remain slower. The privileged
follow-up below records those remaining gaps as well as the gains.

The tables before that follow-up preserve the initial pass against `a98cc9d`.
The earlier [Linux results](mihomo-gap-2026-10.md) cannot establish macOS parity.

This is a local loopback comparison on an Apple M4 (Mac16,12, 4 performance +
6 efficiency cores, 16 GiB), macOS 15.6 / Darwin 24.6.0, with existing desktop
load and FlowBar left running. No builds ran during timed measurements.
Both proxies enabled their REST controllers and connection statistics; each
used separate loopback ports and a temporary home. The initial pass changed
no system routes; the privileged follow-up used only its isolated test subnet.

- Baseline: `a98cc9d`, full default features, Rust 1.98.1.
- Optimized: the accompanying working-tree changes, same compiler and release
  profile (`opt-level = 3`, LTO, one codegen unit, stripped).
- Comparator: [mihomo v1.19.33](https://github.com/MetaCubeX/mihomo/releases/tag/v1.19.33),
  official darwin/arm64 build, Go 1.26.10, `with_gvisor`.
- Outbound peer: official sing-box 1.14.4 on loopback. SS uses AES-128-GCM,
  SS2022 uses 2022-blake3-aes-128-gcm, ChaCha uses chacha20-ietf-poly1305;
  VLESS is plain TCP, Trojan uses local TLS, VMess uses `auto` security.

**Standard TCP workloads.** These reuse the unchanged
`rill-bench/examples/throughput_interleaved.rs` and its normal echo server.
The example warms every proxy and rotates all six three-proxy orderings.
DIRECT has 12 recorded rounds; each outbound has 6. Every sample is retained
in the median, including slow samples; incomplete echoes fail the run.
Gbps counts upload plus echo (twice the payload), and is not a WAN link rate.
The 4 KiB case is 10,000 sequential round trips on one connection; the 1 MiB
case is ten connections, and the 64 MiB case is one connection.

| Path | Workload | Baseline Gbps | Optimized Gbps | mihomo Gbps | Optimized vs mihomo |
|---|---|---:|---:|---:|---:|
| DIRECT | 4 KiB × 10000 | 2.076 | 2.068 | 2.021 | +2.3% |
| DIRECT | 1 MiB × 10 | 40.598 | 45.939 | 42.455 | +8.2% |
| DIRECT | 64 MiB × 1 | 43.905 | 52.318 | 52.181 | +0.3% |
| VLESS | 4 KiB × 10000 | 1.337 | 1.338 | 1.381 | -3.1% |
| VLESS | 1 MiB × 10 | 26.536 | 28.385 | 26.413 | +7.5% |
| VLESS | 64 MiB × 1 | 28.239 | 37.431 | 38.199 | -2.0% |
| SS AES-GCM | 4 KiB × 10000 | 1.248 | 1.276 | 1.314 | -2.9% |
| SS AES-GCM | 1 MiB × 10 | 16.091 | 18.701 | 18.280 | +2.3% |
| SS AES-GCM | 64 MiB × 1 | 20.930 | 23.528 | 23.508 | +0.1% |
| SS2022 | 4 KiB × 10000 | 1.250 | 1.268 | 1.316 | -3.6% |
| SS2022 | 1 MiB × 10 | 19.201 | 21.532 | 20.386 | +5.6% |
| SS2022 | 64 MiB × 1 | 27.200 | 29.936 | 30.351 | -1.4% |
| SS ChaCha20 | 4 KiB × 10000 | 1.049 | 1.060 | 1.027 | +3.2% |
| SS ChaCha20 | 1 MiB × 10 | 8.919 | 10.113 | 8.217 | +23.1% |
| SS ChaCha20 | 64 MiB × 1 | 8.752 | 9.176 | 10.680 | -14.1% |
| Trojan/TLS | 4 KiB × 10000 | 1.230 | 1.231 | 1.303 | -5.5% |
| Trojan/TLS | 1 MiB × 10 | 14.076 | 14.984 | 12.731 | +17.7% |
| Trojan/TLS | 64 MiB × 1 | 23.583 | 24.404 | 25.208 | -3.2% |
| VMess | 4 KiB × 10000 | 1.225 | 1.251 | 1.303 | -4.0% |
| VMess | 1 MiB × 10 | 14.129 | 17.200 | 16.786 | +2.5% |
| VMess | 64 MiB × 1 | 16.845 | 20.969 | 23.769 | -11.8% |

Small differences, especially below about 5%, should be treated as parity
candidates on this shared host, not a general speedup guarantee. The larger
remaining losses are SS ChaCha20 single-flow throughput and VMess bulk.

**Sustained bulk.** A separate native driver uses 256 KiB client I/O, a
64 KiB echo buffer, and validates every received byte. Each leg transfers
256 MiB once on one connection, then 256 MiB on each of four concurrent
connections. CPU covers both sublegs (2,684,354,560 relayed bytes), measured
on the proxy process only with `proc_pid_rusage`; Apple absolute-time ticks
are converted with `mach_timebase_info` (125/3 on this host). RSS is sampled
after the load, not an independently sampled peak. These rows have different
endpoints from the standard workloads above. DIRECT has 12 rounds, SS and
VMess 6; ordering is balanced across all six permutations.

| Path / metric | Baseline | Optimized | mihomo |
|---|---:|---:|---:|
| DIRECT, four-flow Gbps | 30.97 | 46.25 | 32.82 |
| DIRECT, proxy CPU seconds / GB | 0.357 | 0.278 | 0.519 |
| DIRECT, post-load RSS MiB | 12.50 | 16.64 | 36.66 |
| SS AES-GCM, four-flow Gbps | 9.52 | 11.04 | 9.12 |
| SS AES-GCM, proxy CPU seconds / GB | 0.948 | 0.797 | 1.275 |
| SS AES-GCM, post-load RSS MiB | 14.41 | 18.16 | 37.41 |
| VMess, four-flow Gbps | 9.08 | 9.58 | 13.84 |
| VMess, proxy CPU seconds / GB | 1.219 | 1.090 | 0.998 |
| VMess, post-load RSS MiB | 18.05 | 27.87 | 37.59 |

**Latency, connection rate, DNS and UDP.** DNS and UDP are medians of three
rounds on the final binaries. Latency
times SOCKS CONNECT plus a one-byte echo, with the median of four batches
of 1,000 connections, including an initially noisy batch. Connection rate
and idle footprint each use one final run. Connection rate uses exactly
4,000 successful
CONNECT-plus-echo exchanges at concurrency 32; every error fails the leg.
The initially attempted duration-based tests exhausted macOS ephemeral ports
and are excluded. A 31-second drain separates connection-rate legs.
DNS uses 5,000 locally answered fake-IP A queries per round, including repeated
names; this is not an upstream-DNS benchmark or proof of a true 50% cache-miss
ratio. DNS preflight checks response ID, successful RCODE and a nonempty answer.
UDP uses 5,000 SOCKS5-UDP echoes per size and validates framing and payload;
all measured UDP runs completed without timeout or payload mismatch.

| Metric | Optimized rill | mihomo |
|---|---:|---:|
| CONNECT + echo p50, µs | 120.2 | 131.5 |
| CONNECT + echo p99, µs | 265.6 | 304.5 |
| CONNECT + echo p99 batch range, µs | 141.2–403.2 | 167.1–432.2 |
| Complete connections / second | 21702 | 19136 |
| Proxy CPU µs / complete connection | 68.8 | 213.7 |
| Local fake-IP DNS QPS | 56536.7 | 33912.3 |
| Local fake-IP DNS p99, µs | 29.6 | 37.1 |
| UDP 64-byte round trips / second | 32215 | 26863 |
| UDP 64-byte p99, µs | 45.4 | 51.5 |
| UDP 1400-byte round trips / second | 31684 | 26123 |
| UDP 1400-byte p99, µs | 45.5 | 53.6 |
| 1,000 live idle DIRECT connections, RSS MiB | 19.45 | 54.98 |
| Incremental KiB / idle connection | 5.04 | 16.21 |

The idle sample holds all 1,000 connections for two seconds and samples RSS
relative to the warmed pre-connection baseline. This is one hold and a short
footprint check,
not a long-running leak test; the existing relay-churn allocation test covers
connection cleanup separately.

**Causes and retained changes.**

1. macOS always uses the copy relay; Linux's socket-to-socket `splice` is
   unavailable here. The old path copied at 4 KiB until 128 KiB, then at
   32 KiB. On macOS it now promotes at 16 KiB and copies up to 128 KiB,
   reducing read/write calls and accounting overhead. For fully filled
   buffers, a 1 MiB direction takes roughly 12 read cycles instead of 60;
   actual reads depend on transport framing and available data. The shared
   scratch grows per worker; spill buffers still appear only under
   backpressure. The 256 KiB poll budget, direction fairness and half-close
   behavior remain covered by the existing relay tests. The tradeoff is
   visible in post-load RSS: this is not an improvement over baseline RAM.
2. SS reads encrypted lengths and bodies separately and writes individual
   AEAD records. The new macOS `record_io` uses worker-local read scratch,
   retaining a 32 KiB per-stream buffer only when a successful read leaves
   extra bytes. Small writes pass through; bulk records enable a 64 KiB
   queue. SS drives the queue before waiting for a response, including
   tunnel prefixes. A pending flush still allows reads, and its retry slice
   is frozen until drained, preserving TLS retry semantics. The change
   adds no new dependencies and avoids buffers on silent connections.
3. VMess has additional codec tasks and an in-memory duplex handoff. Its
   32 KiB handoff repeatedly backpressured two-record bursts. macOS now uses
   a demand-grown 128 KiB window and the same lazy read-ahead on the read
   half. A 256 KiB experiment raised loaded RSS to about mihomo's level
   without improving parallel throughput and was rejected.

The copy changes are in [relay.rs](../../crates/rill-tunnel/src/relay.rs),
the buffered I/O in [record_io.rs](../../crates/rill-proxy/src/record_io.rs),
and the VMess handoff in [conn.rs](../../crates/rill-proxy/src/vmess/conn.rs).
Other operating systems retain their previous relay sizes and VMess window.

An eagerly allocated SS `BufStream` was also rejected: with 1,000 idle SS
connections it used 72.5 MiB versus mihomo's 61.8 MiB (about 54.8 versus
24.3 KiB incremental per connection). The lazy candidate brought this back
to 27.2 MiB / 7.5 KiB per connection, versus 62.2 MiB / 24.6 KiB for mihomo.
These SS idle diagnostics preceded the final TLS-retry guard and VMess-only
changes; the final idle table above measures the final binaries on DIRECT.

**Limits and remaining work.**

The table is a measured improvement, not completion of the requested universal
lead. At that stage VMess's extra task/duplex handoff remained a likely
throughput bottleneck, and SS ChaCha20 still needed a cipher/record-path
profile. The follow-up below implements and measures those changes. Several
small-message paths were 2–5% behind on this host.

The first pass could not open a TUN interface without administrator
authentication. The privileged follow-up below now supplies the isolated
lwIP/gVisor comparison. macOS `stack: system` still falls back to lwIP: a
kernel-backend experiment was slower and was removed. Linux kernel-TCP / GSO /
splice measurements do not validate macOS TUN. Neither pass establishes WAN,
QUIC, large-rule-set or encrypted upstream DNS performance.

**Binary provenance.** Sizes are bytes after stripping. The original release
profile and feature set are used for both rill builds.

| Binary | Bytes | SHA-256 |
|---|---:|---|
| rill-before | 16,558,552 | `f3d4b2981b2631f2b7ccebe6e2ce65c5a3998aafad4a3dae8b0a04ef85269340` |
| rill-first-pass | 16,591,640 | `219ce1b5ea9e36043ff08b985325c1c9cb5a50dbf4c6ed29a5b7f573fef7814f` |
| mihomo | 56,810,034 | `f3e8ae41397c08cbf900ce1f7c8a168285d29954e9bca5d84d69a2b2561adfe9` |
| sing-box | 83,934,930 | `6546126c1759683fe85798da92409215d53c50e0f2b346b4f74a61babc8dbec2` |

**Initial-pass validation.**

- `fmt`: passed
- `clippy-default`: passed
- `clippy-minimal`: passed
- `clippy-all`: passed
- `clippy-common`: passed
- `unit`: passed
- `listener-all`: passed
- `ss-only`: passed
- `vmess-only`: passed
- `integration`: passed
- `docs`: passed
- `unit-serial`: passed
- `tunnel-standalone`: passed

The final parallel and serial workspace library runs each passed 2,530 tests
(four ignored). The selected integration targets passed 51 tests; the
all-feature listener run passed 144. Feature-isolated proxy runs passed the
five record-I/O cases with SS and 316 tests with VMess alone. The Clippy runs
cover all targets with default, no-default and all features; documentation
builds use `RUSTDOCFLAGS="-D warnings"`.

An earlier parallel run missed the expected captured warning in the unmodified
`rule_ir::tests::dead_target_in_indexed_prefix_warns_once` test. The standalone
tunnel suite, full serial run and final full parallel rerun passed. This
intermittent logging-test failure remains a validation caveat; its assertions
were not changed.

The existing poll-budget regression caught an overshoot at macOS buffer
promotion; the relay now yields before a pair of reads could exceed its
remaining byte budget. Existing packet roundtrip tests also check FIN/RST
flags, fixing a macOS-only dead-code lint without changing packet handling.

The new inline record-I/O tests cover zero idle-buffer allocation, read-ahead
surviving scratch reuse, exact writes under backpressure, shutdown draining,
large-I/O bypass, and stability of a pending flush's retry slice. Real sing-box
interop above additionally checks the SS cipher variants and VMess data path.

The standard workloads can be repeated with the existing
`throughput_interleaved` example, independent listeners and `--rounds 12`
(or a multiple of six). Build it with:

```sh
rill_perf_scratch=$(mktemp -d)
trap 'rm -rf "$rill_perf_scratch"' EXIT
CARGO_TARGET_DIR="$rill_perf_scratch/target" cargo build --release --locked \
  -p rill-app -p rill-bench --example throughput_interleaved --bins
"$rill_perf_scratch/target/release/examples/throughput_interleaved" \
  127.0.0.1:18390 127.0.0.1:18391 127.0.0.1:18392 --rounds 12
```

As requested, the temporary native driver, orchestration scripts, configs,
certificates, downloaded tools/peers, raw samples/logs and build target are
removed after recording this report. Only production changes, inline
regression cases and this compact report remain.


**Privileged follow-up and final code.**

This second pass rebuilds the first pass's source as its baseline; it does
not compare directly against clean `a98cc9d`. The machine, Rust release
profile, mihomo v1.19.33 and sing-box 1.14.4 are unchanged. A shared lock
serializes builds, tests and timed runs. Proxies keep their API and connection
statistics enabled; all traffic stays on local echo/peer servers. No downloaded
upstream source was incorporated into rill.

The retained changes are:

- The macOS relay keeps 128 KiB bulk scratch and its 256 KiB poll budget,
  but divides the remaining budget between active directions. Both reads
  and spill-buffer drains obey it. A stream of small messages no longer
  self-wakes early merely because its accumulated bytes made it bulk eligible.
- macOS VMess now reads/authenticates and writes/seals records in the caller's
  poll. It removes the two codec tasks, supervisor, split mutex and plaintext
  duplex queues. Partial response headers, lengths and ciphertext persist
  across cancelled reads. Non-macOS keeps the previous task-backed path.
- Plain TCP SS ChaCha20 retains the public shadowsocks codec's salt generation,
  replay checks, authentication and framing. After 2 MiB received, it may move
  its existing decoder and read-ahead to a separate reader task. There are
  at most four such workers, a one-element ready queue, reusable 128 KiB
  chunks and cancellation that aborts the worker. Short/idle streams run
  inline; layered/plugin transports keep the existing path.
- SS and Trojan combine already-ready bulk plaintext records before writing
  them onward. Replies smaller than 8 KiB return immediately. Pending reads
  return their valid prefix; a later decode error is delivered on the next
  read. Trojan's wrapper adds no payload buffer or extra boxing. TLS/Vision's
  raw-switch implementation is unchanged.

The encrypt-only microbenchmark found both ring and BoringSSL ChaCha20 near
2.16 GB/s for 16,383-byte records after warmup. It did not justify a backend
migration. A sampled single-flow workload used about 0.96 CPU cores with
inline rill versus 1.85 with mihomo. Moving bulk decryption to a separate
worker improved actual SS throughput; those observations support directional
concurrency as a bottleneck, rather than proving a general cipher-library gap.

**Follow-up TCP medians.** Every protocol has 12 recorded rounds and all six
three-proxy orderings, using the unchanged standard throughput example.
Baseline is the rebuilt first-pass source. The shared relay/SS/VMess candidate
supplies the first six protocol rows; Trojan has a separate 12-round run
against that candidate, the final coalescing change and mihomo. Its baseline
column therefore means the pre-coalescing candidate. The final SS coalescing
helper is a refactor of the candidate's same read loop. All successful samples
are retained, with no outlier trimming. Trojan uses a local self-signed RSA
2048 certificate and matching verification settings on both proxies.

| Path | Workload | Baseline Gbps | Final Gbps | mihomo Gbps | Final vs mihomo |
|---|---|---:|---:|---:|---:|
| DIRECT | 4 KiB x 10000 | 2.072 | 2.071 | 2.067 | +0.2% |
| DIRECT | 1 MiB x 10 | 45.210 | 45.703 | 40.635 | +12.5% |
| DIRECT | 64 MiB x 1 | 52.689 | 52.478 | 49.463 | +6.1% |
| VLESS | 4 KiB x 10000 | 1.350 | 1.351 | 1.400 | -3.5% |
| VLESS | 1 MiB x 10 | 26.553 | 26.723 | 25.089 | +6.5% |
| VLESS | 64 MiB x 1 | 37.638 | 36.477 | 39.962 | -8.7% |
| SS AES-GCM | 4 KiB x 10000 | 1.273 | 1.275 | 1.326 | -3.8% |
| SS AES-GCM | 1 MiB x 10 | 18.057 | 19.410 | 17.785 | +9.1% |
| SS AES-GCM | 64 MiB x 1 | 23.129 | 25.129 | 23.513 | +6.9% |
| SS2022 | 4 KiB x 10000 | 1.276 | 1.276 | 1.323 | -3.5% |
| SS2022 | 1 MiB x 10 | 20.575 | 21.116 | 20.017 | +5.5% |
| SS2022 | 64 MiB x 1 | 29.051 | 30.022 | 29.923 | +0.3% |
| SS ChaCha20 | 4 KiB x 10000 | 1.061 | 1.048 | 1.036 | +1.1% |
| SS ChaCha20 | 1 MiB x 10 | 9.842 | 10.578 | 8.582 | +23.2% |
| SS ChaCha20 | 64 MiB x 1 | 9.268 | 11.471 | 11.316 | +1.4% |
| Trojan/TLS | 4 KiB x 10000 | 1.225 | 1.224 | 1.298 | -5.8% |
| Trojan/TLS | 1 MiB x 10 | 9.286 | 9.612 | 8.491 | +13.2% |
| Trojan/TLS | 64 MiB x 1 | 24.471 | 26.784 | 24.696 | +8.5% |
| VMess | 4 KiB x 10000 | 1.258 | 1.294 | 1.315 | -1.6% |
| VMess | 1 MiB x 10 | 16.854 | 19.303 | 16.753 | +15.2% |
| VMess | 64 MiB x 1 | 20.193 | 25.899 | 23.001 | +12.6% |

The former VMess and ChaCha20 single-flow losses are closed in these runs.
Small-message SS/Trojan/VLESS/VMess rows are still below mihomo, and VLESS's
64 MiB row remains about 9% slower. Sub-5% differences on this shared desktop
remain parity candidates, not guarantees of a stable ordering.

**Long bulk and proxy CPU.** The follow-up native driver validates every byte,
uses the standard 8 KiB echo buffer and 256 KiB client I/O. Each sample moves
eight 512 MiB payloads, either serially or in two waves of four concurrent
connections: 8 GiB counted with the echo. There are four samples per variant
and mode, with variant order reversed every round. CPU is the proxy's own
`proc_pid_rusage` delta, converted from Mach ticks with 125/3 ns per tick.
This differs from the initial pass's 64 KiB-echo/256 MiB driver; compare
variants within each table, not absolute rates across the two drivers.
These samples precede the Trojan-only wrapper change.

| Path | Concurrent flows | rill Gbps | mihomo Gbps | rill CPU s/GB | mihomo CPU s/GB |
|---|---:|---:|---:|---:|---:|
| DIRECT | 1 | 42.948 | 42.380 | 0.197 | 0.187 |
| DIRECT | 4 | 25.310 | 22.720 | 0.410 | 0.819 |
| VMess | 1 | 23.332 | 21.731 | 0.427 | 0.526 |
| VMess | 4 | 9.553 | 10.789 | 0.758 | 1.317 |
| SS ChaCha20 | 1 | 10.238 | 9.923 | 0.982 | 1.556 |
| SS ChaCha20 | 4 | 17.187 | 14.806 | 1.272 | 1.984 |

VMess still loses the four-flow throughput comparison, despite lower proxy
CPU. A diagnostic override to one Tokio worker raised its four-flow rate to
23.3–23.9 Gbps, while four workers gave 9.0–9.6 and ten gave 10.5–11.1.
This points to runtime/network scheduling overhead; no specific global lock
has been proved responsible. A macOS runtime experiment with event/global
queue intervals of 7 produced some higher concurrent samples but lowered
VMess small-message throughput by about 5%, so it was reverted. No worker
count, scheduling priority or Tokio unstable option is forced in production.
Tokio documents its scheduler's
[LIFO/local-queue trade-offs](https://docs.rs/tokio/1.54.0/tokio/runtime/index.html);
that documentation alone is not a diagnosis of this workload.

**Privileged macOS TUN.** Native macOS administrator authorization runs an
independent device and only `198.19.253.0/24` through it. Each proxy uses
`auto-route: false`, `auto-detect-interface: false`, IPv4 `100.64.253.1/30`,
DNS fake-IP replies and the same MTU. The driver validates the DNS ID, rcode,
answer range, and route's utun interface before traffic. It reaches the echo
through the fake IP, so the workload crosses the packet path rather than a
SOCKS listener. Each row is the median of three recorded runs after warmup.
The TUN binary contains the final shared relay changes; the later Trojan-only
wrapper cannot affect this DIRECT workload. Existing FlowBar stays running.

| MTU | Workload | rill lwIP Gbps | mihomo gVisor Gbps | rill vs mihomo |
|---:|---|---:|---:|---:|
| 1500 | 4 KiB x 10000 | 0.474 | 0.402 | +17.8% |
| 1500 | 1 MiB x 10 | 1.428 | 1.159 | +23.2% |
| 1500 | 64 MiB x 1 | 1.223 | 1.088 | +12.4% |
| 9000 | 4 KiB x 10000 | 0.687 | 0.475 | +44.4% |
| 9000 | 1 MiB x 10 | 7.790 | 3.416 | +128.1% |
| 9000 | 64 MiB x 1 | 8.352 | 3.376 | +147.4% |

mihomo `system` did not complete its TCP handshake in this isolated manual-route
setup, including retries with the application allowed through the enabled
macOS firewall. It is not scored as zero throughput; a working system-stack
comparison remains unresolved. An experimental rill macOS kernel-TCP port
worked but only reached about 0.7 Gbps at MTU 1500 and 4.1 at MTU 9000,
versus lwIP's 1.2 and 8.4; that port and its dependency changes were removed.
The production macOS system/mixed fallback therefore remains unchanged.

All test routes/devices and firewall entries whose paths belonged to the
scratch directory were removed. No production route, resolver, FlowBar
process or global firewall setting was changed.

**Follow-up latency, connection rate, DNS and idle RSS.** Each workload
has three recorded rounds with variant order reversed on alternate rounds,
fresh proxy processes and enabled controllers/statistics. Idle samples require
all 1,000 sessions to be live and sample RSS during a three-second hold.
Latency includes a fresh SOCKS/TCP connection and a validated one-byte echo,
2,000 iterations per round. DNS uses the unchanged 5,000-query fake-IP
workload (2,500 nominal hits/2,500 misses), plus a parsed fake-IP preflight.
These DNS numbers do not measure upstream recursive resolution.

Connection rate is a bounded batch of 2,048 completed, validated exchanges,
16 concurrent clients, with any failure invalidating the batch. It is a short
connection-setup measurement, not a sustained-capacity claim. Cooldowns and
separate listener ports avoid the host's finite ephemeral-port range.

| Metric (median across rounds) | Final rill | mihomo |
|---|---:|---:|
| Connections/s, bounded batch | 19188 | 16377 |
| Fake-IP DNS queries/s | 54231 | 31712 |
| Cold connection + echo p50, µs | 122.54 | 137.08 |
| Cold connection + echo p95, µs | 200.29 | 233.83 |
| Cold connection + echo p99, µs | 395.25 | 298.33 |
| RSS, 1,000/1,000 idle sessions, MiB | 18.97 | 52.86 |
| Incremental RSS per idle session, KiB | 6.08 | 23.31 |

rill's median p99 is worse in this batch, despite lower p50/p95. Its
per-round p99 spans 283–409 µs versus mihomo's 268–377 µs. The third round
reverses the tail ordering. This is an unresolved tail-latency result, not a
claim of universal latency superiority.

An earlier uninterrupted connection-churn gauntlet exhausted macOS's
49,152–65,535 ephemeral-port range: native connect reported
`EADDRNOTAVAIL`, and idle establishment became incomplete. A feature-test
batch also overlapped the port-recovery window of an attempted CPS repeat.
Those failed/incomplete workloads are excluded rather than scored as speed
or footprint wins. The complete final batches above, and the successful TUN
repeat, run after recovery; no global TCP sysctl was changed. Full echo/data
validation failures were never counted as completed connections.

**Final validation and retained footprint.**

Default, no-default-feature and all-feature Clippy runs pass with
`--all-targets -- -D warnings`; the separate rill-common Clippy run, formatting
and workspace documentation with `RUSTDOCFLAGS="-D warnings"` also pass.
The default workspace library run passes **2,543 tests**, four ignored.
Explicit runs pass 144 all-feature listener tests, 374 SS-only proxy tests,
316 VMess-only tests, 308 Trojan-only tests, 206 selected integration tests
and 10 SS listener integration tests. Minimal logbook tests also pass.

The SS-only run initially caught an existing GOST header-limit fixture that
implicitly enabled mux while the feature was absent. The fixture now says
`mux=false`, so it tests only the intended header limit. Production GOST
code is unchanged; the full SS-only suite and the default-feature fixture
were rerun successfully. No failing assertion or protocol-authentication
check was removed.

Additional inline regressions cover fragmented/cancelled VMess headers and
records, upload backpressure with concurrent downloads, ready-record
coalescing, shutdown deadlines, SS read-ahead and decoder-state transfer,
both half-close directions, worker cancellation, and valid-prefix/error
ordering. Relay tests check small-read scheduling after bulk promotion,
the byte/cycle budget, data integrity under backpressure and idle scratch.
The listener connection-future size checks still pass. No benchmark data
buffers are allocated by relay setup, and idle relays retain no payload
buffers; cipher/protocol state is separate from this relay invariant.

| Follow-up binary | Stripped bytes | SHA-256 |
|---|---:|---|
| Rebuilt first-pass baseline | 16,591,648 | `c37f1f5427b9a731be033ea18f5158a87f114c3aaedf0d2b979bce49b8eaa863` |
| Shared relay/SS/VMess candidate | 16,575,136 | `649bbb10c513d4f1a81330696f31b709f733d7b5cb3a191122e2db125d7c0161` |
| Final production binary | 16,575,152 | `f5cbd725d2e16968901fe5c952e6b80dc43563d27495c365a0fa3af10b1167f9` |

The final binary is 16,496 bytes smaller than the rebuilt first-pass baseline
with the same default feature set and release profile. The earlier provenance table
retains mihomo/sing-box hashes, which match the follow-up downloads.

The task's temporary examples, native drivers, orchestration scripts, configs,
certificates, downloads, toolchain and build target are removed after results
are recorded. The final source changes, inline regression coverage and this
compact report remain. The running FlowBar kernel is not replaced by these
source changes.

**Pre-commit regression bar.** Before publishing these changes, all 23
commands in AGENTS.md's regression bar were run on the pinned Rust 1.98.1.
The full default library/binary/integration invocation passed 3,277 tests
(four ignored); the opt-in AnyTLS library run passed 764. TrustTunnel's
TCP and HTTP/3 endpoint tests, and the real sing-box, GOST, v2ray-plugin,
restls, jls and kcptun peer tests also passed. The additional release
allocation-count gate passed seven tests. Platform-specific/optional suites
retain their existing applicability and skip policies.

The initial default invocation stopped because the DNS routing integration
fixture expected GeoIP data on disk. Its successful rerun used a SHA-256
verified MetaCubeX GeoIP database under a temporary XDG_CONFIG_HOME. No
user configuration or test assertion was changed to resolve that dependency.
Those submission-only tools, peer binaries, data and build artifacts were
also removed after validation and publication.
