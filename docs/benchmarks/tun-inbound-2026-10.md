# TUN inbound vs mihomo — baseline (2026-10)

First measurement of meow's TUN datapath. Every earlier comparison
(README, [methodology.md](methodology.md), [tcp-throughput-746.md](tcp-throughput-746.md))
drives the mixed listener over loopback SOCKS5, which never touches the
userspace TCP/IP stack a TUN inbound runs on. This run puts meow's lwIP
core next to mihomo's two TUN stacks on an identical datapath.

Raw artifacts: [tun-inbound-2026-10.json](tun-inbound-2026-10.json) (six
runs, three per MTU). Reproduce with `bash bench-tun.sh` (Linux, sudo).

## Setup

| Field | Value |
|-------|-------|
| Host | Oracle Cloud VM, ARM Neoverse-N1, 4 vCPU, 22 GiB RAM |
| OS / kernel | Oracle Linux 9.8, Linux 6.12.0-205.92.4.2.el9uek.aarch64 |
| meow | 0.26.1 @ `62525d4`, `cargo build --release` (default `full` features) |
| Toolchain | system `rustc 1.92.0` (Red Hat build) — **not** the `rust-toolchain.toml` pin (1.98.1); no rustup on this host |
| mihomo | v1.19.30 linux/arm64 (go1.26.6, `with_gvisor`) |
| Duration | `--duration 10`, `--latency-iterations 1000`, `--concurrency 64` |

The harness (`meow-bench --only tun`, `crates/meow-bench/src/bench_tun.rs`)
runs entirely inside a fresh network namespace (`unshare --net`) holding
only `lo` and the TUN device:

```text
client ── connect(198.18.x.y:port) ──▶ route 198.18.0.0/16 dev meowbench0
  ──▶ proxy TUN stack ── fake IP → echo.bench ──▶ MATCH,DIRECT
  ── echo.bench via the harness's upstream DNS (→ 127.0.0.1) ──▶ echo server
```

- Same config shape for every target: `dns.enhanced-mode: fake-ip`,
  `tun.auto-route: false` (the harness installs the one fake-ip route
  itself), `inet4-address: 172.19.0.1/30`, `rules: [MATCH,DIRECT]`, same
  MTU. mihomo additionally gets `stack:` and `auto-detect-interface: false`;
  its `gso` is left at its default.
- Workloads are the existing W1–W3 TCP legs (`bench_throughput`,
  `bench_latency`, `bench_conn_rate`), dialing the fake IP directly
  instead of through SOCKS5. The conn-rate leg spreads its 64 workers over
  16 fake IPs: closing client-first leaves TIME_WAIT on the client, and
  against a single non-loopback address (`tcp_tw_reuse=2` only covers
  loopback) the ephemeral range ran dry within seconds — a first run
  without the spread capped all three targets near 2 000 conn/s.
- CPU is the proxy process's user + system time from `/proc/<pid>/stat`
  (all threads), sampled around each leg. "Per GB relayed" counts both
  directions of the echo.
- Cells are the median of three runs; `±` is half the min–max spread
  relative to the median.

## Results — MTU 1500

| Metric | meow (lwip) | mihomo (system) | mihomo (gvisor) |
|---|---|---|---|
| RSS idle | **16.2 MB** (±4%) | 41.4 MB (±1%) | 43.5 MB (±1%) |
| RSS under load (peak) | **23.3 MB** (±6%) | 84.7 MB (±2%) | 105.8 MB (±4%) |
| TCP throughput, 64 MB × 1 | 1.78 Gbps (±6%) | **1.98 Gbps** (±2%) | 0.81 Gbps (±15%) |
| TCP throughput, 1 MB × 10 | **1.63 Gbps** (±8%) | 1.52 Gbps (±5%) | 0.78 Gbps (±5%) |
| TCP throughput, 4 KB × 10000 | 0.52 Gbps (±5%) | **0.73 Gbps** (±3%) | 0.28 Gbps (±1%) |
| Proxy CPU per GB relayed | 9.36 s (±5%) | **6.62 s** (±1%) | 20.45 s (±3%) |
| Latency p50 (connect + 1 B echo) | **316 µs** (±5%) | 369 µs (±4%) | 558 µs (±4%) |
| Latency p95 | **429 µs** (±28%) | 473 µs (±15%) | 782 µs (±5%) |
| Latency p99 | 576 µs (±53%) | **558 µs** (±27%) | 1101 µs (±6%) |
| Connections/sec | **13 147 /s** (±6%) | 4 292 /s (±3%) | 5 267 /s (±1%) |
| Proxy CPU per connection | **152 µs** (±6%) | 267 µs (±0%) | 498 µs (±0%) |

## Results — MTU 9000 (mihomo's default)

| Metric | meow (lwip) | mihomo (system) | mihomo (gvisor) |
|---|---|---|---|
| RSS idle | **14.8 MB** (±5%) | 41.3 MB (±1%) | 43.4 MB (±1%) |
| RSS under load (peak) | **22.3 MB** (±4%) | 84.6 MB (±0%) | 99.1 MB (±1%) |
| TCP throughput, 64 MB × 1 | 1.55 Gbps (±9%) | **5.67 Gbps** (±3%) | 1.89 Gbps (±7%) |
| TCP throughput, 1 MB × 10 | 1.50 Gbps (±12%) | **4.85 Gbps** (±8%) | 1.92 Gbps (±7%) |
| TCP throughput, 4 KB × 10000 | 0.53 Gbps (±3%) | **0.80 Gbps** (±4%) | 0.35 Gbps (±3%) |
| Proxy CPU per GB relayed | 10.37 s (±6%) | **3.21 s** (±1%) | 8.56 s (±1%) |
| Latency p50 (connect + 1 B echo) | **316 µs** (±1%) | 370 µs (±1%) | 550 µs (±3%) |
| Latency p95 | **387 µs** (±1%) | 473 µs (±2%) | 689 µs (±5%) |
| Latency p99 | **462 µs** (±4%) | 558 µs (±4%) | 797 µs (±6%) |
| Connections/sec | **11 770 /s** (±7%) | 4 351 /s (±4%) | 5 122 /s (±0%) |
| Proxy CPU per connection | **175 µs** (±7%) | 266 µs (±0%) | 492 µs (±2%) |

## Findings

**Where meow already leads.** Memory (2.6–4.5× less idle and peak RSS),
connection setup (3.1× mihomo-system's conn/s at 57% of its CPU per
connection) and p50/p95 latency (−14% / −9% vs system at MTU 1500,
−15% / −18% at 9000).
Against gVisor meow wins every TCP metric at MTU 1500.

**Where it loses: bulk throughput and CPU per byte.** At MTU 1500 meow is
within ±10% of mihomo-system on the 1 MB and 64 MB transfers but 29% behind
on the 4 KB round-trip loop, and spends 41% more CPU per GB. At MTU 9000
mihomo-system moves 3.7× more data per second at a third of meow's CPU per
GB; even gVisor overtakes meow there.

**meow does not scale with MTU at all** — its throughput cells are flat
or slightly lower between 1500 and 9000, while both mihomo stacks gain
2.3–3.2× on the 1 MB and 64 MB legs. The code explains it:

- The lwIP netif MTU is hard-coded to 1500 (`crates/meow-lwip/rust/core.rs:478`)
  and `TCP_MSS` is a compile-time 1460 (`crates/meow-lwip/old-src/custom/lwipopts.h:100` — the copy the build compiles),
  so `tun.mtu` only resizes the kernel device; segments stay 1460 B in both
  directions and the per-packet cost (one device read/write, one lwIP
  input/output pass) is paid ~6× more often than a 9000 B MTU needs.
- `TCP_WND` is `32 × TCP_MSS` (~46 KB) with no window scaling, so raising
  the MSS also needs `LWIP_WND_SCALE` / `TCP_RCV_SCALE` to keep the window
  from becoming the cap.
- All TCP/IP processing for every flow runs on one lwIP core task
  (`crates/meow-lwip/rust/core.rs`, module docs), and the write path hands
  lwIP 4 KB `Vec` chunks over a channel (`WRITE_CHUNK`), one allocation and
  copy per chunk.

## Caveats

- One 4-vCPU host runs the client, the proxy, and the echo server; the
  absolute Gbps figures are bounded by that, so read the ratios, not the
  numbers. Loopback DIRECT means this measures stack + relay overhead, not
  any real network.
- The host also runs Docker containers and a system mihomo instance
  (outside the benchmark namespace, idle) — background noise. meow's
  p95/p99 at MTU 1500 spread ±28% / ±53% across the three runs.
- mihomo-system's conn/s depends on window length: a 3 s smoke run
  reached 8 450 /s against the 4 292 /s 10 s median, so its rate decays
  over a sustained window (cause not investigated — its NAT table filling
  would fit). meow's 10 s median is the higher of its own readings.
- TCP only. UDP through the TUN (QUIC, games, DNS) is not measured yet.
- Built with rustc 1.92.0, not the pinned 1.98.1 (see Setup).

## Next steps

Step 1 below is done — see the follow-up section.

1. ~~Plumb `tun.mtu` into the lwIP netif and raise `TCP_MSS` with window
   scaling~~ (follow-up below).
2. Decide on the structural fix (a kernel-TCP "system" stack like
   mihomo's, or a multi-core userspace stack) against these numbers.
3. Add a UDP leg to the harness.

## Follow-up: lwIP MTU plumbing and queue fixes

Branch `perf/tun-lwip-mtu`. Raw artifacts:
[tun-inbound-2026-10-lwip-mtu.json](tun-inbound-2026-10-lwip-mtu.json)
(`before` = meow @ `62525d4`, `after` = this branch; three runs per MTU,
same host and harness, same session).

The harness gained two things first, and both changed the picture:

- A **parallel leg**: 32 concurrent 16 MB echo transfers (1 GiB relayed).
  No sequential leg ever has more than one bulk flow in flight.
- **`tun_tx_dropped`**: the device's `tx_dropped` from `/proc/net/dev` —
  packets the kernel routed into the TUN but dropped because the proxy's
  reader was behind.

With them, the unchanged meow already dropped 1 100–1 600 packets per run,
all in the parallel leg, and topped out at ~1.1 Gbps there at either MTU.

### What changed

| Change | Why (measured with single 3 s runs while iterating) |
|---|---|
| `NetStack::with_mtu`: the netif MTU follows `tun.mtu` instead of a hard-wired 1500; `TCP_MSS` 8960 with window scaling (`TCP_RCV_SCALE` 3); queue length, low-water mark and `PBUF_POOL_BUFSIZE` sized for 1460-byte segments; iOS keeps the old sizing | The baseline's flat MTU-9000 numbers |
| Ingress frames allocate from `PBUF_POOL`, not the heap | With `TCP_SND_BUF` 128 KiB the parallel leg stalled for the full 120 s timeout at MTU 1500. 32 × 128 KiB of unacked data exceeds the 2 MB heap, and a heap-allocated ingress frame — the ACKs that would free it included — then cannot allocate; moving ingress to the pool removed the stall (heap occupancy itself was not instrumented) |
| Streams parked on `ERR_MEM` queue on `mem_waiters` and are retried when another pcb's ACKs (or the 250 ms tick) free heap | A parked stream with nothing in flight gets no `tcp_sent_cb` of its own and waited for its `tcp_poll` tick, 4 s away. Not isolated in a separate A/B |
| Netstack frame channels 512 → 4096 | The egress hook drops a frame when its queue is full; a temporary counter saw ~750 dropped lwIP segments per parallel leg at 512, none at 4096 |
| Linux `txqueuelen` 500 → 4096 on the TUN device | With the deeper channels the device itself still overflowed (1 569 drops at MTU 1500, `TCP_WND` 128 KiB); none at 4096 |
| `TCP_WND` 128 KiB, `TCP_SND_BUF` 128 KiB | Window sweep below |

Window sweep (single runs, channels 4096, txqueuelen still 500):

| `TCP_WND` | MTU 1500: 64 MB / parallel / drops | MTU 9000: 64 MB / parallel / drops |
|---|---|---|
| 64 KiB | 1.69 / 1.36 Gbps / 567 | 4.10 / 3.67 Gbps / 0 |
| 128 KiB | 2.53 / 0.53 Gbps / 1 569 | 5.66 / 5.86 Gbps / 30 |
| 256 KiB | 2.27 / 0.50 Gbps / 2 260 | 5.94 / 2.59 Gbps / 240 |

Every connection's window can be in flight at once and the queues count
packets, so at MTU 1500 a larger window overran them; the txqueuelen
change removed that and let 128 KiB keep its single-flow gain.

### meow before → after (median of 3)

| Metric | MTU 1500 before | after | MTU 9000 before | after |
|---|---|---|---|---|
| RSS idle | 15.7 MB | 16.2 MB | 14.7 MB | 15.8 MB |
| RSS under load (peak) | 24.9 MB | 26.1 MB | 24.6 MB | 25.2 MB |
| TCP throughput, 64 MB × 1 | 1.55 Gbps | **2.37 Gbps** | 1.49 Gbps | **5.51 Gbps** |
| TCP throughput, 1 MB × 10 | 1.38 Gbps | **1.79 Gbps** | 1.42 Gbps | **4.60 Gbps** |
| TCP throughput, 4 KB × 10000 | 0.53 Gbps | 0.53 Gbps | 0.53 Gbps | 0.61 Gbps |
| Proxy CPU per GB relayed | 10.42 s | 8.73 s | 10.50 s | **5.23 s** |
| TCP throughput, 16 MB × 32 parallel | 1.17 Gbps | **1.80 Gbps** | 1.09 Gbps | **5.12 Gbps** |
| Proxy CPU per GB relayed (parallel) | 11.35 s | 9.31 s | 11.10 s | **3.56 s** |
| Latency p50 / p99 | 317 / 541 µs | 324 / 461 µs | 323 / 531 µs | 317 / 486 µs |
| Connections/sec | 12 340 /s | 13 566 /s | 12 050 /s | 12 143 /s |
| TUN `tx_dropped` per run | 1 136–1 613 | **0** | 1 316–1 539 | **0** |

The before medians sit somewhat below the baseline section's (e.g. 64 MB
at MTU 1500: 1.55 vs 1.78 Gbps) — run-to-run variance on this shared host;
compare within a table, not across sections.

### After vs mihomo (median of 3)

| Metric | MTU 1500: meow | mihomo system | mihomo gvisor | MTU 9000: meow | mihomo system | mihomo gvisor |
|---|---|---|---|---|---|---|
| RSS idle | **16.2 MB** | 41.6 MB | 43.2 MB | **15.8 MB** | 41.7 MB | 43.4 MB |
| RSS under load (peak) | **26.1 MB** | 84.8 MB | 780.1 MB | **25.2 MB** | 84.9 MB | 138.6 MB |
| TCP throughput, 64 MB × 1 | **2.37 Gbps** | 2.06 Gbps | 0.92 Gbps | 5.51 Gbps | **5.73 Gbps** | 1.99 Gbps |
| TCP throughput, 1 MB × 10 | **1.79 Gbps** | 1.50 Gbps | 0.81 Gbps | 4.60 Gbps | **4.77 Gbps** | 1.99 Gbps |
| TCP throughput, 4 KB × 10000 | 0.53 Gbps | **0.74 Gbps** | 0.28 Gbps | 0.61 Gbps | **0.82 Gbps** | 0.35 Gbps |
| Proxy CPU per GB relayed | 8.73 s | **6.66 s** | 19.99 s | 5.23 s | **3.21 s** | 8.56 s |
| TCP throughput, 16 MB × 32 parallel | **1.80 Gbps** | 0.75 Gbps | 1.76 Gbps | 5.12 Gbps | 1.99 Gbps | **5.24 Gbps** |
| Proxy CPU per GB relayed (parallel) | 9.31 s | **6.71 s** | 13.76 s | 3.56 s | **2.42 s** | 3.93 s |
| Latency p50 | **324 µs** | 360 µs | 550 µs | **317 µs** | 371 µs | 541 µs |
| Latency p99 | **461 µs** | 534 µs | 805 µs | **486 µs** | 799 µs | 1321 µs |
| Connections/sec | **13 566 /s** | 4 568 /s | 5 331 /s | **12 143 /s** | 4 551 /s | 5 284 /s |
| Proxy CPU per connection | **156 µs** | 263 µs | 500 µs | **177 µs** | 264 µs | 497 µs |
| TUN `tx_dropped` per run | **0** | 92 534–112 741 | 22 117–24 696 | **0** | 12 625–16 238 | 0 |

- meow now matches or beats mihomo-system on bulk TCP at MTU 1500
  (+15% / +19% on the 64 MB / 1 MB legs) and is within 4% of it at 9000.
- Under 32 concurrent flows mihomo-system loses tens of thousands of
  packets at its own TUN queue and falls to 0.75 / 1.99 Gbps — 2.4× / 2.6×
  behind meow. gVisor keeps up at 9000 (5.24 Gbps) but its peak RSS reached
  780 MB in the MTU-1500 parallel leg.
- **Still behind: CPU per byte and small messages.** mihomo-system spends
  24% less CPU per GB at MTU 1500 and 39% less at 9000 (single-flow legs),
  and wins the 4 KB round-trip loop by 26–28%. This is the per-packet and
  per-byte cost of the userspace path: a `Vec` per frame each way, a copy
  into and out of lwIP per segment, and two channel hops — work the
  kernel-TCP system stack never does.

### Next

1. Cut per-packet cost on the datapath (frame `Vec`s and copies, channel
   hops), then TUN offload (tun-rs exposes Linux GSO/GRO) — the CPU-per-GB
   gap above.
2. The structural decision (kernel-TCP system stack vs multi-core userspace
   stack), now against these numbers.
3. A UDP leg.
4. Consider defaulting `tun.mtu` to 9000 as mihomo and sing-box do, after
   checking utun and Wintun limits.
