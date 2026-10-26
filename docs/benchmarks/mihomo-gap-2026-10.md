# Closing the mihomo gap (2026-10)

Before/after of the branch `perf/close-mihomo-gap` against rill 0.1.2
(`599c562`, `main`) and Go mihomo v1.19.30, all measured in one session on
one host. Every row that rill lost to mihomo at `599c562` was profiled,
attributed and fixed; what is still behind is listed at the end.

## Setup

| Field | Value |
|-------|-------|
| Host | Oracle Cloud VM, ARM Neoverse-N1, 4 vCPU, 22 GiB RAM, Linux 6.12 (el9uek) |
| Toolchain | rustc 1.98.1 (the `rust-toolchain.toml` pin) |
| Baseline | `599c562`, `cargo build --release` (then `opt-level = "z"`) |
| Optimized | this branch, `cargo build --release` (`opt-level = 3`) |
| mihomo | v1.19.30 linux/arm64 (go1.26.6, `with_gvisor`) |
| Harness | `rill-bench` (W1–W4, `--proxy-config config-bench-vless.yaml` with sing-box 1.14.0, `--only idle/steady/reload/tun`); bulk rows from a 4-flow SOCKS5 echo driver with 1 MiB syscalls |

SOCKS5 rows are the median of 3 runs, TUN rows of 2 (MTU 1500, fake-ip →
DIRECT). Client, proxy and echo server share the 4 cores, so absolute
numbers are loopback-bound; compare columns. The host also runs an idle
production mihomo (TUN, outside the benchmark namespaces) and Docker.

## SOCKS5 → DIRECT

| Metric | rill 599c562 | rill optimized | mihomo |
|---|---|---|---|
| RSS idle | 12.3 MB | 13.6 MB | 39.4 MB |
| RSS under load | 18.9 MB | **15.1 MB** | 50.4 MB |
| 4 KB × 10000 | 0.83 Gbps | 0.90 Gbps | 0.93 Gbps |
| 1 MB × 10 (sequential) | 0.38 Gbps | **13.31 Gbps** | 9.59 Gbps |
| 64 MB × 1 | 8.68 Gbps | **13.04 Gbps** | 11.99 Gbps |
| 4 flows × 512 MiB echo | 27.8 Gbps | **54.6 Gbps** | 53.3 Gbps |
| Latency p50 / p99 | 303 / 472 µs | **262 / 419 µs** | 443 / 637 µs |
| Connections/sec | 10 750 | **10 878** | 8 713 |
| Proxy CPU per GB (throughput leg) | 1.645 s | **1.265 s** | 1.434 s |
| Proxy CPU per connection | 169 µs | **145 µs** | 229 µs |
| DNS QPS (fake-ip) / p99 | 22 254 / 71 µs | **24 789 / 63 µs** | 14 866 / 103 µs |
| 10 000 idle connections, peak RSS | 194.5 MB (18.6 KB/conn) | **65.1 MB (5.2 KB/conn)** | 212.2 MB (17.6 KB/conn) |
| Steady conn churn RSS | 18.2 MB | **14.9 MB** | 47.8 MB |
| 10 × `PUT /configs` under load: mean reload | 3.3 ms | **2.4 ms** | 10.3 ms |
| … load connections failed | 640 | **0** | 92 |

## SOCKS5 → VLESS (plain) → sing-box

| Metric | rill 599c562 | rill optimized | mihomo |
|---|---|---|---|
| RSS under load | 20.6 MB | **16.5 MB** | 56.6 MB |
| 1 MB × 10 | 0.47 Gbps | 6.60 Gbps | **7.38 Gbps** |
| 64 MB × 1 | 7.82 Gbps | 10.88 Gbps | **11.22 Gbps** |
| Latency p50 / p99 | 708 / 953 µs | **662 / 848 µs** | 789 / 983 µs |
| Connections/sec | 5 436 | **5 619** | 4 982 |

## TUN inbound

| Metric | rill 599c562 (lwip) | rill lwip | rill `stack: system` | mihomo system | mihomo gvisor |
|---|---|---|---|---|---|
| RSS idle / peak | 15.3 / 25.9 MB | 17.9 / 33.1 MB | 18.0 / 41.0 MB | 41.4 / 86.8 MB | 43.1 / 730.2 MB |
| 4 KB × 10000 | 0.54 Gbps | 0.65 Gbps | **0.76 Gbps** | 0.73 Gbps | 0.29 Gbps |
| 1 MB × 10 | 1.70 Gbps | 2.65 Gbps | **8.29 Gbps** | 1.52 Gbps | 0.79 Gbps |
| 64 MB × 1 | 2.27 Gbps | 3.56 Gbps | **14.14 Gbps** | 1.97 Gbps | 0.92 Gbps |
| CPU per GB relayed | 8.84 s | 6.16 s | **3.02 s** | 6.75 s | 19.89 s |
| 16 MB × 32 parallel | 1.72 Gbps | 2.51 Gbps | **7.50 Gbps** | 0.86 Gbps | 1.25 Gbps |
| CPU per GB (parallel) | 9.65 s | 6.50 s | **1.45 s** | 6.98 s | 13.86 s |
| Latency p50 / p99 | 308 / 443 µs | 254 / 377 µs | **242 / 362 µs** | 361 / 515 µs | 538 / 752 µs |
| Connections/sec | 12 994 | **13 107** | 9 226 | 9 730 | 5 407 |
| CPU per connection | 168 µs | **152 µs** | 205 µs | 262 µs | 501 µs |
| TUN `tx_dropped` | 0 | 0 | 0 | 103 048 | 24 208 |

## What each fix was worth

| Loss at 599c562 | Cause (measured) | Fix |
|---|---|---|
| Sequential 1 MB relays at 0.38 Gbps (25× behind) | Inbound sockets kept Nagle: each response tail waited for the client's 40 ms delayed ACK | `TCP_NODELAY` on mixed / tproxy / shadowsocks accepts |
| Bulk at 52% of mihomo | 26% of CPU in `copy_{to,from}_user`; mihomo splices | Lazy Linux `splice` for kernel-TCP pairs past 128 KiB, ≤32 pipes enlarged to 1 MiB (64 KiB pipes still left 8% on the table) |
| +9% CPU per GB, slower latency | `opt-level = "z"`: outlined code, uninlined hot paths | `release` back to `opt-level = 3` (ADR-0007 amendment); routers use `release-small` |
| 18.6 KB per idle connection | One 23.4 KB task future per connection; two 4 KiB relay buffers held for life | Boxed transient sub-futures (3.96 KB mixed / 2.16 KB tproxy, size-guarded); per-worker scratch, spill buffer only under backpressure |
| Reload killed every live flow | Cold reload by design | Established flows survive; only setups still dialing are cancelled (#510 guarantee kept) |
| TUN CPU per GB +31% vs mihomo-system | lwIP first-fit `mem_malloc` (27% of the single core task), a `Vec` per packet/chunk, one syscall per packet | Bounded libc-backed lwIP heap, recycled frame/chunk/ingress buffers, virtio-net GSO/GRO batching |
| TUN capped at one core | All TCP in one lwIP task | `stack: system` / `mixed`: kernel TCP via packet NAT, whole GSO super-packets NATed in place; a passive close frees its NAT port after 5 s (60 s held every port and stalled a 10 s conn-rate run at ~63 k flows) |
| +11 MB TUN peak RSS after the above | Pumps and lwIP core allocate on whichever tokio worker runs them; glibc grew an arena per thread | `M_ARENA_MAX = 1` at startup on glibc (no measurable throughput / latency / CPU cost; `MALLOC_ARENA_MAX` overrides) |

## Still behind mihomo

- **Plain VLESS outbound bulk** (1 MB × 10 −11%, 64 MB −3%): the VLESS
  connection wraps its socket, so it relays through the copy path. Exposing
  the raw socket once both VLESS headers have crossed would let it splice;
  real deployments run VLESS over TLS/REALITY, where neither side splices.
- **4 KB ping-pong** (−3%, within run-to-run spread): syscall-bound on both.
- **`stack: system` conn/s** (9.2 k vs 9.7 k; mihomo-system drops ~100 k
  packets doing it): one ingress task NATs every packet; a multi-queue TUN
  (`IFF_MULTI_QUEUE`, a pump per queue) would spread it across cores.
- **Footprint vs the baseline itself**: idle RSS +1.3 MB and a 19.4 MB
  binary (+52%) from `opt-level = 3`; TUN peak RSS +7 MB (lwip). Still a
  third of mihomo's idle and half its system-stack peak.
