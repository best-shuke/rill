# Changelog

## 0.1.0 — unreleased

First version of rill, started from meow-rs 0.26.1 (`62525d4`; see NOTICE).
meow-rs's own history is kept in `docs/history/meow-rs-CHANGELOG.md`.

### Changed

- **Renamed** from meow-rs: crates `rill-*`, binaries `rill`, `rill-cli` and
  `rill-bench`, config directory `rill`, environment variables `RILL_*`.
- **TUN throughput**: the lwIP netif MTU follows `tun.mtu` (it was
  hard-wired to 1500) and TCP_MSS goes up to 8960 with window scaling. With
  32 concurrent flows the stack no longer drops its own traffic or stalls:
  ingress comes from PBUF_POOL instead of the shared heap, streams parked
  on `ERR_MEM` are woken when other connections free memory, the netstack
  queues are 4096 frames deep and the Linux TUN txqueuelen is 4096. MTU 9000
  single flow 1.49 → 5.51 Gbps, 32-flow parallel 1.09 → 5.12 Gbps
  (docs/benchmarks/tun-inbound-2026-10.md).
- **CI** is only the Linux `lint`, `test` and `features` jobs.

### Added

- `rill-bench --only tun` and `bench-tun.sh`: TUN-inbound benchmark against
  mihomo's `system` and `gvisor` stacks, run in a private network namespace.
