# Changelog

## Unreleased

- Disable Nagle on accepted mixed/SOCKS/HTTP, TProxy and Shadowsocks
  connections, as Go does: the tail of each response written back to the
  client no longer waits for its 40 ms delayed ACK. Sequential 1 MB relays
  went from 0.38 to 13 Gbps on loopback.
- Release builds use `opt-level = 3` again (ADR-0007 §3): about 15% less
  CPU per byte and per connection and lower latency, for a 19 MB instead of
  a 13 MB binary. Size-capped router builds use the new `release-small`
  profile (`opt-level = "z"`), which the OpenWrt packaging now builds.
- On Linux, a relay between plain kernel TCP sockets — an inbound
  connection dialed DIRECT — moves bulk data with `splice` past its first
  128 KiB, as Go's net package does (4-flow loopback echo 27.8 → 54.6 Gbps;
  mihomo 53.3). Idle connections hold no relay buffers and a far smaller
  task: 10 000 idle connections take 65 MB instead of 194 MB.
- `PUT /configs` keeps established connections, as mihomo does; only
  connections still dialing under the old configuration are cancelled.

## 0.1.2 — 2026-10-25

- Keep the `warning` log to what concerns the whole process: a failed
  connection, DNS reply or UDP flow, a rule target skipped for one
  connection, and each health-check probe now log at `info` or `debug`.
  A group logs one warning when none of its members is reachable any more
  and one `info` line when it recovers, instead of every member every
  round. Ignored nameserver parameters (`h3=true`) are noted at `info`.
- Console output carries no colour escape codes unless it is a terminal,
  so a front end's log file (FlowBar's `core.log`) stays plain text.

## 0.1.1 — 2026-10-25

- Interpret `#proxy`, `#DIRECT` and `#RULES` as DNS outbounds for DoH/DoT
  as well as plain DNS. Encrypted queries now support proxy transports
  with normal certificate verification; use `&sni=hostname` for an
  explicit TLS name override. Decode chunked DoH responses.
- Understand mihomo's nameserver parameters (`#h3=true`,
  `#skip-cert-verify=true`, `#ecs=…`, `#disable-ipv6=true`, …), which used
  to be taken as the TLS name: `skip-cert-verify`, `ecs` and `disable-*`
  take effect, the rest are ignored with a warning.
- A `#name` DNS outbound the config does not define no longer fails the
  config (`nameserver`, `fallback`) or quietly queries direct
  (`nameserver-policy`): as in mihomo it loads with a warning and its
  queries fail. `strict: true` rejects it.
- Honor `dns.respect-rules`, `direct-nameserver` and
  `direct-nameserver-follow-policy`, including resolver reloads and
  independent direct-DNS caching. As in mihomo, `respect-rules` requires
  `proxy-server-nameserver` and does not apply to `direct-nameserver`.
  Preserve encryption for IP-literal `default-nameserver` entries. See
  [DNS routing](docs/dns-routing.md).
- As in mihomo, a `nameserver-policy` match is final: its answer, failure
  included, is no longer fallback-filtered or retried on `nameserver` /
  `fallback`, and the policy outranks the fallback-filter domain gate. A
  down policy upstream (say, one routed through a proxy) no longer sends
  the query to the global nameservers.
- DNS logs name the outbound an upstream uses instead of `#PROXY`, and
  show an SNI override as `#sni=…`.
- Carry Vision UDP in Vision-protected VLESS CommandMux/Mux.Cool
  sessions, avoiding sing-box's missing-flow rejection. Recreate these
  sessions after outbound-interface changes.

## 0.1.0 — 2026-10-25

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
- **CI** is the Linux `lint`, `test` and `features` jobs, plus a release
  workflow (`v*` tags, or run by hand to only build) for static Linux
  x86_64/aarch64, macOS arm64 and Windows x64/arm64. Each archive carries
  `LICENSE`, `NOTICE` and `LICENSE-THIRD-PARTY.txt` (and Wintun's license
  on Windows).

### Added

- **mihomo geo parity**: top-level `geodata-mode` and `-m` read GEOIP from
  `GeoIP.dat` (from `geox-url.geoip`); Meta-geoip0 (`geoip.metadb`) and
  sing-geoip MMDBs load alongside MaxMind's; `GEOIP,LAN` and
  `SRC-GEOIP,LAN` are built in and need no database. The default GeoIP
  file and download are mihomo's `geoip.metadb`, geosite's `GeoSite.dat`,
  each found without regard to case.
- `dns.listen` serves TCP beside UDP, as mihomo does, so a stub resolver
  (macOS's, which FlowBar points at it) can retry a truncated answer.
- DNS `fallback-filter` as in mihomo: `geosite:` categories go to the
  fallback servers only (with mihomo's deprecation warning),
  `geoip-code: LAN` needs no database, and a geoip gate whose database
  cannot be loaded is a config error (`load GeoIP dns fallback filter
  error, …`) instead of being silently left out.
- `rill -t` downloads a referenced-but-missing database the way mihomo's
  config test does, with mihomo's log wording (`Can't find MMDB, start
  download`, …); `rill -t --offline` keeps the network-free check, which
  the OpenWrt init script and LuCI now use.

- `rill-bench --only tun` and `bench-tun.sh`: TUN-inbound benchmark against
  mihomo's `system` and `gvisor` stacks, run in a private network namespace.
