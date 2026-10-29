# XPro/1 outbound

Enable `--features xpro`; excluded from default/full. The 0.1.0 client source
snapshot lives under `vendor/xpro`, with SHA256SUMS. It uses the same BoringSSL
5.2.0 bindings and rill's injected TCP dialer/interface binding.

Required: `type: xpro`, `name`, `server`, `port`, `device-id` (32 hex digits),
`key-file` (exactly 32 raw bytes). Optional: `transport: h2|wss` (default h2),
`servername` (default server), `path` (default /api/stream), `ca-file` (outer
private CA; replaces public roots), `udp: false`, and heartbeat values
`ws-ping-interval: 30` / `ws-pong-timeout: 15` (seconds, 1..3600).

WSS requires `inner-tls: {servername: xpro-origin, ca-file: /secure/ca.pem}`;
H2 forbids inner-tls. TLS is mandatory and certificates are always checked.
Client IDNA converts domain names; original names take precedence over Fake-IP
metadata. No UDP, relay, dialer-proxy, inline key, or skip-cert-verify policy.

Bad/disabled XPro nodes remain bound to dead placeholders in static and
provider configurations. UDP routed to XPro fails explicitly, including a
selectable group that unwraps to XPro, without skipping to a later DIRECT rule.
Use TCP proxy DNS and independent bootstrap DNS; TUN/DNS leak acceptance needs
actual network captures. No live sessions or payload are replayed after reset.

Protocol/authentication: see [the frozen specification](../../vendor/xpro/docs/protocol-spec.md). No
claim about resistance to censorship is established by local interop tests.
