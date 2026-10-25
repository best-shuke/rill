# DNS outbound selection

The `#` suffix selects an outbound for UDP, TCP, DoT and DoH upstreams.
It never replaces the TLS certificate name. Quote URLs containing suffixes
in YAML flow lists.

```yaml
dns:
  enable: true
  respect-rules: true
  default-nameserver:
    - 'https://223.5.5.5/dns-query#DIRECT'
  proxy-server-nameserver:
    - 'https://223.5.5.5/dns-query#DIRECT'
  nameserver:
    - 'https://1.1.1.1/dns-query#my-proxy'
  direct-nameserver:
    - 'https://223.5.5.5/dns-query#DIRECT'
  direct-nameserver-follow-policy: false
```

- `#my-proxy` uses the named node or group. A name the config does not
  define loads with a warning and every query through that upstream fails
  (never a direct query), as in mihomo; `strict: true` rejects it instead.
- `#DIRECT` explicitly bypasses rule routing for the DNS connection.
- `#RULES` selects the outbound using the live tunnel mode and routing rules.
- With `respect-rules: true`, untagged `nameserver`, `fallback` and
  `nameserver-policy` upstreams use rule routing, as in mihomo. An explicit
  suffix takes precedence. The routing destination is the DNS server's
  original URL host and bootstrap IP, not the queried domain or an SNI
  override. Like mihomo, `respect-rules` requires a non-empty
  `proxy-server-nameserver`: node hostnames must not resolve through
  nameservers the rules may route through those nodes.
- `direct-nameserver` provides a separate resolver/cache for direct outbound
  hostname lookups and, as in mihomo, does not inherit `respect-rules`.
  `direct-nameserver-follow-policy: true` applies the same
  `nameserver-policy` there; the default is false. An absent/empty direct
  list uses the main resolver. The direct result takes precedence even if
  rule matching already looked up the host through the main resolver;
  DNS housekeeping connections retain their bootstrap IP to avoid cycles.
- `proxy-server-nameserver` resolves node hostnames and does not inherit
  `respect-rules`. Keep it independently reachable to avoid resolver cycles.
- `default-nameserver` bootstraps DNS server hostnames. It requires IP
  literals and allows UDP, TCP, DoT and DoH; encryption is retained.
  Only an absent suffix or `#DIRECT` is permitted here.

DoT/DoH verifies the URL host by default. For a deliberate certificate-name
override use `tls://1.1.1.1#DIRECT&sni=cloudflare-dns.com`; the URL host
continues to control routing and HTTP Host, also for hostnames looked up
through the bootstrap servers. The low-level `NameServerUrl` parser's
legacy SNI syntax is not the YAML configuration syntax.

The suffix also carries mihomo's `&key=value` parameters:

| Parameter | Effect |
|-----------|--------|
| `skip-cert-verify=true` | DoT/DoH accepts any certificate (logged once per upstream) |
| `ecs=1.2.3.0/24` | EDNS Client Subnet on every query; a bare address is a full-length prefix |
| `ecs-override=true` | Accepted; queries never carry a client's own subnet, so `ecs` always applies |
| `disable-ipv4=true`, `disable-ipv6=true`, `disable-qtype-<n>=true` | That query type is answered locally with an empty NOERROR |
| `h3=true` | Accepted with a warning: DoH uses HTTP/1.1 |

Other parameters are ignored with a warning, as mihomo ignores them, so a
subscription carrying one still loads. When several bare names appear,
the last one is the outbound.

Plain UDP upstreams routed through an outbound use TCP DNS framing. Native
UDP DNS through proxy adapters, DoQ and DoH3 are not implemented.

Regression coverage: `dns_routing_integration`, `proxy_routed_dns` and the
encrypted client tests cover live rules/mode/reload, direct DNS cache/policy,
verified TLS over proxy IO, chunked responses and certificate-name failures.
