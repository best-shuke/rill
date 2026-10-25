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

- `#my-proxy` uses the named node or group. Unknown names fail config load,
  including inside `nameserver-policy`.
- `#DIRECT` explicitly bypasses rule routing for the DNS connection.
- `#RULES` selects the outbound using the live tunnel mode and routing rules.
- With `respect-rules: true`, untagged main, fallback, policy and direct DNS
  upstreams use rule routing. An explicit suffix takes precedence. The
  routing destination is the DNS server's original URL host and bootstrap
  IP, not the queried domain or an SNI override.
- `direct-nameserver` provides a separate resolver/cache for direct outbound
  hostname lookups. `direct-nameserver-follow-policy: true` applies the same
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
continues to control routing and HTTP Host. Unrecognized fragment parameters
are rejected. The low-level `NameServerUrl` parser's legacy SNI syntax is
not the YAML configuration syntax.

Plain UDP upstreams routed through an outbound use TCP DNS framing. Native
UDP DNS through proxy adapters, DoQ and DoH3 are not implemented.

Regression coverage: `dns_routing_integration`, `proxy_routed_dns` and the
encrypted client tests cover live rules/mode/reload, direct DNS cache/policy,
verified TLS over proxy IO, chunked responses and certificate-name failures.
