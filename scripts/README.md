# rill helper scripts

Transparent-proxy setup, gateway, and verification helpers. All are plain
`bash`, take `up` / `down` / `status` (except the `verify-*` pair), and need
root for the firewall (`nft` on Linux, `pfctl` on macOS).

| Script | Platform | Purpose |
|--------|----------|---------|
| `fetch-wintun.sh` | any (writes a Windows DLL) | Download the official signed `wintun.dll` for a Rust Windows target. Official release zips already include it. |
| `licenses.py` | any | Write `LICENSE-THIRD-PARTY.txt`: the notices of every crate (and vendored C library) the `rill` binary links for a target, from the locked sources. The release workflow ships it in every archive. |
| `tproxy-local-linux.sh` / `tproxy-local-macos.sh` | Linux / macOS | Proxy **this host's own** outbound traffic. Runs rill; rill auto-manages the firewall. |
| `tproxy-gateway-linux.sh` / `tproxy-gateway-macos.sh` | Linux / macOS | Make this host a **LAN gateway** that forwards & proxies **other devices'** traffic. Installs the firewall rill does *not* create. |
| `verify-tproxy-setup.sh` + `verify-tproxy-test.sh` | Linux / macOS | Bring up a loopback rig and assert local-outbound interception works. |

**Local vs gateway in one line:** *local* = the firewall hooks this host's own
`output` path (rill installs it for you); *gateway* = the firewall hooks
*forwarded* (`prerouting`) traffic from other devices, which rill does not
install — so the gateway scripts do.

Full background (how rill's tproxy works, fake-ip vs redir-host, the non-loopback
listener requirement) is in [`docs/tproxy-gateway.md`](../docs/tproxy-gateway.md);
the macOS local-mode guide (pf anchor, `route-to lo0` recipe, limitations) is
[`docs/tproxy-macos.md`](../docs/tproxy-macos.md).

---

## Proxy this host's own traffic — `tproxy-local-*`

rill's built-in firewall creates the redirect (`output`-chain nft REDIRECT in
a per-instance `rill_tproxy_<pid>_<seq>` table, or a per-instance
`com.apple/com.rill.tproxy.<pid>.<seq>` pf anchor) when a tproxy listener is
configured, and removes it on exit. These wrappers just run rill and confirm it came up.

```bash
# Quick demo (generated MATCH,DIRECT config — intercepts, but proxies nowhere):
sudo ./scripts/tproxy-local-linux.sh up --rill ./target/release/rill

sudo ./scripts/tproxy-local-linux.sh status     # rill running? firewall present?
sudo ./scripts/tproxy-local-linux.sh down        # stop rill; firewall auto-removed

# Real use — supply your own config (proxies + rules + a tproxy listener):
sudo ./scripts/tproxy-local-linux.sh up --rill /usr/local/bin/rill --config /etc/rill/config.yaml
```

macOS is identical with `tproxy-local-macos.sh`.

Notes:
- **Linux works today**; the host's own new outbound TCP is intercepted.
  Activating it can briefly reset existing connections (including a remote SSH
  session managing the host).
- **macOS** loads the pf anchor correctly but interception is currently
  loopback-only and the handshake does not complete — it does not yet proxy
  real outbound. See the macOS-tproxy follow-up issue.
- For real use, the only config requirement is a tproxy listener — just add
  `tproxy-port: 7893` (and `routing-mark: 9527` for loop avoidance) to your
  config; rill does the rest.

---

## LAN gateway — `tproxy-gateway-*`

For forwarding & proxying **other devices'** traffic. This installs the
`prerouting` redirect + DNS hijack that rill does not create; you run rill
separately, with a tproxy listener bound to a **non-loopback** address.

```bash
# 1. Install the gateway firewall (autodetects interface + LAN IP):
sudo ./scripts/tproxy-gateway-linux.sh up
#    options: -i eth0  -a 192.168.1.1  -p 7893  -d 1053  [--no-dns] [--no-ipv6]

sudo ./scripts/tproxy-gateway-linux.sh status
sudo ./scripts/tproxy-gateway-linux.sh down

# 2. Run rill with a NON-loopback tproxy listener (the top-level `tproxy-port`
#    binds 127.0.0.1 and won't catch forwarded traffic — declare it explicitly):
#       listeners:
#         - { name: tproxy-gw, type: tproxy, listen: '::', port: 7893 }
#       dns: { listen: 0.0.0.0:1053, ... }
rill -f /etc/rill/config.yaml

# 3. Point LAN clients' default route (and DNS) at this host.
```

macOS has an **experimental** `tproxy-gateway-macos.sh` (pf-based). The systemd
wiring for a persistent Linux gateway is in
[`docs/tproxy-gateway.md`](../docs/tproxy-gateway.md).

---

## Verify local interception — `verify-tproxy-*`

A self-contained rig (loopback alias + echo server + rill with `MATCH,REJECT`)
that proves the host's own traffic is intercepted. Run as a **non-root** user
(the test client must not be UID-bypassed on macOS); the scripts `sudo` where
needed.

```bash
./scripts/verify-tproxy-setup.sh up --rill ./target/release/rill   # bring up the rig
./scripts/verify-tproxy-test.sh                                     # assert (re-runnable)
./scripts/verify-tproxy-setup.sh down                              # tear down
```

`verify-tproxy-test.sh` checks: listener started, firewall rules loaded,
connection intercepted (the echo server is not reached), and rill recovered the
original destination. Exit 0 = all passed.
