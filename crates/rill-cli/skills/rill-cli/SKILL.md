---
name: rill-cli
description: Inspect and control a running rill (rill, the Rust mihomo / Clash Meta kernel) from the shell with rill-cli. Use when the user asks why traffic goes where it goes, which node a proxy group uses, to switch a group's node or the routing mode, to look at or close connections, to test node delays, to query or flush DNS, to update providers or subscriptions, to read the logbook or follow the log, or to reload the config.
license: MIT
compatibility: Needs the rill-cli binary and a running rill with external-controller set.
---

# rill-cli

`rill-cli` talks to a running rill over its REST API (the `external-controller`).
It never starts or stops rill; every command is one or a few HTTP requests.
`rill-cli --help` and `rill-cli <command> --help` list every option.

If `rill-cli` is not on PATH, use the one that ships with this skill, two
directories above its folder: `<dir>/rill-cli` (`rill-cli.exe` on Windows)
beside `<dir>/skills/rill-cli/`. The folder may be a link; go up from its
real path (`cd <folder> && pwd -P`), not from the link.

## Connecting

rill serves the API only when its config sets `external-controller`. Once the
API is up, rill writes its address and secret to a file that only the user
rill runs as can read. On that machine, as that user, rill-cli needs no
options, whoever started rill: a service, a terminal, or a desktop GUI that
passed the secret on rill's command line.

rill-cli finds the controller in this order:

1. `--controller host:port` or `RILL_CONTROLLER`
2. `external-controller` in the config given with `--config FILE` or `RILL_CONFIG`
3. the rill running as this user, from its file
4. `127.0.0.1:9090`

The API secret comes from `--secret-stdin`, else `RILL_SECRET`, else the file
of the rill at that address, else `secret` in the `--config` file.

```bash
rill-cli status                                 # the rill running as this user
rill-cli --config /etc/rill/config.yaml status
rill-cli --controller 192.168.1.1:9090 status   # a rill on another host
printf '%s\n' "$SECRET_FROM_A_VAULT" | rill-cli --secret-stdin status
```

Rules for the secret:

- Never print, echo, log or paste the secret, and never put it on a command
  line: there is no `--secret` flag on purpose.
- Do not open the config file or rill's controller file to show them to the
  user; they hold the secret, and the config holds node passwords. Let
  rill-cli read them.
- A `401` means the secret is missing or wrong. Ask the user how to supply it.

When several rills run as this user, rill-cli lists them and asks for
`--controller`; ask the user which one they mean. A rill running as root (a
system service, or one started with sudo for TUN) or as another user writes
its file for that user only: rill-cli then has to run as that user too, such
as `sudo rill-cli status`. Ask before using sudo.

If rill-cli cannot connect, rill is not running, or it runs without
`external-controller`, or on another address. Say so; do not start rill
yourself unless the user asks.

## Reading state

These commands change nothing; run them freely.

```bash
rill-cli status                      # version, mode, log level, TUN, ports, traffic totals
rill-cli mode                        # without an argument these three only read
rill-cli log-level
rill-cli tun
rill-cli group list                  # every group and the member it routes through
rill-cli group show "Proxy"       # one group's members with their last delay
rill-cli proxy list                  # every proxy, provider members too
rill-cli proxy list --filter HK
rill-cli proxy show "HK 01"          # type, UDP, delay history
rill-cli rule list --filter google   # rules in match order, with their index
rill-cli conn list                   # open connections: rule, destination, route
rill-cli conn list --filter youtube
rill-cli conn show 1a2b3c4d          # one connection with its notes; an id prefix works
rill-cli dns query example.com
rill-cli dns query example.com --type AAAA
rill-cli dns cache --search example --limit 20
rill-cli provider list               # proxy and rule providers, usage and expiry
rill-cli subscription list
rill-cli logbook                     # notable engine events, newest first
rill-cli logbook --level warning --limit 20
rill-cli logbook --kind config       # config.reload, config.change
rill-cli stats                       # bytes each proxy carried since rill started
rill-cli listeners
rill-cli log --level warning --count 50   # follow the log; --count makes it stop
rill-cli traffic --count 5                # one sample per second
```

Add `--json` to any command to get what the API answered, for parsing:

```bash
rill-cli --json group show "Proxy"
rill-cli conn list --json
rill-cli proxy list --json --filter JP
```

Text output puts names last, so names with CJK or emoji do not break the
columns. In `conn list` the route reads from the rule's target to the node that
dials: `Proxy > Auto > HK 01`. `delay` shows `-` before a first successful
test and `down` for a node that failed its last one.

### Answering "why does this go there?"

1. `rill-cli conn list --filter <host>` shows the rule that matched and the
   route each connection took.
2. `rill-cli conn show <id>` adds the connection's notes when the config sets
   `connection-notes: true`: DNS answers, the rule decision, each dial hop.
3. `rill-cli rule list --filter <word>` finds the rule; its index is its place
   in match order.
4. `rill-cli group show <group>` shows which member the group uses now.

### Answering "is something broken?"

`rill-cli logbook` lists notable events, newest first: reloads, provider and
subscription updates, listener starts, network interface changes and
dialer-proxy chain changes, each with how often it repeated. `--level warning`
keeps only the failures. The logbook survives restarts, unlike
`rill-cli log`.

```bash
rill-cli --timeout 5 status          # is rill up and answering at all?
rill-cli logbook --level warning     # what failed, newest first
rill-cli logbook --subject airport   # one provider, group or listener
rill-cli logbook --before 812        # older entries; a full page prints this line
```

### Checking a dialer-proxy chain

`chain-health` dials a proxy through each member of a group, the way
`dialer-proxy` chains it, whether or not its config sets one, and tests each
member alone too. It records nothing: no delay, no verdict, no switch. Each
member gets one verdict:

- `reached`: the chain works through it; CHAIN is the chain's delay.
- `failed`: the member works alone, and other members carry the proxy, but
  this one does not: it blocks the proxy's server. Keep it out of the
  proxy's dialer group.
- `inconclusive`: it works alone, but no member carried the proxy: the
  proxy's own server is the likelier fault.
- `down`: it fails alone too, so it says nothing about the chain.
- `skipped`: a group, or the proxy itself.

```bash
rill-cli chain-health home Auto      # can each member of Auto carry home?
rill-cli chain-health home "HK 01"   # one front proxy
rill-cli chain-health home Auto --url https://cp.cloudflare.com --probe-timeout 3000
rill-cli --json chain-health home Auto
```

A proxy that cannot run over another proxy's stream, like hysteria2, is
refused (422). The check is TCP only.

## Changing state

These change how rill routes or what it keeps. Tell the user what you are
about to change and get a yes first, unless they asked for exactly that
change.

```bash
rill-cli mode global                 # rule | global | direct
rill-cli group select "Proxy" "HK 01"
rill-cli group unfix Auto            # url-test / fallback back to automatic
rill-cli group test Auto             # delay-test every member
rill-cli group test Auto --url https://cp.cloudflare.com --probe-timeout 3000
rill-cli proxy test "HK 01"
rill-cli proxy test "HK 01" --url https://cp.cloudflare.com --probe-timeout 3000
rill-cli conn close 1a2b3c4d
rill-cli conn close --all
rill-cli dns flush
rill-cli dns flush-fakeip
rill-cli provider update airport
rill-cli provider update reject-list --kind rule
rill-cli provider check airport      # health-check a provider's nodes
rill-cli subscription update airport
rill-cli reload                      # the --config file, else the one rill loaded
rill-cli reload /etc/rill/config.yaml
rill-cli reload --force              # only when the user asks for it, see below
rill-cli log-level debug
rill-cli tun on
rill-cli logbook clear
```

What to know before changing things:

- `group select` on a `select` group switches it and rill remembers the pick
  across restarts. On a `url-test` group it pins that member: the group stops
  choosing on its own until `group unfix`, and a pinned member that goes down
  is routed around but stays pinned. On a `fallback` group the pin holds only
  while the member is up; rill drops it once it sees the member down.
- `group test` on a `url-test` or `fallback` group clears its pin first, as
  mihomo does. To measure without unpinning, test members one by one with
  `proxy test`.
- `select` groups have nothing to unfix; `load-balance` and `relay` groups
  cannot be selected.
- `mode`, `log-level` and `tun` change the running rill, not the config file.
  rill keeps them in its in-memory copy of the config, though, and whatever
  saves that copy writes them into the file: a subscription update (by hand
  or on its timer), or a GUI saving the config. Until then a restart returns
  to the file's values. `reload` returns `log-level` and `tun` to the file's
  values, and `mode` only when the file sets `mode:`.
- `reload` sends the file's text to rill and closes every open connection,
  like `conn close --all`. rill refuses a file that does not parse. Otherwise
  it skips broken proxies, groups and rules with a warning and applies the
  rest, unless the config sets `strict: true`; check
  `rill-cli logbook --kind config` afterwards. `--force` also applies a config
  whose strict checks, TUN, listeners or DNS fail; use it only when the user
  wants that.
- `conn close --all` drops every connection, the user's current calls and
  downloads included. `dns flush-fakeip` breaks open fake-IP flows.
- Provider and subscription updates fetch over the network and can take a
  minute. `provider check` runs the provider's `health-check:`; a provider
  without one (or with it disabled) is refused, so test its nodes with
  `proxy test`.
- `logbook clear` deletes the record for good.
- Subscription URLs carry access tokens: `subscription list` shows only their
  host. Never ask for or print the full URL.

## Errors

rill-cli exits 0 on success and 1 on any failure, with the reason on stderr:

- `cannot reach rill's controller at …`: rill is down, or the address is wrong.
- `rill wants the API secret (401)`: see Connecting.
- `rill answered 400 …` / `404 …`: rill refused the request; the message says
  why (unknown group or member, a member that is not in the group, a config
  that does not parse).
- `proxy test` exits 1 when the node fails the test; `group test` lists
  failed members as `failed` and still exits 0.

## Installing this skill

The desktop release archives (Windows, macOS, and Linux glibc and musl on x86_64
and aarch64) carry this skill as `skills/rill-cli/`: copy that folder into the
agent's skills directory. `rill-cli skill` prints this file, for a rill-cli
installed another way:

```bash
mkdir -p ~/.claude/skills/rill-cli
rill-cli skill > ~/.claude/skills/rill-cli/SKILL.md
```
