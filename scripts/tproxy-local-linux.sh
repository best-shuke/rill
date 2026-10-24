#!/usr/bin/env bash
# tproxy-local-linux.sh — run rill as a LOCAL transparent proxy for THIS host's
# own outbound traffic (Linux / nftables).
#
# Unlike a gateway, you do NOT install firewall rules yourself: rill's built-in
# firewall creates an `output`-chain nft REDIRECT (per-instance table
# `inet rill_tproxy_<pid>_<seq>`) when a tproxy listener is configured, and
# removes it on exit. This wrapper just runs rill with such a config and
# confirms the firewall came up. To forward OTHER devices' traffic, use
# tproxy-gateway-linux.sh instead.
#
# Usage:
#   sudo ./tproxy-local-linux.sh up [--config FILE] [--rill PATH]
#   sudo ./tproxy-local-linux.sh down
#   sudo ./tproxy-local-linux.sh status
#
# With no --config a minimal demo config (tproxy-port + MATCH,DIRECT) is used:
# it proves interception works but does not proxy anywhere. Supply your own
# config (with proxies + rules + a tproxy listener) for real use.
set -uo pipefail

STATE_DIR="/run/rill-tproxy-local"
[ -w /run ] 2>/dev/null || STATE_DIR="${TMPDIR:-/tmp}/rill-tproxy-local"
PIDF="$STATE_DIR/rill.pid"
LOG="$STATE_DIR/rill.log"
GENCFG="$STATE_DIR/rill.yaml"
# rill auto-creates one table per listener instance: rill_tproxy_<pid>_<seq>.
RILL="${RILL:-rill}"
CONFIG=""

die() { echo "error: $*" >&2; exit 2; }

cmd="${1:-}"; shift || true
while [ $# -gt 0 ]; do case "$1" in
  --config) CONFIG="$2"; shift 2;;
  --rill)   RILL="$2"; shift 2;;
  -h|--help) sed -n '2,21p' "$0"; exit 0;;
  *) die "unknown option: $1";;
esac; done

fw_tables() { nft list tables 2>/dev/null | awk '$2=="inet" && $3 ~ /^rill_tproxy/ {print $3}'; }
fw_present() { [ -n "$(fw_tables)" ]; }

case "$cmd" in
  down)
    [ -f "$PIDF" ] && kill "$(cat "$PIDF")" 2>/dev/null || true
    sleep 1
    if fw_present; then echo "warning: rill_tproxy* tables still present: $(fw_tables | tr '\n' ' ')"; else echo "stopped; firewall removed"; fi
    rm -rf "$STATE_DIR"; exit 0;;
  status)
    if [ -f "$PIDF" ] && kill -0 "$(cat "$PIDF")" 2>/dev/null; then echo "rill: running (pid $(cat "$PIDF"))"; else echo "rill: not running"; fi
    if fw_present; then
      echo "firewall: rill-managed tables: $(fw_tables | tr '\n' ' ')"
      for t in $(fw_tables); do nft list table inet "$t" 2>/dev/null | sed 's/^/  /'; done
    else echo "firewall: absent"; fi
    exit 0;;
  up) ;;
  ""|-h|--help) sed -n '2,21p' "$0"; exit 0;;
  *) die "unknown command '$cmd' (use: up | down | status)";;
esac

[ "$(id -u)" = 0 ] || die "must run as root (nftables)"
command -v nft >/dev/null || die "nft (nftables) not found"
command -v "$RILL" >/dev/null 2>&1 || die "rill binary not found ($RILL); pass --rill PATH"
mkdir -p "$STATE_DIR"

if [ -n "$CONFIG" ]; then
  CFG="$CONFIG"
  echo "using config: $CFG"
else
  CFG="$GENCFG"
  cat > "$CFG" <<EOF
# Demo local-tproxy config (no real proxy — MATCH,DIRECT). Replace the proxies
# and rules with your own; keep \`tproxy-port\` to enable transparent proxy.
tproxy-port: 7893
routing-mark: 9527
mode: rule
log-level: info
dns: { enable: true, listen: "127.0.0.1:1053", enhanced-mode: normal, nameserver: ["1.1.1.1"] }
proxies: []
proxy-groups: []
rules: [ "MATCH,DIRECT" ]
EOF
  echo "using generated demo config: $CFG (MATCH,DIRECT — no real proxy)"
fi

"$RILL" -f "$CFG" -t >/dev/null 2>&1 || die "config failed validation ($RILL -f $CFG -t)"
grep -qE "^tproxy-port:|type: *tproxy" "$CFG" || echo "warning: config has no tproxy listener; rill will not set up a redirect"

echo "note: the output-chain redirect captures this host's own new outbound TCP;"
echo "      existing connections (including a remote SSH session managing this)"
echo "      may reset as it activates."

nohup "$RILL" -f "$CFG" >"$LOG" 2>&1 &
echo $! > "$PIDF"

# Wait for the listener (first start may download geodata DBs).
for _ in $(seq 1 180); do
  grep -qE "TProxy listener.*started" "$LOG" 2>/dev/null && break
  kill -0 "$(cat "$PIDF")" 2>/dev/null || { echo "rill exited early:"; tail -5 "$LOG"; exit 1; }
  sleep 0.5
done

if fw_present; then
  echo "local transparent proxy active — this host's own outbound TCP is intercepted."
  echo "rill pid $(cat "$PIDF"); firewall: table(s) inet $(fw_tables | tr '\n' ' ')"
  echo "stop with: sudo $0 down"
else
  echo "warning: rill started but no rill_tproxy* table is present; check $LOG"
  exit 1
fi
