#!/usr/bin/env bash
# rill TUN global-routing e2e (Linux, root): the tun: block FlowBar writes,
# checked against what it means to mihomo — IP-literal capture, UDP and TCP
# DNS hijack, route-exclude-address, strict-route, following a default-route
# move (auto-detect-interface), and a clean teardown. Runs under the host's
# own rp_filter defaults (strict on RHEL-family hosts).
#
#   rt-host  rill + clients; uplinks up1 (10.10.1.2, default) / up2 (10.10.2.2)
#   rt-net   the "internet": echo :7000 and DNS on 10.10.9.9, an excluded
#            server 10.10.8.8, IPv6 server fd00:9::9
#
# usage: cargo build --bin rill && sudo bash tests/tun-global/tun-e2e.sh target/debug/rill
set -uo pipefail
RILL=$(readlink -f "$1")
HERE=$(cd "$(dirname "$0")" && pwd)
WORK=$(mktemp -d)
H="ip netns exec rt-host"
N="ip netns exec rt-net"
PASS=0
FAIL=0
check() { # name expected actual
    if [[ "$3" == $2 ]]; then echo "PASS  $1"; PASS=$((PASS + 1)); else echo "FAIL  $1: expected '$2', got '$3'"; FAIL=$((FAIL + 1)); fi
}
cleanup() {
    [[ -n "${RILL_PID:-}" ]] && kill "$RILL_PID" 2>/dev/null && wait "$RILL_PID" 2>/dev/null
    [[ -n "${SVC_PID:-}" ]] && kill "$SVC_PID" 2>/dev/null
    ip netns del rt-host 2>/dev/null
    ip netns del rt-net 2>/dev/null
    rm -rf "$WORK"
}
trap cleanup EXIT
ip netns del rt-host 2>/dev/null; ip netns del rt-net 2>/dev/null
ip netns add rt-host && ip netns add rt-net
for i in 1 2; do
    ip link add up$i netns rt-host type veth peer name dn$i netns rt-net
    $H ip addr add 10.10.$i.2/24 dev up$i
    $H ip -6 addr add fd00:$i::2/64 dev up$i nodad
    $H ip link set up$i up
    $N ip addr add 10.10.$i.1/24 dev dn$i
    $N ip -6 addr add fd00:$i::1/64 dev dn$i nodad
    $N ip link set dn$i up
done
$H ip link set lo up
$N ip link set lo up
$H sysctl -n net.ipv4.conf.up2.rp_filter > "$WORK/rp_up2"
$N ip link add dummy0 type dummy
$N ip addr add 10.10.9.9/32 dev dummy0
$N ip addr add 10.10.8.8/32 dev dummy0
$N ip -6 addr add fd00:9::9/128 dev dummy0
$N ip link set dummy0 up
$H ip route add default via 10.10.1.1 dev up1
$H ip -6 route add default via fd00:1::1 dev up1

$N python3 -I "$HERE/netsvc.py" serve > "$WORK/svc.log" 2>&1 &
SVC_PID=$!
sleep 1
check "baseline: IPv6 reachable before rill" "ok" "$($H python3 -I "$HERE/netsvc.py" echo fd00:9::9 7000)"

mkdir -p "$WORK/home"
cat > "$WORK/config.yaml" <<'EOF'
mixed-port: 17890
allow-lan: false
bind-address: 127.0.0.1
external-controller: 127.0.0.1:19090
secret: s
mode: rule
log-level: info
ipv6: false
dns:
  enable: true
  listen: 127.0.0.1:15353
  ipv6: false
  enhanced-mode: fake-ip
  nameserver: [10.10.9.9]
tun:
  route-exclude-address: [10.10.8.0/24]
  enable: true
  device: FlowBar
  auto-route: true
  auto-detect-interface: true
  stack: mixed
  dns-hijack: [any:53, tcp://any:53]
  strict-route: true
rules:
  - MATCH,DIRECT
EOF
$H "$RILL" -d "$WORK/home" -f "$WORK/config.yaml" > "$WORK/rill.log" 2>&1 &
RILL_PID=$!
API="curl -s -m 3 -H Authorization:Bearer\ s http://127.0.0.1:19090"
for _ in $(seq 1 50); do $H sh -c "$API/version" >/dev/null 2>&1 && break; sleep 0.2; done
sleep 1
check "rill up (/version)" "*version*" "$($H sh -c "$API/version")"
check "TUN device FlowBar exists" "*FlowBar*" "$($H ip -o link show FlowBar 2>&1)"

conns() { $H sh -c "$API/connections" | python3 -I -c 'import json,sys; print(" ".join(sorted({c["metadata"].get("destinationIP","")+"|"+c["metadata"].get("host","") for c in json.load(sys.stdin).get("connections") or []})))'; }

# C1: an IP literal is captured (mihomo auto-route: true).
$H python3 -I "$HERE/netsvc.py" echo 10.10.9.9 7000 2 > "$WORK/c1" &
sleep 1
check "C1 IP-literal flow goes through rill" "*10.10.9.9*" "$(conns)"
wait $!; check "C1 echo through the TUN" "ok" "$(cat "$WORK/c1")"

# C2: route-exclude-address bypasses the device.
$H python3 -I "$HERE/netsvc.py" echo 10.10.8.8 7000 2 > "$WORK/c2" &
sleep 1
check "C2 excluded prefix bypasses rill" "!(*10.10.8.8*)" "$(conns)"
wait $!; check "C2 excluded echo still works" "ok" "$(cat "$WORK/c2")"
check "C2 exclusion route via the physical gateway" "*10.10.8.0/24 via 10.10.1.1 dev up1*" "$($H ip route show 10.10.8.0/24)"

# C3/C4: DNS aimed at any server is hijacked, over UDP and TCP.
check "C3 UDP DNS hijacked to a fake IP" "198.18.*" "$($H dig +short +time=2 +tries=1 @10.10.9.9 echo.test A)"
check "C4 TCP DNS hijacked to a fake IP" "198.18.*" "$($H dig +tcp +short +time=2 +tries=1 @10.10.9.9 echo.test A)"

# C5: a domain flow through its fake IP reaches the real server.
FAKE=$($H dig +short +time=2 +tries=1 @10.10.9.9 echo.test A)
check "C5 domain flow via fake IP" "ok" "$($H python3 -I "$HERE/netsvc.py" echo "$FAKE" 7000)"

# C6: strict-route with IPv6 off — IPv6 cannot bypass the proxy.
check "C6 strict-route: IPv6 unreachable" "error*" "$($H python3 -I "$HERE/netsvc.py" echo fd00:9::9 7000)"
check "C6 unreachable ::/1 installed" "*unreachable ::/1*" "$($H ip -6 route show)"

# C7: the default route moves to up2 — rill follows (auto-detect-interface).
$H ip link set up1 down
$H ip route replace default via 10.10.2.1 dev up2
moved=no
for _ in $(seq 1 20); do grep -q "default route moved .*up2" "$WORK/rill.log" && moved=yes && break; sleep 0.5; done
check "C7 rill re-binds to up2" "yes" "$moved"
check "C7 IP-literal flow after the move" "ok" "$($H python3 -I "$HERE/netsvc.py" echo 10.10.9.9 7000)"
FAKE2=$($H dig +short +time=2 +tries=1 @10.10.9.9 echo2.test A)
check "C7 domain flow after the move (DNS upstream re-bound)" "ok" "$($H python3 -I "$HERE/netsvc.py" echo "$FAKE2" 7000)"
check "C7 exclusion re-routed via up2" "*10.10.8.0/24 via 10.10.2.1 dev up2*" "$($H ip route show 10.10.8.0/24)"

# C8: clean shutdown removes everything rill installed.
kill -TERM "$RILL_PID"; wait "$RILL_PID" 2>/dev/null; RILL_PID=
check "C8 device removed" "*does not exist*" "$($H ip -o link show FlowBar 2>&1)"
check "C8 strict-route routes removed" "!(*unreachable*)" "$($H ip -6 route show)"
check "C8 exclusion route removed" "" "$($H ip route show 10.10.8.0/24)"
check "C8 rp_filter left as found on up2" "$(cat "$WORK/rp_up2")" "$($H sysctl -n net.ipv4.conf.up2.rp_filter)"

echo "---- $PASS passed, $FAIL failed"
if [[ $FAIL -gt 0 ]]; then echo "---- rill.log (tail)"; tail -40 "$WORK/rill.log"; fi
exit $FAIL
