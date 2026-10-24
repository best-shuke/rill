#!/usr/bin/env bash
# TUN inbound benchmark (Linux): rill's TUN stack vs mihomo's
# `stack: system` / `stack: gvisor` on the same fake-ip → DIRECT datapath.
#
# Needs sudo for the TUN device and its route. The harness runs inside a
# fresh network namespace (`unshare --net`), so host routes — including a
# live TUN proxy's fake-ip range — are never touched, and the namespace
# disappears with everything in it when the run ends.
#
#   GO_BINARY=/path/to/mihomo bash bench-tun.sh [extra rill-bench args]
#
# Extra args go to rill-bench, e.g. `--tun-mtu 9000` or
# `--tun-mihomo-stacks system`.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

if [ "$(uname -s)" != "Linux" ]; then
    echo "bench-tun.sh is Linux-only" >&2
    exit 1
fi

GO_BINARY="${GO_BINARY:-$(command -v mihomo || true)}"
DURATION="${DURATION:-10}"

echo "=== Building rill (release) ==="
cargo build --release -p rill-app -p rill-bench

GO_ARGS=()
MIHOMO_VERSION="${MIHOMO_VERSION:-}"
if [ -n "$GO_BINARY" ]; then
    GO_ARGS+=(--go-binary "$GO_BINARY")
    if [ -z "$MIHOMO_VERSION" ]; then
        # "Mihomo Meta v1.19.30 linux arm64 ..." → v1.19.30
        MIHOMO_VERSION=$("$GO_BINARY" -v 2>/dev/null | head -1 | awk '{print $3}')
    fi
    echo "mihomo: $GO_BINARY ${MIHOMO_VERSION}"
else
    echo "mihomo not found — rill leg only (set GO_BINARY to compare)"
fi

mkdir -p target/bench
OUTPUT=target/bench/tun-results.json

echo ""
echo "=== Running TUN benchmark (sudo, private network namespace) ==="
sudo MIHOMO_VERSION="$MIHOMO_VERSION" unshare --net -- \
    ./target/release/rill-bench \
    --only tun \
    --rust-binary ./target/release/rill \
    "${GO_ARGS[@]}" \
    --duration "$DURATION" \
    --output "$OUTPUT" \
    --markdown \
    "$@"
sudo chown "$(id -u):$(id -g)" "$OUTPUT"
