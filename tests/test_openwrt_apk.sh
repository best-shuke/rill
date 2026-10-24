#!/usr/bin/env bash
# Packaging test for the OpenWrt .apk packages (apk-tools v3 / ADB format,
# OpenWrt 25.12+; issue #466). Builds both packages with openwrt/build-apk.sh
# and checks them two ways:
#
#   1. Static: `apk verify --allow-untrusted`, and `apk adbdump` assertions on
#      the metadata, owned files, conffiles and maintainer scripts.
#   2. Install: `apk add --allow-untrusted` into a real OpenWrt 25.12 rootfs
#      container, then file/conffile/script/enable-symlink/removal checks.
#
# Needs apk-tools 3 (set APK, or run openwrt/install-apk-tools.sh <dir> and
# point APK at <dir>/apk) and root (build-apk.sh requirement; the script
# re-execs itself under sudo). Step 2 additionally needs Docker; without it
# the install check is skipped, unless RILL_REQUIRE_DOCKER=1 (set in CI).
#
# Environment overrides:
#   APK               path to apk-tools 3 binary (default: apk)
#   OPENWRT_IMAGE     rootfs image (default openwrt/rootfs:<tag>-25.12.5)
#
# Usage: APK=/path/to/apk bash tests/test_openwrt_apk.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
APK="${APK:-apk}"
VERSION="0.0.0-r1"
PASS=0; FAIL=0

ok()   { echo "PASS: $1"; PASS=$((PASS + 1)); }
bad()  { echo "FAIL: $1"; FAIL=$((FAIL + 1)); }
check() { # check <desc> <command...>
    local desc="$1"; shift
    if "$@" >/dev/null 2>&1; then ok "$desc"; else bad "$desc"; fi
}

if [ "$(id -u)" -ne 0 ]; then
    exec sudo -E env "APK=$(command -v "$APK")" bash "$0" "$@"
fi

case "$(uname -m)" in
    aarch64 | arm64) OW_ARCH=aarch64_generic; OW_TAG=armsr-armv8 ;;
    *)               OW_ARCH=x86_64;          OW_TAG=x86-64 ;;
esac
IMAGE="${OPENWRT_IMAGE:-openwrt/rootfs:${OW_TAG}-25.12.5}"

WORK="$(mktemp -d)"
CNAME="rill-apk-test-$$"
cleanup() {
    docker rm -f "$CNAME" >/dev/null 2>&1 || true
    rm -rf "$WORK"
}
trap cleanup EXIT

# Placeholder payload: this test is about packaging, not the proxy binary.
printf '#!/bin/sh\necho rill-placeholder\n' > "$WORK/rill-bin"
chmod 755 "$WORK/rill-bin"

echo "=== Building apks ($OW_ARCH) ==="
bash "$ROOT_DIR/openwrt/build-apk.sh" rill --binary "$WORK/rill-bin" --version "$VERSION" --arch "$OW_ARCH" --outdir "$WORK"
bash "$ROOT_DIR/openwrt/build-apk.sh" luci --version "$VERSION" --outdir "$WORK"
RILL_APK="$WORK/rill_${VERSION}_${OW_ARCH}.apk"
LUCI_APK="$WORK/luci-app-rill_${VERSION}_all.apk"

echo "=== Static checks ==="
check "build-apk.sh rejects an opkg-style version" \
    bash -c "! bash '$ROOT_DIR/openwrt/build-apk.sh' luci --version 0.0.0-1 --outdir '$WORK/x'"
check "apk verify (rill)" "$APK" verify --allow-untrusted "$RILL_APK"
check "apk verify (luci-app-rill)" "$APK" verify --allow-untrusted "$LUCI_APK"
RILL_DUMP="$("$APK" adbdump "$RILL_APK")"
LUCI_DUMP="$("$APK" adbdump "$LUCI_APK")"
dump_has() { grep -qF -- "$2" <<<"$1"; }
for needle in "name: rill" "version: $VERSION" "arch: $OW_ARCH" "license: MIT" "- libc" \
              "name: rill.conffiles" "name: rill.conffiles_static" "name: rill.list" \
              "post-install:" "post-upgrade:" "pre-deinstall:" "name: 80_rill" "name: rill-arp"; do
    if dump_has "$RILL_DUMP" "$needle"; then ok "rill metadata has '$needle'"; else bad "rill metadata has '$needle'"; fi
done
for needle in "name: luci-app-rill" "arch: noarch" "- luci-base" "- rill" "- curl" \
              "name: luci-app-rill.list" "post-install:" "post-deinstall:"; do
    if dump_has "$LUCI_DUMP" "$needle"; then ok "luci metadata has '$needle'"; else bad "luci metadata has '$needle'"; fi
done
if dump_has "$RILL_DUMP" "user: root" && ! grep -E '(user|group): ' <<<"$RILL_DUMP" | grep -qvE ': root$'; then
    ok "rill payload is owned by root:root"
else
    bad "rill payload is owned by root:root"
fi

echo "=== Install check ($IMAGE) ==="
if ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1; then
    if [ "${RILL_REQUIRE_DOCKER:-0}" = 1 ]; then echo "FAIL: docker required"; exit 1; fi
    echo "SKIP: docker not available"
else
    docker image inspect "$IMAGE" >/dev/null 2>&1 || docker pull "$IMAGE" >/dev/null
    # Stand-in for the feed package luci-app-rill depends on (no network here).
    # luci-base already ships in the 25.12 rootfs image.
    mkdir -p "$WORK/empty"
    "$APK" mkpkg --info name:curl --info version:1-r1 --info arch:noarch \
        --info description:stub --files "$WORK/empty" --output "$WORK/curl-stub.apk"

    docker run -d --name "$CNAME" "$IMAGE" tail -f /dev/null >/dev/null
    docker cp "$RILL_APK" "$CNAME:/tmp/rill.apk"
    docker cp "$LUCI_APK" "$CNAME:/tmp/luci.apk"
    docker cp "$WORK/curl-stub.apk" "$CNAME:/tmp/curl.apk"
    dx() { docker exec "$CNAME" sh -c "$1"; }
    # apk in the container, minus the unreachable-feed warnings; keeps apk's
    # exit status (busybox sh has no pipefail).
    apkx() { dx "out=\$(apk $1 2>&1); rc=\$?; echo \"\$out\" | grep -v WARNING; exit \$rc"; }
    dx 'mkdir -p /var/lock'   # procd's lock dir; absent in the bare rootfs

    # --no-network: only the local files; deps resolve against what is installed.
    check "apk add rill + luci-app-rill" \
        apkx 'add --allow-untrusted --no-network /tmp/curl.apk /tmp/rill.apk /tmp/luci.apk'

    check "/usr/bin/rill installed, executable" dx 'test -x /usr/bin/rill'
    check "init scripts installed" dx 'test -x /etc/init.d/rill && test -x /etc/init.d/rill-arp'
    check "gateway helper scripts installed" dx 'test -x /usr/share/rill/gateway.sh && test -x /usr/share/rill/arp-hijack.sh'
    check "default config installed" dx 'test -f /etc/rill/config.yaml && test -f /etc/config/rill'
    check "luci files installed" dx 'test -x /usr/libexec/rill-api && test -f /www/luci-static/resources/view/rill/overview.js'
    # shellcheck disable=SC2016  # runs in the container's shell, not here
    check "post-install ran uci-defaults (consumed, uci sections created)" \
        dx '! test -e /etc/uci-defaults/80_rill && uci -q get rill.tproxy && uci -q get rill.arp && test -n "$(uci -q get rill.main.secret)"'
    check "services enabled by post-install" dx 'ls /etc/rc.d/S95rill /etc/rc.d/S96rill-arp'
    check "conffiles list recorded" dx 'grep -qx /etc/config/rill /lib/apk/packages/rill.conffiles && grep -qx /etc/rill/config.yaml /lib/apk/packages/rill.conffiles'
    check "apk lists owned files" dx 'apk info -L rill | grep -q usr/bin/rill'

    # Config protection: a user edit must survive a reinstall; the packaged
    # copy lands beside it as *.apk-new.
    dx 'echo "# user edit" >> /etc/rill/config.yaml'
    check "apk add --force-reinstall (post-upgrade path)" \
        apkx 'add --allow-untrusted --no-network --force-reinstall /tmp/rill.apk'
    check "edited conffile preserved across reinstall" dx 'tail -1 /etc/rill/config.yaml | grep -qx "# user edit"'
    check "packaged conffile staged as .apk-new" dx 'test -f /etc/rill/config.yaml.apk-new'
    check "service still enabled after reinstall" dx 'ls /etc/rc.d/S95rill'

    check "apk del luci-app-rill rill" apkx 'del luci-app-rill rill'
    check "pre-deinstall disabled the service" dx '! test -e /etc/rc.d/S95rill && ! test -e /etc/rc.d/S96rill-arp'
    check "binary and luci files removed" dx '! test -e /usr/bin/rill && ! test -e /usr/libexec/rill-api'
    check "conffiles kept on plain del" dx 'test -f /etc/config/rill'
fi

echo
echo "Results: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
