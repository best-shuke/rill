#!/usr/bin/env bash
# Assemble OpenWrt .ipk packages (opkg format) without the OpenWrt SDK.
#
# The release binaries are fully static musl builds, so a single Rust target
# serves several OpenWrt architecture labels; the ipk only differs in the
# `Architecture:` control field. Works with both GNU tar and bsdtar (macOS).
#
# Usage:
#   build-ipk.sh rill --binary <path> --version <ver> --arch <openwrt-arch> [--outdir <dir>]
#   build-ipk.sh luci --version <ver> [--outdir <dir>]
#
# Examples:
#   build-ipk.sh rill --binary target/aarch64-unknown-linux-musl/release-small/rill \
#       --version 0.16.0 --arch aarch64_generic --outdir dist
#   build-ipk.sh luci --version 0.16.0 --outdir dist

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
MAINTAINER="Max Lv <max.c.lv@gmail.com>"

usage() {
    sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//'
    exit 1
}

# tar flags forcing root ownership: GNU tar and bsdtar spell them differently.
# --format=ustar is mandatory: bsdtar's default (restricted pax) emits
# extended-header entries that opkg's untar skips silently, producing an
# "installed" package with no files on the device.
if tar --version 2>/dev/null | grep -q "GNU tar"; then
    TAR_OWNER=(--format=ustar --owner=0 --group=0 --numeric-owner)
else
    TAR_OWNER=(--format=ustar --uid 0 --gid 0 --numeric-owner)
fi

# pack_ipk <staging-dir> <output-file>
# <staging-dir> must contain control/ (control, conffiles, postinst, ...)
# and data/ (the target filesystem tree).
pack_ipk() {
    local staging="$1" out="$2"

    printf '2.0\n' > "${staging}/debian-binary"
    tar -C "${staging}/control" "${TAR_OWNER[@]}" -czf "${staging}/control.tar.gz" .
    tar -C "${staging}/data" "${TAR_OWNER[@]}" -czf "${staging}/data.tar.gz" .
    # opkg expects members in this exact order.
    tar -C "${staging}" "${TAR_OWNER[@]}" -czf "${out}" \
        ./debian-binary ./control.tar.gz ./data.tar.gz
    echo "built ${out}"
}

# installed_size <data-dir>
installed_size() {
    find "$1" -type f -exec wc -c {} + | awk 'END { print $1 }'
}

build_rill() {
    local binary="" version="" arch="" outdir="."
    while [ $# -gt 0 ]; do
        case "$1" in
            --binary)  binary="$2"; shift 2 ;;
            --version) version="$2"; shift 2 ;;
            --arch)    arch="$2"; shift 2 ;;
            --outdir)  outdir="$2"; shift 2 ;;
            *) echo "unknown option: $1" >&2; usage ;;
        esac
    done
    [ -n "$binary" ] && [ -n "$version" ] && [ -n "$arch" ] || usage
    [ -f "$binary" ] || { echo "binary not found: $binary" >&2; exit 1; }

    local staging
    staging="$(mktemp -d)"
    mkdir -p "$staging/control" \
             "$staging/data/usr/bin" \
             "$staging/data/etc/init.d" \
             "$staging/data/etc/config" \
             "$staging/data/etc/rill" \
             "$staging/data/etc/uci-defaults" \
             "$staging/data/usr/share/rill"

    install -m 755 "$binary" "$staging/data/usr/bin/rill"
    install -m 755 "$SCRIPT_DIR/rill/files/rill.init" "$staging/data/etc/init.d/rill"
    install -m 644 "$SCRIPT_DIR/rill/files/rill.config" "$staging/data/etc/config/rill"
    install -m 644 "$SCRIPT_DIR/rill/files/config.yaml" "$staging/data/etc/rill/config.yaml"
    install -m 755 "$SCRIPT_DIR/rill/files/gateway.sh" "$staging/data/usr/share/rill/gateway.sh"
    install -m 755 "$SCRIPT_DIR/rill/files/arp-hijack.sh" "$staging/data/usr/share/rill/arp-hijack.sh"
    install -m 755 "$SCRIPT_DIR/rill/files/rill-arp.init" "$staging/data/etc/init.d/rill-arp"
    install -m 755 "$SCRIPT_DIR/rill/files/rill.uci-defaults" "$staging/data/etc/uci-defaults/80_rill"

    cat > "$staging/control/control" <<EOF
Package: rill
Version: ${version}
Depends: libc
Section: net
Architecture: ${arch}
Installed-Size: $(installed_size "$staging/data")
Maintainer: ${MAINTAINER}
Description:  A high-performance, rule-based tunneling proxy kernel in Rust,
  compatible with mihomo (Clash Meta). Static binary; configuration lives in
  /etc/rill/config.yaml, service settings in /etc/config/rill.
EOF

    cat > "$staging/control/conffiles" <<EOF
/etc/config/rill
/etc/rill/config.yaml
EOF

    cat > "$staging/control/postinst" <<'EOF'
#!/bin/sh
[ -n "${IPKG_INSTROOT}" ] && exit 0
[ -f /etc/uci-defaults/80_rill ] && sh /etc/uci-defaults/80_rill && rm -f /etc/uci-defaults/80_rill
/etc/init.d/rill enable || true
# rill-arp self-gates on the (default-off) arp_hijack section, so enabling it
# is safe: it steers nothing until clients are selected in LuCI.
/etc/init.d/rill-arp enable || true
exit 0
EOF

    cat > "$staging/control/prerm" <<'EOF'
#!/bin/sh
[ -n "${IPKG_INSTROOT}" ] && exit 0
/etc/init.d/rill-arp stop 2>/dev/null
/etc/init.d/rill-arp disable 2>/dev/null
/etc/init.d/rill stop 2>/dev/null
/etc/init.d/rill disable || true
exit 0
EOF

    chmod 755 "$staging/control/postinst" "$staging/control/prerm"

    mkdir -p "$outdir"
    pack_ipk "$staging" "${outdir}/rill_${version}_${arch}.ipk"
    rm -rf "$staging"
}

build_luci() {
    local version="" outdir="."
    while [ $# -gt 0 ]; do
        case "$1" in
            --version) version="$2"; shift 2 ;;
            --outdir)  outdir="$2"; shift 2 ;;
            *) echo "unknown option: $1" >&2; usage ;;
        esac
    done
    [ -n "$version" ] || usage

    local staging app="$SCRIPT_DIR/luci-app-rill"
    staging="$(mktemp -d)"
    mkdir -p "$staging/control" "$staging/data/www/luci-static" "$staging/data"

    # htdocs/ maps to /www, root/ overlays / verbatim.
    cp -R "$app/root/." "$staging/data/"
    cp -R "$app/htdocs/luci-static/." "$staging/data/www/luci-static/"
    find "$staging/data" -type d -exec chmod 755 {} +
    find "$staging/data" -type f -exec chmod 644 {} +

    chmod 755 "$staging/data/usr/libexec/rill-api" "$staging/data/usr/libexec/rill-validate"

    cat > "$staging/control/control" <<EOF
Package: luci-app-rill
Version: ${version}
Depends: libc, luci-base, rill, curl
Section: luci
Architecture: all
Installed-Size: $(installed_size "$staging/data")
Maintainer: ${MAINTAINER}
Description:  LuCI support for rill: status overview, YAML config editor,
  service and transparent-proxy (gateway / side-router) settings, per-client
  proxy bypass, opt-in ARP-based client steering, logs, and the built-in rill
  web panel embedded in LuCI. Client steering uses the built-in unicast ARP
  sender.
EOF

    cat > "$staging/control/postinst" <<'EOF'
#!/bin/sh
[ -n "${IPKG_INSTROOT}" ] && exit 0
rm -f /tmp/luci-indexcache* 2>/dev/null
/etc/init.d/rpcd reload 2>/dev/null
exit 0
EOF

    cat > "$staging/control/postrm" <<'EOF'
#!/bin/sh
[ -n "${IPKG_INSTROOT}" ] && exit 0
rm -f /tmp/luci-indexcache* 2>/dev/null
exit 0
EOF

    chmod 755 "$staging/control/postinst" "$staging/control/postrm"

    mkdir -p "$outdir"
    pack_ipk "$staging" "${outdir}/luci-app-rill_${version}_all.ipk"
    rm -rf "$staging"
}

case "${1:-}" in
    rill) shift; build_rill "$@" ;;
    luci) shift; build_luci "$@" ;;
    *) usage ;;
esac
