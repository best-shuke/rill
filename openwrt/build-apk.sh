#!/usr/bin/env bash
# Assemble OpenWrt .apk packages (apk-tools v3 / ADB format, OpenWrt 25.12+)
# without the OpenWrt SDK. Counterpart of build-ipk.sh with the same CLI and
# the same payload / maintainer-script semantics.
#
# The release binaries are fully static musl builds, so a single Rust target
# serves several OpenWrt architecture labels; the apk only differs in the
# `arch` metadata field.
#
# Requires apk-tools >= 3.0 (`apk mkpkg`) on PATH, or pointed to by $APK.
# Must run as root (e.g. `sudo -E`) so the payload is owned by root:root.
# Packages are unsigned: install them with
# `apk add --allow-untrusted ./<file>.apk`.
#
# Usage:
#   build-apk.sh rill --binary <path> --version <ver> --arch <openwrt-arch> [--outdir <dir>]
#   build-apk.sh luci --version <ver> [--outdir <dir>]
#
# <ver> uses apk syntax, which OpenWrt spells X.Y.Z-rN (not opkg's X.Y.Z-N).
#
# Examples:
#   build-apk.sh rill --binary target/aarch64-unknown-linux-musl/release/rill \
#       --version 0.22.0-r1 --arch aarch64_generic --outdir dist
#   build-apk.sh luci --version 0.22.0-r1 --outdir dist

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
MAINTAINER="Max Lv <max.c.lv@gmail.com>"
LICENSE="MIT"
URL="https://github.com/best-shuke/rill"
APK="${APK:-apk}"

usage() {
    sed -n '2,24p' "$0" | sed 's/^# \{0,1\}//'
    exit 1
}

# `apk mkpkg` records file ownership as found on disk, so the payload must be
# staged by root to end up root:root. (fakeroot does not work: the static
# apk-tools binary used in CI bypasses its LD_PRELOAD shim.)
if [ "$(id -u)" -ne 0 ]; then
    echo "build-apk.sh: must run as root (e.g. sudo -E) so the payload is owned by root:root" >&2
    exit 1
fi

command -v "$APK" >/dev/null 2>&1 || {
    echo "build-apk.sh: apk-tools 3 not found (set APK=/path/to/apk)" >&2
    exit 1
}
case "$("$APK" --version 2>/dev/null)" in
    "apk-tools "[3-9].*) ;;
    *)
        echo "build-apk.sh: '$APK' is not apk-tools >= 3.0 (needed for 'apk mkpkg')" >&2
        exit 1
        ;;
esac

sha256_of() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | cut -d' ' -f1
    else
        shasum -a 256 "$1" | cut -d' ' -f1
    fi
}

# check_version <ver>: apk-style X.Y.Z-rN.
check_version() {
    case "$1" in
        *-r[0-9]*) ;;
        *) echo "version '$1' is not apk-style; use X.Y.Z-rN (e.g. 0.22.0-r1)" >&2; exit 1 ;;
    esac
}

# write_pkg_meta <staging> <pkgname> [conffile...]
# Writes the OpenWrt apk bookkeeping under <staging>/files/lib/apk/packages/:
# <pkg>.list (owned files), and for conffiles <pkg>.conffiles plus
# <pkg>.conffiles_static ("<path> <sha256>"), mirroring include/package-pack.mk.
write_pkg_meta() {
    local stg="$1" root="$1/files" pkg="$2"; shift 2
    local meta="$root/lib/apk/packages" f
    mkdir -p "$meta"
    (cd "$root" && find . \( -type f -o -type l \) | sed 's|^\./|/|' | LC_ALL=C sort) > "$stg/pkg.list"
    mv "$stg/pkg.list" "$meta/$pkg.list"
    if [ $# -gt 0 ]; then
        : > "$meta/$pkg.conffiles"
        : > "$meta/$pkg.conffiles_static"
        for f in "$@"; do
            echo "$f" >> "$meta/$pkg.conffiles"
            echo "$f $(sha256_of "$root$f")" >> "$meta/$pkg.conffiles_static"
        done
    fi
    find "$root/lib" -type d -exec chmod 755 {} +
    find "$meta" -type f -exec chmod 644 {} +
}

# pack_apk <staging> <name> <version> <arch> <depends> <description> <output> [script-spec...]
# <staging>/files is the target filesystem tree; script specs are TYPE:FILE.
pack_apk() {
    local staging="$1" name="$2" version="$3" arch="$4" depends="$5" desc="$6" out="$7"; shift 7
    local args=() s
    for s in "$@"; do args+=(--script "$s"); done
    SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-0}" "$APK" mkpkg \
        --info "name:${name}" \
        --info "version:${version}" \
        --info "description:${desc}" \
        --info "arch:${arch}" \
        --info "license:${LICENSE}" \
        --info "origin:rill" \
        --info "url:${URL}" \
        --info "maintainer:${MAINTAINER}" \
        --info "depends:${depends}" \
        "${args[@]}" \
        --files "${staging}/files" \
        --output "${out}"
    echo "built ${out}"
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
    check_version "$version"

    local staging d
    staging="$(mktemp -d)"
    d="$staging/files"
    mkdir -p "$staging/scripts" \
             "$d/usr/bin" "$d/etc/init.d" "$d/etc/config" "$d/etc/rill" \
             "$d/etc/uci-defaults" "$d/usr/share/rill"

    install -m 755 "$binary" "$d/usr/bin/rill"
    install -m 755 "$SCRIPT_DIR/rill/files/rill.init" "$d/etc/init.d/rill"
    install -m 644 "$SCRIPT_DIR/rill/files/rill.config" "$d/etc/config/rill"
    install -m 644 "$SCRIPT_DIR/rill/files/config.yaml" "$d/etc/rill/config.yaml"
    install -m 755 "$SCRIPT_DIR/rill/files/gateway.sh" "$d/usr/share/rill/gateway.sh"
    install -m 755 "$SCRIPT_DIR/rill/files/arp-hijack.sh" "$d/usr/share/rill/arp-hijack.sh"
    install -m 755 "$SCRIPT_DIR/rill/files/rill-arp.init" "$d/etc/init.d/rill-arp"
    install -m 755 "$SCRIPT_DIR/rill/files/rill.uci-defaults" "$d/etc/uci-defaults/80_rill"
    find "$d" -type d -exec chmod 755 {} +

    write_pkg_meta "$staging" rill /etc/config/rill /etc/rill/config.yaml

    # Same logic as the ipk postinst. apk runs post-install on a fresh install
    # and post-upgrade on an upgrade; both do the idempotent enable.
    # IPKG_INSTROOT is set by OpenWrt image builds (offline rootfs): skip then.
    cat > "$staging/scripts/post-install" <<'EOF'
#!/bin/sh
[ -n "${IPKG_INSTROOT}" ] && exit 0
[ -f /etc/uci-defaults/80_rill ] && sh /etc/uci-defaults/80_rill && rm -f /etc/uci-defaults/80_rill
/etc/init.d/rill enable || true
# rill-arp self-gates on the (default-off) arp_hijack section, so enabling it
# is safe: it steers nothing until clients are selected in LuCI.
/etc/init.d/rill-arp enable || true
exit 0
EOF
    cp "$staging/scripts/post-install" "$staging/scripts/post-upgrade"

    # Runs on removal only (apk does not run the old pre-deinstall on upgrade),
    # so the service is not disabled across upgrades.
    cat > "$staging/scripts/pre-deinstall" <<'EOF'
#!/bin/sh
[ -n "${IPKG_INSTROOT}" ] && exit 0
/etc/init.d/rill-arp stop 2>/dev/null
/etc/init.d/rill-arp disable 2>/dev/null
/etc/init.d/rill stop 2>/dev/null
/etc/init.d/rill disable || true
exit 0
EOF
    chmod 755 "$staging"/scripts/*

    mkdir -p "$outdir"
    pack_apk "$staging" rill "$version" "$arch" libc \
        "A high-performance, rule-based tunneling proxy kernel in Rust, compatible with mihomo (Clash Meta). Static binary; configuration lives in /etc/rill/config.yaml, service settings in /etc/config/rill." \
        "${outdir}/rill_${version}_${arch}.apk" \
        "post-install:$staging/scripts/post-install" \
        "post-upgrade:$staging/scripts/post-upgrade" \
        "pre-deinstall:$staging/scripts/pre-deinstall"
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
    check_version "$version"

    local staging app="$SCRIPT_DIR/luci-app-rill" d
    staging="$(mktemp -d)"
    d="$staging/files"
    mkdir -p "$staging/scripts" "$d/www/luci-static"

    # htdocs/ maps to /www, root/ overlays / verbatim.
    cp -R "$app/root/." "$d/"
    cp -R "$app/htdocs/luci-static/." "$d/www/luci-static/"
    find "$d" -type d -exec chmod 755 {} +
    find "$d" -type f -exec chmod 644 {} +
    chmod 755 "$d/usr/libexec/rill-api" "$d/usr/libexec/rill-validate"

    write_pkg_meta "$staging" luci-app-rill

    cat > "$staging/scripts/post-install" <<'EOF'
#!/bin/sh
[ -n "${IPKG_INSTROOT}" ] && exit 0
rm -f /tmp/luci-indexcache* 2>/dev/null
/etc/init.d/rpcd reload 2>/dev/null
exit 0
EOF
    cp "$staging/scripts/post-install" "$staging/scripts/post-upgrade"

    cat > "$staging/scripts/post-deinstall" <<'EOF'
#!/bin/sh
[ -n "${IPKG_INSTROOT}" ] && exit 0
rm -f /tmp/luci-indexcache* 2>/dev/null
exit 0
EOF
    chmod 755 "$staging"/scripts/*

    mkdir -p "$outdir"
    pack_apk "$staging" luci-app-rill "$version" noarch "libc luci-base rill curl" \
        "LuCI support for rill: status overview, YAML config editor, service and transparent-proxy (gateway / side-router) settings, per-client proxy bypass, opt-in ARP-based client steering, logs, and the built-in rill web panel embedded in LuCI. Client steering uses the built-in unicast ARP sender." \
        "${outdir}/luci-app-rill_${version}_all.apk" \
        "post-install:$staging/scripts/post-install" \
        "post-upgrade:$staging/scripts/post-upgrade" \
        "post-deinstall:$staging/scripts/post-deinstall"
    rm -rf "$staging"
}

case "${1:-}" in
    rill) shift; build_rill "$@" ;;
    luci) shift; build_luci "$@" ;;
    *) usage ;;
esac
