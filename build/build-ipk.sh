#!/usr/bin/env bash
#
# Build the opkg package for the Pager: od3sa-recon_<version>_mipsel_24kc.ipk
#
# What it does, in order:
#   1. find the OpenWrt 24.10.1 SDK and its scripts/ipkg-build
#   2. make sure there is a static mipsel binary of the daemon to package
#      (build/build-mipsel.sh builds it; the SDK's own rustc does not and is
#      not needed)
#   3. assemble the package tree and run ipkg-build on it
#   4. run the six checks from docs/PACKAGING.md against the result
#   5. print the ipk's path and its sha256
#
# The script needs no network once the SDK and the toolchain are in place:
# the daemon binary is built with the SDK's own cross compiler, and the
# package is assembled from files that are already here.
#
# Usage:
#   build/build-ipk.sh            # build the ipk and run the checks
#   build/build-ipk.sh --rebuild  # rebuild the daemon binary first
#
# Environment:
#   SDK          the SDK tree (default: $HOME/sdk/sdk/openwrt-sdk-*)
#   OUT_DIR      where the ipk is written (default: build/out)

set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="$REPO_DIR/build"
OUT_DIR="${OUT_DIR:-$BUILD_DIR/out}"
# Where the SDK is fetched to, and where it is unpacked.
WORK_DIR="${WORK_DIR:-$HOME/src/od3sa-mipsel}"
SDK_ROOT="${SDK_ROOT:-$WORK_DIR/sdk}"
DAEMON_BIN="$REPO_DIR/target/mipsel-unknown-linux-musl/release/od3sa-recond"
SDK_NAME="openwrt-sdk-24.10.1-ramips-mt76x8_gcc-13.3.0_musl.Linux-x86_64"

REBUILD=0
for argument in "$@"; do
    case "$argument" in
        --rebuild) REBUILD=1 ;;
        -h | --help)
            sed -n '3,25p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *)
            echo "unknown argument: $argument" >&2
            exit 2
            ;;
    esac
done

log() { printf '\n== %s\n' "$*"; }
fail() {
    echo "FAIL: $*" >&2
    exit 1
}

# Create a file with the given mode, and check that it took.
#
# The content is passed on stdin. The file is written once and its mode
# is then set in a loop: on the build machine, the first external process
# that looks up a path a file was just created at can miss it, and the
# next attempt succeeds. The device this package is built for has no such
# quirk, but the check must not be flaky on the build machine either.
make_file() {
    local mode="$1" path="$2" attempt
    cat > "$path" || return 1
    for attempt in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
        if chmod "$mode" "$path" 2>/dev/null; then
            return 0
        fi
        sleep 0.1
    done
    echo "FAIL: could not set the mode of $path" >&2
    return 1
}

# ---------------------------------------------------------------------------
# 1. the SDK
# ---------------------------------------------------------------------------
# Fetch the SDK and take its scripts out of it.
#
# Only the scripts are needed: ipkg-build assembles a package from a
# directory, and it does not want the target's staging tree. The tarball is
# the whole SDK, so this is a download and a partial unpack.
fetch_sdk() {
    local url="https://downloads.openwrt.org/releases/24.10.1/targets/ramips/mt76x8/${SDK_NAME}.tar.zst"
    local tarball="$WORK_DIR/${SDK_NAME}.tar.zst"

    # The message goes to stderr: this function runs inside a command
    # substitution, so anything it prints on stdout would become part of
    # the path it returns.
    log "fetching the OpenWrt SDK" >&2
    mkdir -p "$WORK_DIR"
    if [ ! -f "$tarball" ]; then
        curl -sSLo "$tarball" "$url" || return 1
    fi
    mkdir -p "$SDK_ROOT"
    tar --zstd -xf "$tarball" -C "$SDK_ROOT" \
        "$SDK_NAME/scripts" || return 1
    printf '%s' "$SDK_ROOT/$SDK_NAME"
}

find_sdk() {
    if [ -n "${SDK:-}" ] && [ -x "$SDK/scripts/ipkg-build" ]; then
        printf '%s' "$SDK"
        return 0
    fi
    # The SDK tree is unpacked under ~/sdk/sdk on this machine, but the
    # older layout put it directly under ~/sdk. Look in both.
    local candidate
    for candidate in "$HOME"/sdk/sdk/openwrt-sdk-* "$HOME"/sdk/openwrt-sdk-*; do
        if [ -x "$candidate/scripts/ipkg-build" ]; then
            printf '%s' "$candidate"
            return 0
        fi
    done
    return 1
}

SDK_DIR="$(find_sdk || fetch_sdk)" || fail "the OpenWrt SDK could not be fetched"
IPKG_BUILD="$SDK_DIR/scripts/ipkg-build"
[ -x "$IPKG_BUILD" ] || fail "the SDK has no scripts/ipkg-build"
log "SDK: $SDK_DIR"

# ---------------------------------------------------------------------------
# 2. the daemon binary
# ---------------------------------------------------------------------------
# The ipk carries the binary that build/build-mipsel.sh builds: a static,
# soft-float, O32 mipsel binary with no interpreter and no shared library.
# The SDK's own rustc is not used, and is not needed.
if [ "$REBUILD" = 1 ] || [ ! -f "$DAEMON_BIN" ]; then
    log "building the daemon for mipsel"
    bash "$BUILD_DIR/build-mipsel.sh"
else
    log "using the existing daemon binary"
fi
[ -f "$DAEMON_BIN" ] || fail "no daemon binary at $DAEMON_BIN"

# The binary in the package has to be the static one. Check it here, and
# check the copy inside the package again further down.
verify_static() {
    local binary="$1"
    if readelf -l "$binary" 2>/dev/null | grep -q INTERP; then
        echo "FAIL: $binary wants an interpreter" >&2
        readelf -l "$binary" | grep -A1 INTERP >&2
        return 1
    fi
    if readelf -d "$binary" 2>/dev/null | grep -q NEEDED; then
        echo "FAIL: $binary needs shared libraries" >&2
        readelf -d "$binary" | grep NEEDED >&2
        return 1
    fi
    return 0
}
verify_static "$DAEMON_BIN" || fail "the daemon binary is not static"

# ---------------------------------------------------------------------------
# 3. the package
# ---------------------------------------------------------------------------
VERSION="$(sed -n 's/^version = "\(.*\)"/\1/p' "$REPO_DIR/Cargo.toml" | head -1)"
[ -n "$VERSION" ] || fail "no version in Cargo.toml"
PACKAGE="od3sa-recon"
ARCH="mipsel_24kc"

PKG_DIR="$OUT_DIR/pkg"
rm -rf "$PKG_DIR"
install -d -m 0755 "$PKG_DIR/CONTROL" "$PKG_DIR/etc/init.d" \
    "$PKG_DIR/mmc/od3sa-recon" "$PKG_DIR/mmc/od3sa-recon/plugins"

# The init script goes on the overlay, and is kept on the SD card too, so
# that reinstall.sh has something to put back after a firmware update.
install -m 0755 "$BUILD_DIR/init.d/od3sa-recond" "$PKG_DIR/etc/init.d/od3sa-recond"
install -m 0755 "$BUILD_DIR/init.d/od3sa-recond" "$PKG_DIR/mmc/od3sa-recon/od3sa-recond.init"

# The daemon, the configuration and the reinstall script live on the SD card.
install -m 0755 "$DAEMON_BIN" "$PKG_DIR/mmc/od3sa-recon/od3sa-recond"
install -m 0644 "$BUILD_DIR/config.toml" "$PKG_DIR/mmc/od3sa-recon/config.toml"
install -m 0755 "$BUILD_DIR/reinstall.sh" "$PKG_DIR/mmc/od3sa-recon/reinstall.sh"

# The plugins: their manifest, their binary and anything else that belongs
# to them. A plugin's manifest says where its executable is, relative to the
# plugin's own directory, so the binary has to sit next to it.
#
# The plugin binaries are cross-built for the device, exactly like the
# daemon: static, soft-float, O32.
PLUGIN_SRC="$REPO_DIR/plugins"
PLUGIN_BIN="$REPO_DIR/target/mipsel-unknown-linux-musl/release"
if [ -d "$PLUGIN_SRC" ]; then
    for plugin_dir in "$PLUGIN_SRC"/*/; do
        plugin="$(basename "$plugin_dir")"
        [ -f "$plugin_dir/plugin.toml" ] || continue
        install -d -m 0755 "$PKG_DIR/mmc/od3sa-recon/plugins/$plugin"
        install -m 0644 "$plugin_dir/plugin.toml" \
            "$PKG_DIR/mmc/od3sa-recon/plugins/$plugin/plugin.toml"
        # Any extra files the plugin brings with it, such as the shell
        # script the Pager's payload menu runs.
        for extra in "$plugin_dir"/*.sh; do
            [ -f "$extra" ] || continue
            install -m 0755 "$extra" "$PKG_DIR/mmc/od3sa-recon/plugins/$plugin/"
        done
        # The binary, if it was built.
        if [ -f "$PLUGIN_BIN/$plugin" ]; then
            install -d -m 0755 "$PKG_DIR/mmc/od3sa-recon/plugins/$plugin/bin"
            install -m 0755 "$PLUGIN_BIN/$plugin" \
                "$PKG_DIR/mmc/od3sa-recon/plugins/$plugin/bin/$plugin"
        else
            log "the plugin $plugin has no binary yet; the package carries only its manifest"
        fi
    done
fi

cat > "$PKG_DIR/CONTROL/control" <<EOF
Package: $PACKAGE
Version: $VERSION
Architecture: $ARCH
# ipkg-build replaces this with the real size of the data archive.
Installed-Size: 1
Maintainer: Yakov Khalinsky <646086+yakovkhalinsky@users.noreply.github.com>
Section: utils
Priority: optional
Description: Passive, listen-only WiFi recon collector for the Pineapple Pager
 The daemon, the database and the plugins live on the SD card, under
 /mmc/od3sa-recon. Only the init script is installed on the overlay,
 because a firmware update wipes the overlay.
EOF

log "building the package"
mkdir -p "$OUT_DIR"

# The package is built with the SDK's ipkg-build. ipkg-build calls tar
# without an owner, so the entries would carry the builder's uid; a tar
# wrapper sets them to root, which is what a package on the device wants.
WRAPPER_DIR="$(mktemp -d)"
trap 'rm -rf "$WRAPPER_DIR"' EXIT
make_file 0755 "$WRAPPER_DIR/tar" <<EOF
#!/bin/sh
exec "$(command -v tar)" --owner=0 --group=0 "\$@"
EOF

SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-0}"
export SOURCE_DATE_EPOCH
TAR="$WRAPPER_DIR/tar" "$IPKG_BUILD" "$PKG_DIR" "$OUT_DIR"

IPK="$OUT_DIR/${PACKAGE}_${VERSION}_${ARCH}.ipk"
[ -f "$IPK" ] || fail "the package was not built"

# ---------------------------------------------------------------------------
# 4. the checks
# ---------------------------------------------------------------------------
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK" "$WRAPPER_DIR"' EXIT

# The ipk is a gzipped tar with debian-binary, data.tar.gz and
# control.tar.gz in it.
tar -xzf "$IPK" -C "$WORK"
[ -f "$WORK/data.tar.gz" ] || fail "the ipk has no data.tar.gz"
[ -f "$WORK/control.tar.gz" ] || fail "the ipk has no control.tar.gz"
mkdir -p "$WORK/data" "$WORK/control"
tar -xzf "$WORK/data.tar.gz" -C "$WORK/data"
tar -xzf "$WORK/control.tar.gz" -C "$WORK/control"

FAILED=0
check() {
    local name="$1"
    shift
    if "$@"; then
        echo "PASS: $name"
    else
        echo "FAIL: $name" >&2
        FAILED=1
    fi
}

log "the checks"

# 1. the init script: valid shell, and it names nothing that would touch a
#    radio.
init_clean() {
    sh -n "$BUILD_DIR/init.d/od3sa-recond" || return 1
    # The tool names are matched on word boundaries, so that an ordinary
    # word cannot trip the test; the two phrases are matched as they are.
    local word
    for word in pineapd blue5 iw iwconfig ifconfig; do
        if grep -qw -- "$word" "$BUILD_DIR/init.d/od3sa-recond"; then
            echo "  the init script mentions '$word'" >&2
            return 1
        fi
    done
    for word in "ip link" "iw dev"; do
        if grep -qF -- "$word" "$BUILD_DIR/init.d/od3sa-recond"; then
            echo "  the init script mentions '$word'" >&2
            return 1
        fi
    done
    return 0
}
check "the init script is valid shell and mentions no radio tool" init_clean

# 2. the init script names the binary under /mmc, not on the overlay.
init_paths() {
    grep -q '^PROG=/mmc/od3sa-recon/od3sa-recond$' "$BUILD_DIR/init.d/od3sa-recond" || return 1
    if grep -q '/overlay' "$BUILD_DIR/init.d/od3sa-recond"; then
        echo "  the init script mentions the overlay" >&2
        return 1
    fi
    if grep -qE '/usr/(bin|sbin)/od3sa-recond' "$BUILD_DIR/init.d/od3sa-recond"; then
        echo "  the init script names a binary outside /mmc" >&2
        return 1
    fi
    return 0
}
check "the init script runs the binary from /mmc" init_paths

# 3. the package holds the three things it should.
package_contents() {
    local listing="$WORK/listing.txt"
    tar -tzf "$WORK/data.tar.gz" > "$listing"
    sed 's|^\./||' "$listing" | sed 's|/$||' | grep -qx 'etc/init.d/od3sa-recond' || return 1
    sed 's|^\./||' "$listing" | sed 's|/$||' | grep -qx 'mmc/od3sa-recon/od3sa-recond' || return 1
    sed 's|^\./||' "$listing" | sed 's|/$||' | grep -qx 'mmc/od3sa-recon/config.toml' || return 1
    return 0
}
check "the package holds the init script, the daemon and the configuration" package_contents

# 4. the metadata names the device's architecture.
package_arch() {
    grep -qx "Architecture: $ARCH" "$WORK/control/control"
}
check "the package metadata names $ARCH" package_arch

# 5. the daemon inside the package is the static one.
packaged_binary_static() {
    local binary="$WORK/data/mmc/od3sa-recon/od3sa-recond"
    [ -f "$binary" ] || return 1
    verify_static "$binary"
}
check "the daemon in the package is static, with no interpreter" packaged_binary_static

# 6. reinstall.sh: valid shell, idempotent, and it copies only the init
#    script.
reinstall_ok() {
    sh -n "$BUILD_DIR/reinstall.sh" || return 1

    # It must not name the database, the configuration or the plugins, in
    # anything but a comment.
    local word commands
    commands="$(grep -v '^[[:space:]]*#' "$BUILD_DIR/reinstall.sh")"
    for word in "recon.sqlite" "config.toml" "plugins"; do
        if printf '%s' "$commands" | grep -qF -- "$word"; then
            echo "  reinstall.sh mentions '$word'" >&2
            return 1
        fi
    done

    # Run it twice in a sandbox. The init script it puts back is a stub
    # that records the calls it is asked for, because the real one needs
    # procd, which the build machine does not have.
    local sandbox="$WORK/sandbox"
    rm -rf "$sandbox"
    mkdir -p "$sandbox/mmc/od3sa-recon/plugins" "$sandbox/etc/init.d"
    make_file 0755 "$sandbox/mmc/od3sa-recon/od3sa-recond.init" <<STUB || return 1
#!/bin/sh
echo "\$1" >> "$sandbox/calls.log"
exit 0
STUB

    # Sentinels: the things the reinstall script must not touch.
    echo "the database" > "$sandbox/mmc/od3sa-recon/recon.sqlite"
    echo "the configuration" > "$sandbox/mmc/od3sa-recon/config.toml"
    echo "a plugin" > "$sandbox/mmc/od3sa-recon/plugins/one.sh"

    local before sentinels
    before="$(cd "$sandbox" && find . -type f ! -name calls.log | sort)"
    sentinels="$(md5sum "$sandbox/mmc/od3sa-recon/recon.sqlite" \
        "$sandbox/mmc/od3sa-recon/config.toml" \
        "$sandbox/mmc/od3sa-recon/plugins/one.sh")"

    OD3SA_PREFIX="$sandbox" sh "$BUILD_DIR/reinstall.sh" >"$WORK/reinstall.log" 2>&1 || {
        echo "  the first run failed:" >&2
        sed "s/^/    /" "$WORK/reinstall.log" >&2
        return 1
    }
    local first
    first="$(cd "$sandbox" && find . -type f ! -name calls.log | sort)"
    OD3SA_PREFIX="$sandbox" sh "$BUILD_DIR/reinstall.sh" >/dev/null 2>&1 || {
        echo "  the second run failed" >&2
        return 1
    }
    local second
    second="$(cd "$sandbox" && find . -type f ! -name calls.log | sort)"

    # Idempotent: the second run leaves the same state as the first.
    [ "$first" = "$second" ] || {
        echo "  the second run changed the state" >&2
        return 1
    }
    # Only the init script was copied: the one file that is new is the
    # init script, and nothing else appeared or disappeared.
    local added
    added="$(comm -13 <(printf '%s\n' "$before") <(printf '%s\n' "$second"))"
    [ "$added" = "./etc/init.d/od3sa-recond" ] || {
        echo "  the files the reinstall added were:$added" >&2
        return 1
    }
    # The database, the configuration and the plugins are untouched.
    [ "$sentinels" = "$(md5sum "$sandbox/mmc/od3sa-recon/recon.sqlite" \
        "$sandbox/mmc/od3sa-recon/config.toml" \
        "$sandbox/mmc/od3sa-recon/plugins/one.sh")" ] || {
        echo "  the reinstall touched the database, the configuration or the plugins" >&2
        return 1
    }
    # It enabled and restarted the service.
    grep -qx "enable" "$sandbox/calls.log" || return 1
    grep -qx "restart" "$sandbox/calls.log" || return 1
    return 0
}
check "reinstall.sh is valid, idempotent, and copies only the init script" reinstall_ok

if [ "$FAILED" = 1 ]; then
    fail "the checks failed"
fi

# ---------------------------------------------------------------------------
# 5. the result
# ---------------------------------------------------------------------------
log "the package"
ls -l "$IPK"
sha256sum "$IPK"
echo
echo "contents:"
tar -tzvf "$WORK/data.tar.gz"
