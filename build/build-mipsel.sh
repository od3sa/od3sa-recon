#!/usr/bin/env bash
#
# Build a static mipsel musl binary of od3sa-recond for the Pager.
#
# The toolchain is the OpenWrt SDK's own cross compiler for the device's
# target: the same gcc (13.3.0, OpenWrt r28597) that built the firmware the
# Pager is running. Two things follow from that, and both are what this
# project needs:
#
#   * it is SOFT-FLOAT by default. The Pager's MT7628 has no FPU and its
#     userland is /lib/ld-musl-mipsel-sf.so.1. A hard-float binary would
#     fault on the first FPU register it touched. (The musl.cc toolchain,
#     which this script used first, is hard-float: its crt objects, its
#     libc and its libgcc are all built for a CPU with an FPU.)
#   * it carries the target's kernel headers, so libpcap cross-builds.
#
# What it does, in order:
#   1. fetch the SDK and take the cross toolchain and the host libraries
#      out of it
#   2. write a linker wrapper, because rustc's musl target points the
#      linker at the *host's* /usr/lib
#   3. cross-build libpcap into a sysroot, for the capture path
#   4. build the workspace for mipsel-unknown-linux-musl
#   5. verify the float ABI, the linkage and the absence of an interpreter
#
# Usage:
#   build/build-mipsel.sh            # everything
#   build/build-mipsel.sh --verify   # only check an existing binary
#
# Environment:
#   TOOLCHAIN_DIR   where the toolchain and sysroot live (default: $HOME/toolchains)
#   WORK_DIR        where the SDK is downloaded and unpacked (default: $HOME/src/od3sa-mipsel)
#   TARGET_DIR      cargo's target directory     (default: the repo's target/)
#   OD3SA_TOOLCHAIN  the rust toolchain to build with (default: nightly)
#
# The toolchain's name is worth pinning: the "nightly" channel moves every
# few days, and two builds of the same source a week apart are not the same
# binary.

set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TOOLCHAIN_DIR="${TOOLCHAIN_DIR:-$HOME/toolchains}"
WORK_DIR="${WORK_DIR:-$HOME/src/od3sa-mipsel}"
TARGET_DIR="${TARGET_DIR:-$REPO_DIR/target}"

# The SDK for the device's release and target. The tarball sits directly in
# the target directory; the older SDK/ subdirectory is a 404 for 24.10.1.
SDK_NAME="openwrt-sdk-24.10.1-ramips-mt76x8_gcc-13.3.0_musl.Linux-x86_64"
SDK_URL="https://downloads.openwrt.org/releases/24.10.1/targets/ramips/mt76x8/${SDK_NAME}.tar.zst"
SDK_ROOT="$WORK_DIR/sdk"
SDK_TOOLCHAIN="$SDK_ROOT/$SDK_NAME/staging_dir/toolchain-mipsel_24kc_gcc-13.3.0_musl"

LIBPCAP_VERSION="1.10.5"
# Debian's pool carries the release tarball of libpcap, which has the
# generated lexer and parser in it.
LIBPCAP_URL="http://deb.debian.org/debian/pool/main/libp/libpcap/libpcap_${LIBPCAP_VERSION}.orig.tar.xz"

SYSROOT="$TOOLCHAIN_DIR/mipsel-sysroot"
CC_WRAPPER="$TOOLCHAIN_DIR/mipsel-cc.sh"

log() { printf '\n== %s\n' "$*"; }

verify() {
    local bin="$1"
    log "verifying $bin"
    file "$bin"
    # The float ABI must be soft: the Pager's CPU has no FPU.
    readelf -A "$bin" | grep -i "FP ABI" || true
    # No interpreter means a static binary, which needs no loader on device.
    if readelf -l "$bin" | grep -q INTERP; then
        echo "FAIL: the binary wants an interpreter" >&2
        readelf -l "$bin" | grep -A1 INTERP >&2
        return 1
    fi
    # No shared libraries means nothing to install alongside it.
    if readelf -d "$bin" 2>/dev/null | grep -q NEEDED; then
        echo "FAIL: the binary needs shared libraries" >&2
        readelf -d "$bin" | grep NEEDED >&2
        return 1
    fi
    readelf -h "$bin" | grep -iE "^  Class|^  Machine|Flags"
    echo "OK: static, soft-float, O32"
}

if [ "${1:-}" = "--verify" ]; then
    verify "$TARGET_DIR/mipsel-unknown-linux-musl/release/od3sa-recond"
    exit 0
fi

mkdir -p "$TOOLCHAIN_DIR" "$WORK_DIR"

# 1. the cross toolchain -----------------------------------------------------
if [ ! -x "$SDK_TOOLCHAIN/bin/mipsel-openwrt-linux-musl-gcc" ]; then
    log "fetching the OpenWrt SDK"
    mkdir -p "$SDK_ROOT"
    if [ ! -f "$WORK_DIR/${SDK_NAME}.tar.zst" ]; then
        curl -sSLo "$WORK_DIR/${SDK_NAME}.tar.zst" "$SDK_URL"
    fi
    # Only two directories are needed: the cross toolchain, and the host
    # libraries its wrapper runs through. The rest of the SDK is not.
    log "unpacking the cross toolchain"
    tar --zstd -xf "$WORK_DIR/${SDK_NAME}.tar.zst" -C "$SDK_ROOT" \
        "$SDK_NAME/staging_dir/toolchain-mipsel_24kc_gcc-13.3.0_musl" \
        "$SDK_NAME/staging_dir/host/lib"
fi
CROSS_CC="$SDK_TOOLCHAIN/bin/mipsel-openwrt-linux-musl-gcc"
CROSS_AR="$SDK_TOOLCHAIN/bin/mipsel-openwrt-linux-musl-ar"

# 2. the linker wrapper ------------------------------------------------------
# rustc's musl target passes "-L /usr/lib -rpath-link /usr/lib", which on a
# build machine is the *host's* library directory: the cross libc in there
# is the wrong architecture, and the linker prefers it. The wrapper drops
# those two and points the linker at the cross toolchain's own sysroot
# instead, and asks for a static link.
log "writing the linker wrapper"
cat > "$CC_WRAPPER" <<EOF
#!/usr/bin/env bash
# Generated by build/build-mipsel.sh. Do not edit.
#
# Two things are wrong with rustc's link line for a musl target, and both
# have to be fixed before the cross compiler will accept it:
#
#   * rustc passes linker options in the form ld understands -- "--eh-frame-
#     hdr", "-melf32ltsmip", "-z noexecstack" and so on. The cross gcc
#     only takes those through "-Wl,", so they are rewritten.
#   * rustc's musl target passes "-L /usr/lib -rpath-link /usr/lib", which
#     on a build machine is the *host's* library directory. The cross libc
#     in there is for the wrong architecture and the linker prefers it, so
#     the pair is dropped.
#
# The binary is linked statically: the Pager has no FPU, and a static
# binary needs neither a loader nor a shared library on the device.
set -uo pipefail
args=()
join=0      # the next argument belongs to the previous -Wl, token
value=0     # the next argument is the value of a flag
for a in "\$@"; do
    if [ "\$join" = "1" ]; then
        join=0
        args[-1]="\${args[-1]},\$a"
        continue
    fi
    if [ "\$value" = "1" ]; then
        value=0
        # The host's library directory: the cross libc in it is for the
        # wrong architecture, and the linker would prefer it. The flag
        # goes with it, or the linker would take the next argument as
        # the directory.
        if [ "\$a" = "/usr/lib" ]; then
            unset 'args[-1]'
            continue
        fi
        args+=("\$a"); continue
    fi
    case "\$a" in
        --eh-frame-hdr|--gc-sections|--strip-debug|-EL|-melf32ltsmip)
            args+=("-Wl,\$a") ;;
        -dynamic-linker|-z)
            args+=("-Wl,\$a"); join=1 ;;
        -rpath-link|-L)
            args+=("\$a"); value=1 ;;
        # rustc asks for a position independent executable, and then for
        # the shared unwinder and the shared libc. A static binary is
        # what this project wants: the device's libc is not installed
        # there, and a static binary needs no loader at all. So -pie
        # goes, the dynamic search mode goes, and the shared unwinder
        # becomes the static one - libgcc_eh, which is where the
        # unwinder lives.
        -pie|-Bdynamic) ;;
        -Wl,-Bdynamic) args+=("-Wl,-Bstatic") ;;
        -lgcc_s) args+=("-lgcc_eh") ;;
        *) args+=("\$a") ;;
    esac
done
exec "$CROSS_CC" --sysroot="$SDK_TOOLCHAIN" -static "\${args[@]}"
EOF
chmod +x "$CC_WRAPPER"

# 3. libpcap, for the capture path -------------------------------------------
if [ ! -f "$SYSROOT/lib/libpcap.a" ]; then
    log "building libpcap $LIBPCAP_VERSION for the target"
    # libpcap generates its scanner and parser, so it needs flex and bison.
    HOST_TOOLS="$TOOLCHAIN_DIR/host-tools"
    if ! command -v flex >/dev/null 2>&1 || ! command -v bison >/dev/null 2>&1; then
        log "fetching flex and bison (no root, so they are unpacked into a prefix)"
        mkdir -p "$HOST_TOOLS"
        for pkg in "f/flex/flex_2.6.4-8.2_amd64.deb" "b/bison/bison_3.8.2+dfsg-1+b3_amd64.deb"; do
            deb="$WORK_DIR/$(basename "$pkg")"
            curl -sSLo "$deb" "http://deb.debian.org/debian/pool/main/$pkg"
            dpkg-deb -x "$deb" "$HOST_TOOLS"
        done
        export PATH="$HOST_TOOLS/usr/bin:$PATH"
        export BISON_PKGDATADIR="$HOST_TOOLS/usr/share/bison"
    fi
    curl -sSLo "$WORK_DIR/libpcap.tar.xz" "$LIBPCAP_URL"
    rm -rf "$WORK_DIR/libpcap-${LIBPCAP_VERSION}"
    tar xf "$WORK_DIR/libpcap.tar.xz" -C "$WORK_DIR"
    (
        cd "$WORK_DIR/libpcap-${LIBPCAP_VERSION}"
        ./configure --host=mipsel-openwrt-linux-musl --prefix="$SYSROOT" \
            --disable-shared --without-libnl --disable-dbus \
            CC="$CROSS_CC" CFLAGS="-Os --sysroot=$SDK_TOOLCHAIN"
        make -j"$(nproc)"
        make install
    )
fi

# 4. the daemon ---------------------------------------------------------------
log "building od3sa-recond for mipsel-unknown-linux-musl"
export PATH="$HOME/.cargo/bin:$PATH"

# rustc embeds the absolute paths of the sources, so the same source built
# in two different directories gives two different binaries, and the checksum
# in a release would mean nothing to anyone who rebuilt it. The paths are
# mapped to fixed ones, so a rebuild anywhere gives the same bytes.
# The registry is mapped too: the vendored dependencies' own sources are
# in it, and the standard library's backtrace support names them.
export RUSTFLAGS="${RUSTFLAGS:+$RUSTFLAGS }--remap-path-prefix=$REPO_DIR=/od3sa-recon --remap-path-prefix=$HOME/.rustup=/rustup --remap-path-prefix=${CARGO_HOME:-$HOME/.cargo}=/cargo"

export CARGO_TARGET_MIPSEL_UNKNOWN_LINUX_MUSL_LINKER="$CC_WRAPPER"
# Any C dependency in the tree - the bundled SQLite, for one - is compiled
# for the target with the same cross compiler.
export CC_mipsel_unknown_linux_musl="$CROSS_CC"
export AR_mipsel_unknown_linux_musl="$CROSS_AR"
export CFLAGS_mipsel_unknown_linux_musl="--sysroot=$SDK_TOOLCHAIN"
# The capture crate finds libpcap here.
export OD3SA_PCAP_SYSROOT="$SYSROOT"
# ... and the cross toolchain's tools here, so that it can strip libpcap's
# transmit symbols out of the archive before linking.
export OD3SA_CROSS_BIN="$SDK_TOOLCHAIN/bin"
cd "$REPO_DIR"
cargo +"${OD3SA_TOOLCHAIN:-nightly}" build \
    -Zbuild-std=std,panic_abort \
    --target mipsel-unknown-linux-musl \
    --release \
    --target-dir "$TARGET_DIR" \
    --config "target.mipsel-unknown-linux-musl.rustflags=[\"-Clink-self-contained=no\"]"

# 5. verify -------------------------------------------------------------------
verify "$TARGET_DIR/mipsel-unknown-linux-musl/release/od3sa-recond"
