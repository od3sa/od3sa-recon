//! Linking for the capture crate.
//!
//! The crate needs libpcap at link time and nothing else.
//!
//! * **mipsel** (the Pager): the static, soft-float `libpcap.a` built by
//!   `build/build-mipsel.sh`. The sysroot comes from `OD3SA_PCAP_SYSROOT`
//!   and defaults to `$HOME/toolchains/mipsel-linux-musl-sf`.
//! * **host** (x86, CI): the system libpcap, found with
//!   `pkg-config --cflags --libs libpcap`. If that is not installed, the
//!   local `$HOME/toolchains/x86-libpcap` prefix is used.
//!
//! If neither is found the build script prints a warning and links nothing.
//! The crate still compiles: the `extern "C"` declarations do not need the
//! library until something calls them.
//!
//! # The transmit symbols
//!
//! libpcap exports `pcap_inject` and `pcap_sendpacket`, the two functions
//! that put a frame onto an interface. This crate never declares them and
//! never calls them, but they live in the same object file (`pcap.o`) as the
//! reading functions we do call, so a *static* link drags them into the
//! daemon binary. `nm` on the device binary would then show two transmit
//! entry points, which is a bad look for a listen-only tool and a bad thing
//! for a reviewer to have to reason about.
//!
//! So on the mipsel target we link a copy of the archive with those two
//! symbols stripped. The result is a daemon that has no transmit entry point
//! at all, in any symbol table. This is a best-effort step: if the target's
//! `objcopy` cannot be found, or the surgery fails, we say so and link the
//! archive as it is. The crate's own guarantee (it declares no transmit
//! function, so there is no call site) does not depend on this.

use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

/// The default sysroot holding the static, soft-float mipsel libpcap.
const DEFAULT_MIPSEL_SYSROOT: &str = "toolchains/mipsel-linux-musl-sf";

/// The fallback host prefix, used when pkg-config knows nothing about
/// libpcap.
const DEFAULT_HOST_PREFIX: &str = "toolchains/x86-libpcap";

/// The libpcap functions that write a frame onto an interface. They are
/// stripped from the static archive before linking.
const TRANSMIT_SYMBOLS: [&str; 2] = ["pcap_inject", "pcap_sendpacket"];

fn main() {
    println!("cargo:rerun-if-env-changed=OD3SA_PCAP_SYSROOT");
    println!("cargo:rerun-if-changed=build.rs");

    // Key off TARGET, not CARGO_CFG_TARGET_ARCH: rustc reports the arch of
    // `mipsel-unknown-linux-musl` as "mips" (the endianness carries the
    // "little"), so an arch test for "mipsel" never matches.
    let target = env::var("TARGET").unwrap_or_default();
    if target.starts_with("mipsel-") {
        link_mipsel();
    } else {
        link_host();
    }
}

/// Link the static, soft-float mipsel libpcap from the sysroot.
fn link_mipsel() {
    let sysroot = match env::var("OD3SA_PCAP_SYSROOT") {
        Ok(path) if !path.is_empty() => PathBuf::from(path),
        _ => home().join(DEFAULT_MIPSEL_SYSROOT),
    };
    let lib_dir = sysroot.join("lib");
    let include_dir = sysroot.join("include");
    let archive = lib_dir.join("libpcap.a");

    if !archive.is_file() {
        println!(
            "cargo:warning=no static libpcap in {}: set OD3SA_PCAP_SYSROOT to the \
             sysroot that holds libpcap.a, or build it with build/build-mipsel.sh",
            lib_dir.display()
        );
        return;
    }

    // The archive to link against: a copy with the transmit symbols
    // stripped, if we can make one.
    match stripped_archive(&archive, &sysroot) {
        Some(dir) => {
            println!("cargo:rustc-link-search=native={}", dir.display());
        }
        None => {
            println!("cargo:rustc-link-search=native={}", lib_dir.display());
        }
    }
    println!("cargo:rustc-link-lib=static=pcap");
    // The headers are listed for tools that want them; this crate declares
    // the few libpcap functions it uses by hand.
    println!("cargo:rustc-link-search=native={}", include_dir.display());
}

/// Make a copy of `archive` without libpcap's transmit symbols.
///
/// Returns the directory holding the copy, or `None` if the surgery could
/// not be done, in which case the caller links the archive unchanged.
fn stripped_archive(archive: &Path, sysroot: &Path) -> Option<PathBuf> {
    let Some(objcopy) = find_objcopy(sysroot) else {
        println!(
            "cargo:warning=no objcopy for the mipsel target: the daemon will carry \
             libpcap's pcap_inject and pcap_sendpacket symbols (unused, but present)"
        );
        return None;
    };

    let out_dir = PathBuf::from(env::var("OUT_DIR").ok()?);
    let dir = out_dir.join("pcap-no-transmit");
    let filtered = dir.join("libpcap.a");
    if std::fs::create_dir_all(&dir).is_err() {
        return None;
    }
    if std::fs::copy(archive, &filtered).is_err() {
        return None;
    }

    // The two symbols are named by relocations in the MIPS procedure
    // descriptor table, so objcopy refuses to strip them while `.pdr` is
    // present. That section is unwind/debug metadata for exception
    // handling; libpcap is plain C with no exceptions, so dropping it from
    // this one object is safe.
    let mut command = Command::new(&objcopy);
    command.arg("--remove-section=.pdr");
    command.arg("--remove-section=.rel.pdr");
    for symbol in TRANSMIT_SYMBOLS {
        command.arg(format!("--strip-symbol={symbol}"));
    }
    command.arg(&filtered);

    let output = command.output().ok()?;
    if !output.status.success() {
        println!(
            "cargo:warning=objcopy failed on {}: {}",
            filtered.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        );
        return None;
    }
    if String::from_utf8_lossy(&output.stderr).contains("not stripping symbol") {
        println!("cargo:warning=objcopy could not strip the transmit symbols");
        return None;
    }

    // Check the result rather than trust it: the reading functions we call
    // must still be there, and the transmit ones must be gone.
    if !archive_has_reading_symbols(&filtered, sysroot) {
        println!("cargo:warning=the stripped libpcap.a lost its reading symbols");
        return None;
    }

    println!(
        "cargo:warning=stripped libpcap's transmit symbols (pcap_inject, \
         pcap_sendpacket) from the static archive: the daemon has no transmit \
         entry point"
    );
    Some(dir)
}

/// Check that the archive still has the reading functions and has lost the
/// transmit ones.
fn archive_has_reading_symbols(archive: &Path, sysroot: &Path) -> bool {
    let Some(nm) = find_nm(sysroot) else {
        // Without nm we cannot check; trust objcopy.
        return true;
    };
    let Ok(output) = Command::new(&nm)
        .arg("--defined-only")
        .arg(archive)
        .output()
    else {
        return true;
    };
    if !output.status.success() {
        return false;
    }
    let symbols = String::from_utf8_lossy(&output.stdout);
    if !symbols.contains("pcap_create") {
        return false;
    }
    !TRANSMIT_SYMBOLS
        .iter()
        .any(|symbol| symbols.contains(&format!("{symbol}\n")))
}

/// Find an `objcopy` that understands the mipsel target.
fn find_objcopy(sysroot: &Path) -> Option<PathBuf> {
    find_tool(sysroot, "objcopy")
}

/// Find an `nm` that understands the mipsel target.
fn find_nm(sysroot: &Path) -> Option<PathBuf> {
    find_tool(sysroot, "nm")
}

/// Find a target tool by looking for a file whose name ends with `tool`.
///
/// The name differs between toolchains: the musl-cross one calls it
/// `mipsel-linux-musl-objcopy` and the OpenWrt SDK's calls it
/// `mipsel-openwrt-linux-musl-objcopy`. Looking for the suffix finds
/// both, and looking for the whole name found neither in CI — which is
/// how the released daemon ended up carrying libpcap's transmit
/// symbols.
fn find_tool(sysroot: &Path, tool: &str) -> Option<PathBuf> {
    let mut directories: Vec<PathBuf> = Vec::new();

    // The cross toolchain the build script used, if it said where it was.
    if let Ok(bin) = env::var("OD3SA_CROSS_BIN") {
        directories.push(PathBuf::from(bin));
    }

    // Next to the linker cargo is using, if it was told about one.
    if let Ok(linker) = env::var("CARGO_TARGET_MIPSEL_UNKNOWN_LINUX_MUSL_LINKER")
        && let Some(dir) = Path::new(&linker).parent()
    {
        directories.push(dir.to_path_buf());
    }

    // In the sysroot itself, and in the cross toolchains next to it.
    directories.push(sysroot.join("bin"));
    if let Some(dir) = sysroot.parent() {
        directories.push(dir.join("mipsel-linux-musl-cross-sf").join("bin"));
        directories.push(dir.join("mipsel-linux-musl-cross").join("bin"));
    }

    // On the PATH.
    if let Ok(path) = env::var("PATH") {
        directories.extend(env::split_paths(&path));
    }

    for directory in directories {
        let Ok(entries) = std::fs::read_dir(&directory) else {
            continue;
        };
        for entry in entries.flatten() {
            let name = entry.file_name();
            if name.to_string_lossy().ends_with(tool) && entry.path().is_file() {
                return Some(entry.path());
            }
        }
    }

    None
}

/// Link the host libpcap: pkg-config first, the local prefix second.
fn link_host() {
    if let Some(flags) = pkg_config_libpcap() {
        for flag in flags {
            emit_flag(&flag);
        }
        return;
    }

    let prefix = home().join(DEFAULT_HOST_PREFIX);
    let lib_dir = prefix.join("lib");
    if !lib_dir.join("libpcap.so").is_file() && !lib_dir.join("libpcap.a").is_file() {
        println!(
            "cargo:warning=libpcap not found: pkg-config knows nothing about it and \
             {} holds no libpcap; the crate will not link against libpcap",
            prefix.display()
        );
        return;
    }

    println!("cargo:rustc-link-search=native={}", lib_dir.display());
    println!("cargo:rustc-link-lib=pcap");
    println!(
        "cargo:rustc-link-search=native={}",
        prefix.join("include").display()
    );
}

/// Ask pkg-config for the flags of the host libpcap.
fn pkg_config_libpcap() -> Option<Vec<String>> {
    let output = Command::new("pkg-config")
        .args(["--cflags", "--libs", "libpcap"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8(output.stdout).ok()?;
    let flags: Vec<String> = text
        .split_whitespace()
        .filter(|flag| !flag.is_empty())
        .map(|flag| flag.to_string())
        .collect();
    if flags.is_empty() { None } else { Some(flags) }
}

/// Turn one pkg-config flag into the cargo instructions it stands for.
fn emit_flag(flag: &str) {
    if let Some(path) = flag.strip_prefix("-L") {
        println!("cargo:rustc-link-search=native={path}");
    } else if let Some(path) = flag.strip_prefix("-I") {
        println!("cargo:rustc-link-search=native={path}");
    } else if let Some(name) = flag.strip_prefix("-l") {
        println!("cargo:rustc-link-lib={name}");
    }
    // Anything else (-pthread, -Wl,...) is left to the default linker setup.
}

/// The user's home directory, or the current directory if it is unknown.
fn home() -> PathBuf {
    match env::var("HOME") {
        Ok(home) if !home.is_empty() => PathBuf::from(home),
        _ => PathBuf::from(Path::new(".")),
    }
}
