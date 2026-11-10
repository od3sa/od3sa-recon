# od3sa-recon design (v0 draft, 2026-11-05)

## Constraints (from the device checks)
- MT7628 at 580 MHz, mipsel_24kc, OpenWrt 24.10.1, kernel 6.6.86, musl libc with soft-float ABI (`/lib/ld-musl-mipsel-sf.so.1`, confirmed 2026-11-05). The CPU has no FPU.
- **About 104 MB RAM available, no swap.**
- The overlay is only 15 MB, while `/mmc` has 2.3 GB free.
- `pineapd` owns `wlan1mon` (MT7921U, 2.4/5/6 GHz, hopping) and `wlan0mon` (2.4 GHz). `blue5` owns `hci0`. Both respawn if stopped, **and we never stop them.**

## Components
### 1. Collector daemon `od3sa-recond`
- **Wi-Fi capture:** libpcap, `pcap_open_live`-style read on existing monitor interfaces. `wlan1mon` is primary; `wlan0mon` and a USB dongle interface (for example `wlan2mon`) are optional.
  - It never sets channel, mode or up/down. Channel and frequency are read from radiotap per frame.
  - Snaplen is limited to headers (for example 256 B). There is no kernel-side BPF filter: the frames are filtered by the parser, which keeps the metadata and drops the body.
  - libpcap on a monitor interface lets several readers share it with pineapd (*assumption: standard AF_PACKET*; verify on the device).
- **Parsing (metadata only):**
  - radiotap: RSSI, channel/freq, rate, flags.
  - 802.11 management frames: beacon, probe req/resp, assoc/reassoc req/resp, auth/deauth/disassoc (*observed* only, for awareness alerts).
  - Control frames: counted.
  - Data frame headers: FromDS/ToDS → client↔BSSID mapping.
  - IEs: SSID, channel, RSN/WPA (AKM, ciphers, PMF), HT/VHT/HE capabilities, vendor IEs (OUI + type), WPS presence (flag and version only).
  - **EAPOL or handshake frames and data payloads are not stored.** They're counted as `eapol_seen` at most.
- **Ingest adapters:**
  - `blue5` output (BLE and BT). Formats are unverified: likely WiGLE CSV under `/root/loot/wigl*`, plus files in `/root/recon` and `/tmp/blue5_sock`.
  - `pineapd` recon (`/root/recon/`, reconname `pager`; format unverified).
  - Adapters are read-only: the blue5 one tails the CSV blue5 wrote, and it never opens the handshake loot. The pineapd one is not written yet.
- **GPS:** an optional gpsd client (localhost:2947, gpsd 3.25 is installed) that tags sightings with lat/lon/alt/fix quality.
- **Aggregation:** in-memory device table with bounded LRU, and sightings bucketed (for example 10 s per device per source). Writes are batched every N seconds.

### 2. Storage
SQLite in WAL mode at `/mmc/od3sa-recon/recon.sqlite`, with a versioned schema (see SCHEMA.md). The retention and rotation rules are written down — old sightings are pruned first, then sessions are rotated to `recon-YYYYMMDD.sqlite` — and the store implements them, but the collector does not call them yet, so the database grows until that is wired up.

### 3. Plugin system
See PLUGINS.md and `docs/api/`. It has:
- an event bus (Unix socket, NDJSON)
- a read-only query API (Unix socket JSON-RPC)
- out-of-process plugins with manifests and capability declarations

### 4. Alerts engine
Simple, defensive, awareness-only rules, configured in TOML:
- new device
- watchlist match (MAC, OUI or SSID)
- device seen again after an absence
- **rogue AP**: same SSID, different BSSID or security
- signal threshold (RSSI above X)
- deauth/disassoc burst observed

Alerts are written to `alerts` and emitted as `alert.raised`.

## Language and build
- **Rust**, built as a static `mipsel-unknown-linux-musl` binary.
  - That target is **Tier 3**: std is supported, but Rust doesn't ship prebuilt artefacts (https://doc.rust-lang.org/rustc/platform-support.html; the master table lists it under Tier 3 with musl 1.2.5).
  - **The daemon's build route.** Nightly `cargo build -Zbuild-std=std,panic_abort --target mipsel-unknown-linux-musl`, linked with the **OpenWrt SDK's own cross compiler** — the same gcc (13.3.0, OpenWrt r28597) that built the firmware the Pager is running. Scripted in [`build/build-mipsel.sh`](../build/build-mipsel.sh); it produces a fully static, soft-float, O32 binary.
    - The SDK's toolchain is used for its **C compiler**, not for Rust: the Rust side stays on the nightly toolchain with `-Zbuild-std`, because building a cross rustc is a much longer job and buys nothing here.
    - The SDK's `lang/rust` (1.96.0 in the 24.10.1 feed) is still the **packaging** route: it builds rustc and std for the target and produces a proper ipk. That is what the packaging uses.
  - **Why the SDK's toolchain rather than a musl-cross toolchain:** the widely used `musl.cc` mipsel toolchain is **hard-float** — its crt objects, its libc and its libgcc are all built for a CPU with an FPU — and the Pager's MT7628 has none. The SDK's toolchain is soft-float by default, which is the ABI the device runs. It also carries the target's kernel headers, so libpcap cross-builds without any header juggling.
  - **Route C:** `cross` with a custom image.
  - **Fallback:** C (C11, libpcap + sqlite3) if Rust is blocked. The design stays the same.
- **Float ABI: soft-float, required.** The upstream target spec sets `features = "+mips32r2,+soft-float"` and `cpu = "mips32r2"` with the O32 ABI ([source](https://github.com/rust-lang/rust/blob/master/compiler/rustc_target/src/spec/targets/mipsel_unknown_linux_musl.rs)), which matches the device loader `/lib/ld-musl-mipsel-sf.so.1`.
  - Do not add `-C target-feature=-soft-float`. A custom target JSON must keep `+soft-float`.
  - The 24kc can use `-C target-cpu=24kc` only if it keeps soft-float.
  - **Static linking (default)** doesn't need the loader.
  - If anything is **linked dynamically** (for example the system libpcap or sqlite), link it with the OpenWrt SDK's soft-float musl toolchain and sysroot. The ELF interpreter must be `/lib/ld-musl-mipsel-sf.so.1`; check with `readelf -l`. Never use a generic hard-float mipsel musl sysroot.
  - **The C toolchain's float ABI is the trap, and it is easy to fall into.** A mipsel musl toolchain is not automatically right for this device: the widely used `musl.cc` one is **hard-float**, and passing `-msoft-float` to *our* objects does not fix that — the linker warns that the crt objects are hard-float and the binary still comes out hard-float. The SDK's toolchain is soft-float by default, which is what the device runs. Always check `readelf -A` for `FP ABI: Soft float` before shipping a binary to the device.
  - **rustc's link line needs adjusting for a cross toolchain.** rustc's musl target passes linker options in the form `ld` understands, and it points the linker at the *host's* `/usr/lib`, where the cross libc for the wrong architecture would be found first. `build/build-mipsel.sh` writes a linker wrapper that rewrites those options to `-Wl,` form, drops the host's library directory, and asks for a static link — no interpreter and no shared library on the device.
  - C dependencies built by `cc`/`cmake` (libpcap, bundled sqlite) must also be compiled with `-msoft-float`. Verified for libpcap 1.10.5: the cross-built `libpcap.a` is soft-float throughout, and a probe linking it statically comes out soft-float and fully static.
- **The crates**, all first-party except two:
  | Crate | What it is |
  |---|---|
  | `od3sa-parse` | the hand-written radiotap and 802.11 parsers, and the information elements |
  | `od3sa-capture` | the libpcap binding — hand-written, so that the transmit functions are not even declared |
  | `od3sa-store` | the SQLite schema and migrations, the aggregator and the batched writer (`rusqlite`, bundled) |
  | `od3sa-events` | the NDJSON event bus |
  | `od3sa-gps` | the gpsd client |
  | `od3sa-alerts` | the awareness rules |
  | `od3sa-plugin` | the plugin host: manifests, capabilities, tokens, supervision |
  | `od3sa-plugins` | the plugins themselves |
  | `od3sa-collector` | the pipeline: capture, aggregate, write, publish |
  | `od3sa-ingest` | the read-only ingest adapters |
  | `od3sa-fixtures` | the synthetic frame builders, for the tests |
  | `od3sa-recond` | the daemon binary |

  The two outside dependencies are `rusqlite` (MIT; SQLite itself is public domain) and `serde_json` (MIT or Apache-2.0). The libpcap binding is written by hand rather than taken from a crate, because that is what keeps `pcap_inject` and `pcap_sendpacket` out of the tree. There is no async runtime: the daemon is a few threads and a socket each, and the RSS budget is 15 MB.
- **Memory budget:** the daemon stays **under 15 MB RSS at steady state, measured over 1 hour** on the device. Plugins have their own budget (PLUGINS.md).
- Builds run on the build machine or in CI, never on a laptop. Development and tests run on x86 with synthetic pcap fixtures.

## Packaging
- opkg `.ipk` for mipsel_24kc from the OpenWrt 24.10.1 SDK.
- Binary and config go under `/mmc/od3sa-recon/`, with a procd init script `/etc/init.d/od3sa-recond` (respawn, nice).
- `/mmc/od3sa-recon/reinstall.sh` restores the init script and symlinks after a firmware update, since the overlay is wiped.

## Testing
- Parser unit tests use synthetic frames built in code.
- Fixture pcaps are generated by a test helper (synthetic MACs and SSIDs). **Real captures are never committed.**
- CI (GitHub Actions): fmt, clippy and test on x86_64, plus a mipsel cross-build job (see).
