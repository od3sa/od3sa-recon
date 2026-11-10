# Changelog

The versions here are the ones the package is built with. A release is cut
by tagging the repository, and the tag's version has to match the workspace's
or the release job stops ✓.

## 0.1.4

**Fixed**

- **The size cap was never enforced.** The store had the retention rules
  and the collector never called them, so the database grew until the card
  filled. The collector now runs the retention pass every hour: it deletes
  the sightings and alerts that have aged out, deletes the devices that
  have no sighting left (with the rows that point at them), and rotates
  the database when it goes over the size cap.
- **The retention pass only deleted sightings.** The `alerts` table grows
  with every alert that is raised, and the `devices` and `ssids` tables
  grow with every device and every network that is seen, for ever. A pass
  that only deleted sightings would have left the database growing.
- **The configuration file was overwritten by the command line.** An
  option that was not given still overwrote what the file said, so
  `database`, `gpsd`, `events_socket`, `query_socket` and `seconds` in
  the file were ignored. `--flush-interval-ms`, `--batch-size` and
  `--device-capacity` were parsed and then never applied at all. An
  option is now "not given" when it is absent, not when it holds its
  default.
- The database is now created with `auto_vacuum = INCREMENTAL`, so the
  space a deleted row leaves goes back to the filesystem instead of
  sitting in the file for ever.

**Added**

- `retention_days` and `max_db_mb` in the configuration file, with
  `--retention-days` and `--max-db-mb` on the command line. The defaults
  are 30 days and 512 MB.

## 0.1.3

The first release from the public repository, and the first one that
carries the fixes below. The daemon's behaviour changes in two small ways,
and one dependency moves.

**Fixed**

- **Four of the five plugin manifests were invalid TOML** and would have
  been refused by the host, silently, one log line per plugin. The
  `fs:write:` capability was written as a key of its own instead of
  inside the `capabilities` array. The plugin tests read their manifests
  as text and looked for substrings, which cannot tell that a manifest
  parses, so nothing caught it. A test now parses every shipped manifest
  with the host's own parser.
- **The project's working log carried committed merge-conflict markers**
  from a union merge. Resolved; both sides were kept, because neither
  duplicated the other.
- **The daemon never printed the plugin tokens**, so a plugin that runs
  itself — `run = "external"`, which is all five of them — had no way to
  get one. It now prints each plugin's token once at start-up, and the
  collector prints its own query token, which it generated but did not
  show.
- The collector's database path was wrong in the design document: it is
  `/mmc/od3sa-recon/recon.sqlite`, with no `db/` component.

**Changed**

- **`rusqlite` 0.40 → 0.41**, and with it `libsqlite3-sys` 0.38 → 0.39.
  The bundled SQLite in 0.38 is vulnerable (RUSTSEC-2026-0459,
  CVE-2026-119375): a crafted database and write-ahead-log pair can make
  a query return uninitialised memory from the process. The fix is in
  SQLite 3.54.0, which `libsqlite3-sys` 0.39 bundles.
- **The minimum supported Rust version is 1.89**, up from 1.85. The fixed
  `rusqlite` requires it. The toolchains in use — stable 1.99.1 and the
  pinned nightly — are well above it.
- The internal crates' dependencies are declared in the workspace table
  rather than one path per crate, so they are versioned dependencies and
  not wildcards.

**Added**

- `deny.toml` and a CI job that runs `cargo deny`: the licence policy
  ("no GPL, LGPL or AGPL") is now enforced rather than only stated, and
  a known-vulnerable dependency fails the build.
- `SECURITY.md` and `CONTRIBUTING.md`.
- `build/publish.sh`, which builds the public tree from this one: it
  removes the private working record, rewrites the repository URL, sweeps
  the result for credentials, real addresses, real SSIDs, GPS tracks and
  private host names, and makes the single squashed commit.

## 0.1.2

No change to the daemon or the plugins: no source that goes into the
package has changed since 0.1.0.

- **The checksum in a release is now verifiable.** rustc embeds the
  absolute paths of the sources, so the same source built in two
  different directories gave two different binaries, and the checksum
  meant nothing to anyone who rebuilt it. The paths are now mapped to
  fixed ones, so a rebuild on any machine gives the same bytes.
- **The daemon no longer carries libpcap's transmit symbols in CI.**
  The build script looks for the target's `objcopy` by name, and the
  OpenWrt SDK calls it `mipsel-openwrt-linux-musl-objcopy` where the
  musl-cross one is `mipsel-linux-musl-objcopy`. The lookup found
  neither in CI, so the stripping was skipped with a warning and the
  released daemon had `pcap_inject` and `pcap_sendpacket` in its
  strings. They were never called — the crate declares neither — but
  the daemon is supposed to have no transmit entry point at all, and
  now it does not. The tool is found by its suffix, so both toolchains
  work.

## 0.1.1

No change to the daemon or the plugins: no source that goes into the
package has changed since 0.1.0.

- **The rust toolchain is pinned** (`nightly-2026-11-08`) instead of
  floating with the nightly channel. That was the reason the same source
  gave two different binaries: the 0.1.0 release was built by CI with a
  nightly two days newer than the build machine's, and the two binaries
  differed in their machine code. Two consecutive builds of the same
  source with the pinned toolchain now give the same binary.
- **The package is built on every merge**, not only by the release
  workflow, so a change that breaks the packaging fails in the pull
  request rather than at the next release.

## 0.1.0

The first release. Everything that does not need a Pager to be present.

**On the device**
- `od3sa-recond`, a static, soft-float, O32, MIPS32r2 binary for
  `mipsel_24kc`. It carries libpcap and SQLite inside it, so the device
  needs nothing alongside it: no libc, no interpreter, no shared library.
- `--dry-run` counts the frames on an interface and prints statistics.
- `--collect` is the collector: capture, aggregate, write and publish.
- `--query-socket` serves the read-only JSON-RPC query API.
- A read-only ingest adapter for the Bluetooth scanner's output.

**The package**
- `od3sa-recon_0.1.0_mipsel_24kc.ipk`, built with the OpenWrt 24.10.1
  SDK's own `ipkg-build`.
- A procd init script, which is the only thing on the overlay: the daemon,
  the database, the configuration and the plugins all live on the SD card,
  under `/mmc/od3sa-recon`, because a firmware update wipes the overlay
  and `/mmc` survives.
- `reinstall.sh`, which puts the init script back after such an update.

**The plugins**
- `pager-ui` — what the Pager's screen shows.
- `ndjson-export`, `wigle-export`, `kismet-feed` and `pcapng-meta`.

**What it does not do**
- It never transmits. The capture crate does not even declare libpcap's
  transmit functions.
- It never changes a channel, a mode, or whether an interface is up.
- It never touches `pineapd` or `blue5`.
- It never stores a frame payload or an EAPOL body.

**Not in this release**
- The pineapd recon ingest adapter, which waits on the recon database's
  schema.
- Anything that needs a Pager to have been tested on a Pager.
