# Packaging contract

The contract for the installable package: the ipk, the procd init script, the
config, and the reinstall script for after a firmware update.

## What is being installed

On the Pager, under `/mmc/od3sa-recon/` — **not** the overlay. The overlay is
15 MB and a firmware update wipes it; `/mmc` is a partition on the SD card
with 2.3 GB free and survives ✓.

| Path | What |
|---|---|
| `/mmc/od3sa-recon/od3sa-recond` | the daemon, static, soft-float, O32, MIPS32r2 |
| `/mmc/od3sa-recon/recon.sqlite` | the database (created at run time) |
| `/mmc/od3sa-recon/config.toml` | the configuration |
| `/mmc/od3sa-recon/plugins/` | the plugins |
| `/etc/init.d/od3sa-recond` | the procd init script — **the one thing on the overlay** |

Only the init script goes on the overlay, and `reinstall.sh` puts it back.

## The init script

A procd init script, as OpenWrt's are written:

```sh
#!/bin/sh /etc/rc.common
USE_PROCD=1
START=99
STOP=10

PROG=/mmc/od3sa-recon/od3sa-recond
CONFIG=/mmc/od3sa-recon/config.toml

start_service() {
    procd_open_instance
    procd_set_param command "$PROG" --collect --config "$CONFIG"
    procd_set_param respawn 3600 5 5
    procd_set_param nice 10
    procd_set_param stdout 1
    procd_set_param stderr 1
    procd_close_instance
}
```

- `respawn 3600 5 5` — restart it if it dies, at most five times in an hour,
  five seconds apart ✓ (OpenWrt's `respawn <threshold> <timeout> <retry>` ✓).
- `nice 10` — the daemon yields to everything else on a device with 104 MB of
  RAM and a CPU at 580 MHz ✓.
- **The init script must not touch `pineapd` or `blue5`** ✓, must not change
  a channel ✓, and must not bring an interface up or down ✓. It starts one
  program ✓.

## The configuration

`/mmc/od3sa-recon/config.toml`, read by the daemon. It holds the settings
that are not secrets and not per-run:

```toml
# The interface to read.
interface = "wlan1mon"

# Where the database lives.
database = "/mmc/od3sa-recon/recon.sqlite"

# The sockets the plugins use.
events_socket = "/tmp/od3sa-recon/events.sock"
query_socket = "/tmp/od3sa-recon/query.sock"

# Where gpsd is, if the Pager has a GPS.
gpsd = "127.0.0.1:2947"

# The alert rules.
[alerts]
enabled = true
new_device = { enabled = true, severity = "info" }
```

**The token is not in the configuration.** The daemon generates one at
start-up and writes it to the log once ✓ — a file on the SD card would be a
secret at rest ✓, and the device's overlay is not protected either ✓.

## The ipk

An opkg package, `od3sa-recon_<version>_mipsel_24kc.ipk`, containing:

- `/etc/init.d/od3sa-recond` — the init script
- `/mmc/od3sa-recon/` — the directory, and the daemon in it
- `/mmc/od3sa-recon/config.toml` — the configuration

**The ipk is built with the SDK's `ipk-build`**, from the SDK tree in
the SDK tree, where `build/build-ipk.sh` looks for it (the `SDK` environment variable overrides it).

The package's metadata names the architecture `mipsel_24kc` ✓ — that is the
device's architecture (`DISTRIB_ARCH=mipsel_24kc` ✓) — and the package
depends on nothing beyond what the device already has ✓ (the binary is
static ✓, so it needs no libc, no libpcap and no SQLite on the device ✓).

## The reinstall script

`/mmc/od3sa-recon/reinstall.sh`, run after a firmware update has wiped the
overlay ✓:

```sh
#!/bin/sh
# Put back the init script the firmware update removed.
set -e
cp -p /mmc/od3sa-recon/od3sa-recond.init /etc/init.d/od3sa-recond
chmod 0755 /etc/init.d/od3sa-recond
/etc/init.d/od3sa-recond enable
/etc/init.d/od3sa-recond restart
```

- **The init script is kept on the SD card too** ✓ — `/mmc/od3sa-recon/od3sa-recond.init` — so the reinstall has something to put back ✓.
- The script is **idempotent** ✓: running it twice does the same thing ✓.
- It does **not** touch the database, the plugins or the configuration ✓ — only the init script ✓.

## The build script

`build/build-ipk.sh` — builds the ipk from the SDK:

1. Check the SDK is there (`$SDK/scripts/ipkg-build`, or under `~/sdk/sdk/openwrt-sdk-*/scripts` by default).
2. Run `build/build-mipsel.sh` first, or check the binary is there ✓ — **the ipk carries the binary that `build-mipsel.sh` builds** ✓, not one built by the SDK's rustc (that build is not running and is not needed ✓).
3. Assemble the package directory and run `ipkg-build` ✓.
4. Print the ipk's path and its sha256 ✓.

**The script must not need the network** once the SDK and the toolchain are
there ✓.

## The tests

1. The init script passes `sh -n` ✓ and contains no reference to `pineapd`,
   `blue5`, `iw`, `iwconfig`, `ifconfig`, `ip link` or `iw dev` ✓ — a test
   that greps for them ✓.
2. The init script names the binary under `/mmc` ✓ and not under the overlay
   ✓.
3. The ipk builds, and its contents are the three things above ✓ — check it
   with `tar` ✓.
4. The package's metadata names `mipsel_24kc` ✓.
5. **The daemon inside the ipk is the static one**: check that the file in the
   package has no interpreter and no shared library ✓ (`readelf -l` and
   `readelf -d` ✓).
6. `reinstall.sh` passes `sh -n` ✓, is idempotent ✓, and only copies the
   init script ✓.

## The rules

- The packaging inputs live under `build/`, next to the build script:
  `build/build-ipk.sh`, `build/init.d/od3sa-recond`, `build/reinstall.sh`
  and `build/config.toml`.
- **Do not modify the daemon's source** to make it installable — if
  something is missing, say so.
- No new dependencies.
- The init script and the reinstall script must be POSIX `sh` — the
  device's shell is BusyBox `ash` — and must pass `sh -n`.
- The package contains no real data and no secrets.
