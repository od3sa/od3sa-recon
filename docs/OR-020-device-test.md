# On-device passive test — instructions for the device's owner

**Task:** On-device passive test: record the pineapd and blue5 PIDs and
the wlan1mon channel, run the dry-run for 10 minutes, then record them again
along with RSS. Everything unchanged, RSS under 15 MB.

**Written:** 2026-11-05. **For:** whoever owns the Pager.

**Depends on:** the `--dry-run` CLI and the mipsel build.

---

## 1. What this tests, and why

The daemon has to read a monitor interface that `pineapd` **already owns**. On
the Pager the radios are shared: `pineapd` holds `wlan1mon` in monitor mode and
`blue5` holds `hci0`, and both respawn if they are stopped — which is why we
never stop them. The one assumption still unverified is in DESIGN.md line 14:
*"libpcap on a monitor interface lets several readers share it with pineapd
(assumption: standard AF_PACKET; verify on the device)"*. This test is the check.
We open `wlan1mon` for **reading only**, alongside `pineapd`, for ten minutes,
and we prove three things: `pineapd` and `blue5` were not disturbed (same
PIDs before and after), the interface was not reconfigured (same channel
pattern, `wlan0cli` still up), and the daemon is small enough to live on the
device (RSS under 15 MB) and actually sees frames.

Nothing in this test transmits anything. The daemon reads; it never writes a
frame, never sets a channel, never changes a mode and never brings an
interface up or down.

---

## 2. The guardrails, restated

These are the project rules, in the words of the person running the test.
They are not optional and they are not altered by anything in this document.

- **Never stop, restart or reconfigure `pineapd` or `blue5`.** Not with
  `/etc/init.d/… stop`, not with `kill`, not with `reboot`. They respawn
  anyway, and a stop test is not part of this test.
- **Never change the channel, the mode or the up/down state of `wlan1mon` or
  `wlan0mon`** — or of any internal radio. So: no `iw … set`, no
  `iw … channel`, no `ifconfig … up/down`, no `ip link set`, no `wpa_cli`, no
  `hostapd_cli`. Read them with `iw … info` and `ip link show`; that is all
  this document asks you to do.
- **Never open `hci0`.** No `bluetoothctl`, no `hciconfig`, no `hcitool`, no
  `btmgmt`. The daemon is Wi-Fi only in this test.
- **Nothing that transmits.** The daemon has no transmit path at all: the
  capture contract in `docs/CAPTURE-API.md` declares only the libpcap
  functions that *read*, so `pcap_inject` and `pcap_sendpacket` are never
  declared and there is no call site that could send a frame. libpcap also
  has no API for setting a channel or a mode. `pineapd`'s own transmissions
  during the test are its own business and are expected — we are only adding a
  reader.
- **Do not install anything.** No `opkg install`, no package downloads, nothing
  in `/etc/init.d`, no new init scripts, no scheduled jobs.
- **Read-only on the device** except for exactly three things: creating
  `/mmc/od3sa-recon/`, copying the binary into it, and writing two log files
  into `/tmp` (tmpfs, gone at the next reboot). Nothing else on the device is
  modified.
- **Never commit real data.** What you paste back gets redacted first — see
  §7.3. Do not paste anything out of `/root/recon` or `/root/loot`: those hold
  real captures.

If a step in this document asks you to do something that would break one of
these rules, **stop and report instead**. There is no scenario in this test worth
changing a radio for.

---

## 3. Before the run: the baseline

Everything here is read-only. Run it **before** the binary is copied and before
the daemon starts, and run exactly the same block again afterwards (§6.1).

**Note on the shell:** the Pager's shell is BusyBox `ash`. The commands below
are plain POSIX `sh` with no bashisms and no GNU-only flags — only `sed`,
`grep`, `sort`, `tail`, `head`, `wc`, `date`, `tr`, `df`, `free`, `ps` and
`iw`, all of which BusyBox has. If any of them is missing, paste the raw
output anyway and I will read it.

### 3.1 The baseline block

Paste this whole block into the Pager shell:

```sh
sec() { echo; echo "===== $* ====="; }

pid_of() {
  for p in /proc/[0-9]*; do
    c=$(tr '\0' ' ' < "$p/cmdline" 2>/dev/null)
    case "$c" in *"$1"*) echo "PID ${p#/proc/} : $c" ;; esac
  done
}

sec "processes (pineapd, blue5)"
pid_of pineapd
pid_of blue5
echo "--- same thing with ps, for reading ---"
ps w | grep -E '[p]ineapd|[b]lue5'

sec "wlan1mon info"
iw dev wlan1mon info
iw dev wlan1mon link
ip link show wlan1mon

sec "wlan0cli"
ip link show wlan0cli

sec "memory"
free -k
```

Notes on what you are looking at:

- `pid_of` reads `/proc/*/cmdline` and prints the PID followed by the command
  line. `pineapd` shows up as `/usr/sbin/pineapd --recon=true --reconpath
  /root/recon/ …`; `blue5` shows up as `/usr/bin/blue5 -D … -i 0 …` and on
  some boots as a bare `blue5` process name. Both forms are fine — the match
  is on the substring, not on the path. **The PID is the number right after
  "PID".** If `pid_of` prints nothing for either, the process name is different
  from what we expect: use the `ps w` line, which lists everything, and tell
  me the exact name you see.
- `iw dev wlan1mon info` prints `type: monitor` and a `channel N (…, MHz), …`
  line. **Write down the channel number and the type.** If the type is not
  `monitor`, stop and report — do not change the mode.
- `iw dev wlan1mon link` is normally empty for a monitor interface. It is
  there because the interface's link state is part of what must not change.
- `ip link show wlan1mon` prints the interface flags: `UP` must be there, and
  `type` must still be `monitor` according to `iw`. Note the flags word by
  word — see the note on `PROMISC` in §7.2.
- `ip link show wlan0cli` prints the interface flags. **The word `UP` in the
  flags must be there.** `wlan0cli` is the Pager's client connection to your
  home network; it must still be up afterwards. Do **not** run
  `iw dev wlan0cli link` — it prints the joined SSID, which must not be
  pasted back. If `ip` is missing, use `ifconfig wlan0cli` instead.
- `free -k` prints kilobytes. Note the `available` line, so we can tell
  whether the daemon cost us anything.

### 3.2 Also note, for the copy step

```sh
df -h /mmc
```

`/mmc` had 2.3 GB free when this was written. The overlay (`/overlay`) is only
15.3 MB with 14.6 MB free and is **wiped by a firmware update** — so `/mmc`
is the only place the binary may go.

---

## 4. Copying the binary onto the device

> **The address is `172.16.52.1`, over the USB interface.** That is the
> address every Pager gets on its USB interface, so it is fixed and it does
> not depend on the home network or on any DHCP lease. `wlan0cli`, the Wi-Fi
> side, has a different and possibly changing address; this document does
> not use it.
>
> Plug the Pager in over USB and `scp` and `ssh` work over that interface.
> If the USB interface is not up — a charge-only cable, or a cable that
> carries power but not data — fall back to one of these, which need no
> network at all:
>
> - **The SD card.** `/mmc` is `mmcblk0p1`, a partition on the Pager's SD
>   card. Copy the binary onto that partition from the laptop, put the card
>   in the Pager, and it is already at `/mmc/od3sa-recon/od3sa-recond`.
> - **A USB serial console.** The device has `cdc_acm` interfaces (what they
>   carry is still an open question). If one of them is a console,
>   that is a shell with no network involved.
>
> If you reach the Pager by a name that resolves, use the name instead of
> the address and nothing else in this document changes.

The binary is built on the build machine by
`build/build-mipsel.sh` and lands at
`target/mipsel-unknown-linux-musl/release/od3sa-recond`. It is fully static,
soft-float, O32, MIPS32r2, about 5 MB, so it needs **nothing** alongside it:
no interpreter, no shared library, no libpcap and no SQLite on the device —
they are inside the binary. The device has no
git and no compiler, so it is copied over with `scp`.

### 4.1 On the device (one command, creates the directory)

```sh
ssh root@172.16.52.1 'mkdir -p /mmc/od3sa-recon && df -h /mmc'
```

`mkdir -p` is the only thing in this whole document that writes to the
device outside `/tmp`. It creates the directory the project will use for the
install later (DESIGN.md puts the binary and the config under
`/mmc/od3sa-recon/`), so it is not a throwaway.

### 4.2 On the build machine

```sh
cd /path/to/od3sa-recon
file target/mipsel-unknown-linux-musl/release/od3sa-recond
scp target/mipsel-unknown-linux-musl/release/od3sa-recond root@172.16.52.1:/mmc/od3sa-recon/od3sa-recond
```

`file` on the build machine should say something like:

```
ELF 32-bit LSB pie executable, MIPS, MIPS32 rel2 version 1 (SYSV), static-pie linked
```

and `readelf -A` on the same file should say `FP ABI: Soft float`. If it says
**hard float**, stop — that binary will fault on the Pager's FPU-less CPU.

### 4.3 On the device: verify the copy

```sh
ssh root@172.16.52.1 'chmod 0755 /mmc/od3sa-recon/od3sa-recond; ls -l /mmc/od3sa-recon/; /mmc/od3sa-recon/od3sa-recond --version'
```

- `chmod 0755` is part of the copy step (it only sets the permission bits on
  the file we just created; `scp` usually carries the mode already, this is
  insurance).
- `file` is probably **not** installed on the Pager — it is not in the
  installed-packages list. If `file` *is* there, run
  `file /mmc/od3sa-recon/od3sa-recond` as well and paste it. Otherwise
  `ls -l` plus `--version` is the check.
- `--version` must print `od3sa-recond <version>`, where the version is the
  one in the package's `Cargo.toml` (check the tag you downloaded). If you
  get `Exec format error`, `not found`, or an "unknown argument" error, the
  binary is wrong or the copy failed: see §8.

---

## 5. The run

**The run is read-only.** The daemon opens `wlan1mon` for reading, counts
frames and prints a summary line every second. It does not change the
channel, the mode, the up/down state or anything else on the interface, and
it never transmits.

### 5.1 A ten-second smoke test first

Do this before the long run, so a wrong interface name or a missing binary
does not cost ten minutes:

```sh
/mmc/od3sa-recon/od3sa-recond --dry-run --interface wlan1mon --seconds 10
```

Expected: a startup line with the version and the passive notice, then about
ten summary lines, then a final summary. The frame count should be greater
than zero, though a zero count over ten seconds is not a failure by itself —
the acceptance check is on the ten-minute run, and §8 explains a quiet
channel. What *is* a failure here is an error message about opening the
interface: if you see one, stop and go to §8, do not go on to the long run.

### 5.2 The ten-minute run (single session)

This variant samples the RSS in the same session, which is the most reliable
way to catch the daemon's memory use while it is actually running.

```sh
/mmc/od3sa-recon/od3sa-recond --dry-run --interface wlan1mon --seconds 600 > /tmp/od3sa-dryrun.log 2>&1 &
DPID=$!
echo "daemon PID is $DPID"

(
  while [ -d "/proc/$DPID" ]; do
    rss=$(sed -n 's/^VmRSS:[[:space:]]*\([0-9]*\).*/\1/p' "/proc/$DPID/status" 2>/dev/null)
    chan=$(iw dev wlan1mon info 2>/dev/null | sed -n 's/^[[:space:]]*channel \([0-9]*\).*/\1/p')
    echo "$(date +%s) rss_kb=${rss:-?} chan=${chan:-?}"
    sleep 10
  done
) > /tmp/od3sa-rss.log 2>&1 &

wait $DPID
echo "daemon exit status: $?"
```

What this does:

- starts the daemon in the background, so `$DPID` is its PID;
- runs a sampler loop that writes one line every ten seconds to
  `/tmp/od3sa-rss.log`, each line being
  `<unix time> rss_kb=<VmRSS> chan=<channel>`;
- the sampler stops by itself when the daemon exits (the `/proc/<pid>`
  directory disappears);
- `wait` blocks until the daemon has finished its 600 seconds.

The two log files are written into `/tmp`, which is **tmpfs**: they use RAM,
they are gone at the next reboot, and they are removed in §9.

**To stop early:** press **Ctrl-C** in the foreground variant below, or
`kill $DPID` in this one (a plain `kill` sends SIGTERM to *our own* daemon
only — never send a signal to `pineapd`, `blue5` or anything else). Stopping
early is safe: it just ends our read-only capture. A partial run is still
useful evidence, as long as you say how long it lasted.

### 5.3 The foreground variant (two terminals)

If you prefer to watch the summary live, run the daemon in the foreground in
one SSH session:

```sh
/mmc/od3sa-recon/od3sa-recond --dry-run --interface wlan1mon --seconds 600
```

Press **Ctrl-C** to stop it early. In a second SSH session, find the PID and
sample the RSS by hand:

```sh
pid_of() {
  for p in /proc/[0-9]*; do
    c=$(tr '\0' ' ' < "$p/cmdline" 2>/dev/null)
    case "$c" in *"$1"*) echo "PID ${p#/proc/} : $c" ;; esac
  done
}
pid_of od3sa-recond
grep VmRSS /proc/<pid>/status
```

Replace `<pid>` with the number from the previous line. This is the same
`VmRSS` figure the background sampler records, so either way works — the
background sampler is better because it keeps a time series.

---

## 6. After the run

### 6.1 The after block

Run the same block as §3.1, with the daemon stopped:

```sh
sec() { echo; echo "===== $* ====="; }

pid_of() {
  for p in /proc/[0-9]*; do
    c=$(tr '\0' ' ' < "$p/cmdline" 2>/dev/null)
    case "$c" in *"$1"*) echo "PID ${p#/proc/} : $c" ;; esac
  done
}

sec "processes (pineapd, blue5)"
pid_of pineapd
pid_of blue5
echo "--- same thing with ps, for reading ---"
ps w | grep -E '[p]ineapd|[b]lue5'

sec "wlan1mon info"
iw dev wlan1mon info
iw dev wlan1mon link
ip link show wlan1mon

sec "wlan0cli"
ip link show wlan0cli

sec "memory"
free -k
```

### 6.2 The RSS log and the peak RSS

**The RSS must be read while the daemon is running**, because `/proc/<pid>/status`
disappears when the process exits — after the run there is nothing to read.
That is why §5.2 samples it every ten seconds into `/tmp/od3sa-rss.log`.

Peak RSS (in kB):

```sh
sed -n 's/.*rss_kb=\([0-9]*\).*/\1/p' /tmp/od3sa-rss.log | sort -n | tail -1
```

If `sort`/`sed` are unhappy, just paste the whole log and I will read the
numbers off it. Number of samples (should be about 60 for a 600-second run):

```sh
wc -l < /tmp/od3sa-rss.log
```

The budget is **15 MB RSS**, i.e. **15360 kB** (VmRSS is reported in kB; 15 MB
= 15 × 1024 × 1024 bytes = 15728640 bytes = 15360 kB).

### 6.3 The daemon's own log

```sh
head -5 /tmp/od3sa-dryrun.log
tail -5 /tmp/od3sa-dryrun.log
```

The tail is the final summary: the totals for the ten minutes. The exact
wording is the CLI's business; what matters is that there is **no error** in
the file and that the total frame count is **greater than zero**.

### 6.4 A control sample of the channel (important)

DESIGN.md records that `pineapd` **hops channels** on `wlan1mon` (and the
interface was sitting on ch100 when the device was first checked). So the
channel before and after a ten-minute run may differ **because pineapd
hopped**, not because of us. To tell those two apart, take one more channel
sample a few minutes later, with the daemon **not** running:

```sh
iw dev wlan1mon info
```

If the channel differs from the baseline sample too, then the hopping
explains the difference and the daemon is not implicated. The channel column
in `/tmp/od3sa-rss.log` shows the hopping pattern during the run as well.

---

## 7. What to paste back

### 7.1 The list

1. The **baseline block** output (§3.1) — the `===== processes =====`,
   `===== wlan1mon info =====`, `===== wlan0cli =====` and `===== memory =====`
   sections.
2. `df -h /mmc` (before the copy).
3. The **`file` output** of the binary on the build machine, and the **device**
   `ls -l` plus `od3sa-recond --version` output.
4. The **daemon's log**: the first five lines and the last five lines of
   `/tmp/od3sa-dryrun.log`.
5. The **RSS log**: `cat /tmp/od3sa-rss.log` (or the peak-RSS number and the
   sample count, if the log is long).
6. The **after block** output (§6.1), plus the control channel sample (§6.4).
7. Anything that looked wrong, in your own words.

### 7.2 What "success" looks like

| Check | Success |
|---|---|
| pineapd PID | **Identical** before and after. |
| blue5 PID | **Identical** before and after. |
| wlan1mon channel | **Identical** before and after — or the difference is explained by pineapd's own hopping, i.e. the §6.4 control sample (taken with the daemon stopped) differs from the baseline too, and the channel column of the RSS log shows the hop happening during the run. |
| wlan1mon type | Still `monitor` before and after. |
| wlan0cli | Still `UP` in `ip link show wlan0cli` before and after. |
| Daemon RSS | Peak **under 15360 kB** (15 MB) in the RSS log. |
| Frame count | **Greater than zero** in the final summary. |
| Interface open | **No error** about opening the interface anywhere in the log. |
| Memory | `free -k` `available` no worse than the baseline by more than the daemon's RSS. |

A note on the channel check, because it is the one that is not a clean
before/after comparison: the daemon **cannot** change a channel. libpcap has
no channel API, and the capture crate never calls `iw`, `wpa_cli`,
`ifconfig` or `ip` — the review of the CLI checks exactly that. The
interesting evidence is that `pineapd` stayed up with the same PID and kept
hopping while our reader was attached.

One more thing worth looking at: whether `ip link show wlan1mon` shows the word
`PROMISC` in the flags while the daemon is running.

**It should not change, and the reason is worth knowing.** On Linux, libpcap
implements promiscuous mode as a *per-socket* membership — a
`PACKET_ADD_MEMBERSHIP` with `PACKET_MR_PROMISC` on the packet socket
(`pcap-linux.c`, the `PACKET_MR_PROMISC` branch) — and not by setting
`IFF_PROMISC` on the interface. The `SIOCSIFFLAGS` code in libpcap is on the
path where libpcap creates a monitor interface of its own through nl80211,
which we never do: we open an interface that already exists. So opening the
capture changes **nothing** about `wlan1mon` — not its flags, not its channel,
not its mode, not whether it is up.

If the flags word by word does change while the daemon runs, that is a finding
worth reporting rather than tidying away. Do not try to change anything.

### 7.3 Redact before pasting

Replace, with `<redacted>`:

- every MAC address (`xx:xx:xx:xx:xx:xx` → `<redacted>`) — including the one
  `ip link show` prints;
- every SSID;
- every Bluetooth device address (BD address);
- anything else identifying: a location, a serial number, the name of your
  home network, GPS coordinates.

Do **not** paste anything out of `/root/recon` or `/root/loot` — those hold
real captures.

---

## 8. If something goes wrong

Every step below is read-only. **Do not "fix" anything by reconfiguring a
radio.**

**The daemon says the interface does not exist.**
`iw dev` lists the interfaces; check the exact name (`wlan1mon`, `wlan0mon`).
Do not create an interface and do not bring one up — report the `iw dev`
output.

**The daemon says the interface is not a monitor interface**
(`CaptureError::NotMonitor`, or a datalink complaint).
`iw dev wlan1mon info` shows `type: monitor` when `pineapd` has set it up.
If it shows `managed`, `pineapd` is not in the state we expect: report it and
stop. **Do not change the mode.**

**The daemon cannot open the interface ("device busy" / "in use").**
Something else holds it exclusively. Run `ps w` and see what. Report it.
**Do not kill anything** — in particular not `pineapd`. Note that on Linux,
AF_PACKET normally allows several readers on one monitor interface, so a
genuine "busy" error is unexpected and worth reporting.

**The frame count is zero.**
Most likely there was simply no traffic on that channel during the window —
`pineapd` hops, and a quiet 5 GHz channel is normal. Check the channel column
in `/tmp/od3sa-rss.log`: if the channel changed during the run, the reader was
following the hop. Let it run longer (`--seconds 1800`) rather than changing
the channel. **Never change the channel to make the count go up.**

**The daemon exits immediately.**
Read `/tmp/od3sa-dryrun.log`. An "unknown argument" message means the CLI
differs from what this document says — paste the log and the `--help` output.
`Exec format error` means the wrong binary: check `file` on the build machine.

**The binary is "not found" on the device.**
Check the path: `ls -l /mmc/od3sa-recon/`. The `scp` may have failed, or it
may have landed with a different name.

**The RSS is over 15 MB.**
Report the number. Do not reduce it by changing anything on the device — the
memory budget is a code question, not a device question.

**Anything at all looks wrong.**
Stop the run (Ctrl-C or `kill $DPID`), paste what you have, and wait. Do not
restart `pineapd` or `blue5` even if they are gone — they respawn on their
own, and a manual restart would spoil the PID comparison this test exists to
make.

---

## 9. Cleanup

On the device:

```sh
rm -f /mmc/od3sa-recon/od3sa-recond
rm -f /tmp/od3sa-dryrun.log /tmp/od3sa-rss.log
rmdir /mmc/od3sa-recon 2>/dev/null
ls -l /mmc/od3sa-recon 2>/dev/null; ls -l /tmp | grep od3sa
```

`rmdir` only succeeds if the directory is empty; if it complains, leave it —
it is where the permanent install will go later (DESIGN.md: binary and config
under `/mmc/od3sa-recon/`).

**`/mmc` is not wiped by a firmware update; the overlay is.** So `/mmc` is the
right place for anything that must survive a reflash, and the overlay
(`/overlay`, only 15.3 MB with 14.6 MB free) is the wrong place for anything
at all — it is thrown away on every firmware update, and it is nearly full.

On the build machine, nothing to clean up.

---

## 10. Open questions this test is meant to answer

- Does a second libpcap reader on `wlan1mon` leave `pineapd` undisturbed?
  (DESIGN.md line 14 — the assumption this test checks.)
- Is the channel difference, if there is one, pineapd's hopping or ours?
  (§6.4.)
- Can the daemon stay under 15 MB RSS? (The first hint of's one-hour
  soak.)
- Does the daemon see frames at all on a channel that `pineapd` is hopping
  across? (Whether a single monitor interface is enough, or whether the
  daemon will need to follow the hop.)
