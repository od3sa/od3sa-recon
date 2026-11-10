# Capture API contract

The contract the capture crate and the daemon's `--dry-run` are written
against. Two files, so the two can be written in parallel.

## The one rule

**The crate cannot transmit.** It declares only the libpcap functions that
*read*. `pcap_inject` and `pcap_sendpacket` are never declared, so there is no
call site to review and no way for the code to send a frame. The whole libpcap
surface is:

| Function | Why |
|---|---|
| `pcap_create` | make a handle, without opening anything yet |
| `pcap_set_snaplen` | how many bytes of each frame to keep |
| `pcap_set_promisc` | whether to see frames not addressed to us |
| `pcap_set_immediate_mode` | deliver packets as they arrive, not in a batch |
| `pcap_set_timeout` | how long a read may block |
| `pcap_activate` | start the capture |
| `pcap_next_ex` | read the next packet |
| `pcap_datalink` | what kind of link layer the interface has |
| `pcap_geterr` | the last error message |
| `pcap_close` | stop and release |
| `pcap_free_datalink` | release the datalink name |

**Nothing here sets a channel, a mode, or the up/down state of an interface.**
libpcap has no such API — that is `iw`'s job, and the daemon never calls `iw`.
The interface is expected to already be in monitor mode, which `pineapd` sets
up.

**Opening a capture changes nothing about the interface.** On Linux, libpcap
implements promiscuous mode as a *per-socket* membership — a
`PACKET_ADD_MEMBERSHIP` with `PACKET_MR_PROMISC` on the packet socket — and
not by setting `IFF_PROMISC` on the interface. The `SIOCSIFFLAGS` path in
libpcap is the one where libpcap creates a monitor interface of its own
through nl80211, which we never do: we open an interface that already exists.
So `wlan1mon` keeps its flags, its channel, its mode and whether it is up.

## `crates/od3sa-capture/src/lib.rs`

```rust
/// How to open an interface.
#[derive(Debug, Clone)]
pub struct CaptureOptions {
    /// How many bytes of each frame to keep. Headers only: 256 is plenty.
    pub snaplen: u32,
    /// Whether to see frames that are not addressed to this host.
    pub promiscuous: bool,
    /// How long a read may block, in milliseconds. 0 means do not block.
    pub timeout_ms: i32,
    /// Whether packets are delivered as they arrive rather than in a batch.
    pub immediate: bool,
}

impl Default for CaptureOptions {
    // snaplen 256, promiscuous true, timeout_ms 100, immediate true
}

impl CaptureOptions {
    /// Options for a passive metadata collector: headers only.
    pub fn metadata() -> CaptureOptions;
}

/// One captured packet.
#[derive(Debug, Clone, Copy)]
pub struct Packet<'a> {
    /// Seconds since the epoch.
    pub ts_sec: i64,
    /// Microseconds within the second.
    pub ts_usec: i64,
    /// The captured bytes: at most `snaplen` of them.
    pub data: &'a [u8],
}

/// What kind of link layer an interface has.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataLink {
    /// Ethernet. Not what we expect on a monitor interface.
    Ethernet,
    /// 802.11, with no radiotap header.
    Ieee80211,
    /// 802.11 with a radiotap header: what a monitor interface gives.
    Ieee80211RadioTap,
    /// Something else.
    Other(i32),
}

/// Why a capture failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CaptureError {
    /// The interface could not be opened.
    Open(String),
    /// A read failed.
    Read(String),
    /// The interface is not a monitor interface.
    NotMonitor(DataLink),
}

/// A capture in progress.
pub struct Capture { /* the libpcap handle */ }

impl Capture {
    /// Open an interface for reading.
    pub fn open(iface: &str, options: &CaptureOptions) -> Result<Capture, CaptureError>;

    /// The next packet, or `None` if the read timed out with nothing to read.
    pub fn next_packet(&mut self) -> Result<Option<Packet<'_>>, CaptureError>;

    /// What kind of link layer the interface has.
    pub fn datalink(&self) -> DataLink;
}

impl Drop for Capture {
    fn drop(&mut self);
}
```

Notes:
- `unsafe` lives in one private module that holds the `extern "C"` block and
  the raw handle. The rest of the crate is safe code, and the crate's `#!`
  attributes forbid `unsafe` outside that module.
- The handle is `*mut pcap_t`, which is opaque to Rust. It is never null
  after a successful `open`.
- `pcap_next_ex` returns 1 for a packet, 0 for a timeout and a negative value
  for an error. A timeout is `Ok(None)`, not an error.
- `Drop` calls `pcap_close`. A capture that goes out of scope stops; nothing
  else stops it.
- `pcap_set_immediate_mode` needs libpcap 1.5 or newer. The device has 1.10.5
  and the cross-built `libpcap.a` is 1.10.5 ✓.

## Linking libpcap (`crates/od3sa-capture/build.rs`)

The crate needs libpcap at link time and nothing else.

- **For the mipsel target** the static, soft-float `libpcap.a` built by
  `build/build-mipsel.sh` is used. The sysroot comes from the environment
  variable `OD3SA_PCAP_SYSROOT`, and defaults to
  `$HOME/toolchains/mipsel-linux-musl-sf`. The build script sets it.
- **For the host** (x86, CI) the system libpcap is used, found with
  `pkg-config --libs --cflags libpcap`. Ubuntu's runners have `libpcap-dev`.
- If neither is found, the build script prints a warning and links nothing.
  The crate still compiles: the `extern "C"` declarations do not need the
  library until something calls them.

## The daemon's `--dry-run` (`crates/od3sa-recond`)

```
od3sa-recond --dry-run --interface wlan1mon [--seconds N] [--snaplen N]
             [--promisc true|false] [--timeout-ms N] [--no-immediate]
```

- `--dry-run` counts frames and prints statistics. It opens the interface for
  reading and nothing else.
- The counting logic must not depend on libpcap, so that it can be tested on
  x86 with synthetic frames. It takes bytes and updates counters; the capture
  is only the source of those bytes.
- The counters are:
  - frames by class: management, control, data, other,
  - frames by management subtype (beacon, probe request, probe response,
    association, authentication, deauthentication, disassociation, other),
  - frames by channel, taken from the radiotap header,
  - the strongest signal seen per channel,
  - total bytes and the mean frame size,
  - EAPOL frames counted separately, and never stored.
- The summary is printed every second and once more at the end, so a
  ten-minute run shows a live trace and a total.
- `--dry-run` on an interface that is not a monitor interface is an error,
  not a warning: `CaptureError::NotMonitor`.
- The daemon prints its version and the passive notice as it does today.

## What a review must confirm

- `pcap_inject` and `pcap_sendpacket` appear nowhere in the tree.
- No `iw`, `wpa_cli`, `ifconfig` or `ip` call, and nothing that changes a
  channel, a mode or the up/down state of an interface.
- No frame payload is stored: the counters keep counts, MAC addresses and
  signal levels, and the EAPOL count is a counter.
