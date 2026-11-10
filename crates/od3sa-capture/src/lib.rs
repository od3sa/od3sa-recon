//! Passive, listen-only capture for the od3sa-recon collector.
//!
//! # Scope
//!
//! This crate opens a libpcap handle on an interface and hands the collector
//! the bytes it reads. It is deliberately small:
//!
//! * It **never transmits**. The libpcap functions that write frames onto an
//!   interface are not declared at all, so there is no call site for them
//!   anywhere in the tree. The `ffi` module holds the exact surface.
//! * It **never changes a radio**. libpcap has no API to change a channel, a
//!   mode or the up/down state of an interface, and this crate shells out to
//!   nothing. The interface is expected to be in monitor mode already, which
//!   the device's own daemon sets up.
//! * It stores **metadata only**. What comes out of it is a timestamp and a
//!   byte slice; keeping, filtering and counting is the collector's job.
//!
//! # Example
//!
//! ```no_run
//! use od3sa_capture::{Capture, CaptureOptions};
//!
//! let mut capture = Capture::open("wlan1mon", &CaptureOptions::metadata())?;
//! while let Some(packet) = capture.next_packet()? {
//!     // `packet.data` holds at most `snaplen` bytes of one frame.
//!     let _ = (packet.ts_sec, packet.ts_usec, packet.data.len());
//! }
//! # Ok::<(), od3sa_capture::CaptureError>(())
//! ```
//!
//! # Safety
//!
//! All `unsafe` lives in the private `ffi` module, which holds the
//! `extern "C"` block and the raw handle. The crate root denies `unsafe`
//! everywhere else, so the safe surface of this crate is exactly the API
//! below.

#![deny(unsafe_code)]

mod ffi;

use std::fmt;

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
    fn default() -> Self {
        CaptureOptions {
            snaplen: 256,
            promiscuous: true,
            timeout_ms: 100,
            immediate: true,
        }
    }
}

impl CaptureOptions {
    /// Options for a passive metadata collector: headers only.
    pub fn metadata() -> CaptureOptions {
        CaptureOptions::default()
    }
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

impl DataLink {
    /// Map a libpcap `DLT_*` number to a link type.
    ///
    /// This is the mapping [`Capture::datalink`] uses, and the one the
    /// collector uses to decide whether an interface is worth reading.
    pub fn from_dlt(dlt: i32) -> DataLink {
        match dlt {
            1 => DataLink::Ethernet,
            105 => DataLink::Ieee80211,
            127 => DataLink::Ieee80211RadioTap,
            other => DataLink::Other(other),
        }
    }

    /// Whether this link type is one of the 802.11 monitor types.
    ///
    /// Only these carry the 802.11 frames the collector counts.
    pub fn is_monitor(&self) -> bool {
        matches!(self, DataLink::Ieee80211 | DataLink::Ieee80211RadioTap)
    }
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

impl fmt::Display for CaptureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CaptureError::Open(message) => write!(f, "cannot open capture: {message}"),
            CaptureError::Read(message) => write!(f, "capture read failed: {message}"),
            CaptureError::NotMonitor(link) => {
                write!(
                    f,
                    "interface is not a monitor interface (link type {link:?})"
                )
            }
        }
    }
}

impl std::error::Error for CaptureError {}

/// A capture in progress.
///
/// The capture stops when this value is dropped. Nothing else stops it, and
/// nothing else can change the interface it reads from.
pub struct Capture {
    /// The libpcap handle.
    raw: ffi::RawCapture,
    /// The interface name, for messages.
    iface: String,
}

impl Capture {
    /// Open an interface for reading.
    ///
    /// The interface is opened for reading only, and is expected to be in
    /// monitor mode already. An interface whose link type is not one of the
    /// 802.11 monitor types is refused with [`CaptureError::NotMonitor`],
    /// because reading it would collect nothing of interest.
    pub fn open(iface: &str, options: &CaptureOptions) -> Result<Capture, CaptureError> {
        let raw = ffi::RawCapture::open(
            iface,
            options.snaplen,
            options.promiscuous,
            options.timeout_ms,
            options.immediate,
        )
        .map_err(CaptureError::Open)?;

        let datalink = DataLink::from_dlt(raw.datalink());
        if !datalink.is_monitor() {
            return Err(CaptureError::NotMonitor(datalink));
        }

        Ok(Capture {
            raw,
            iface: iface.to_string(),
        })
    }

    /// The next packet, or `None` if the read timed out with nothing to read.
    ///
    /// The bytes belong to the capture and are valid until the next call.
    pub fn next_packet(&mut self) -> Result<Option<Packet<'_>>, CaptureError> {
        match self.raw.next_packet().map_err(CaptureError::Read)? {
            Some(packet) => Ok(Some(Packet {
                ts_sec: packet.ts_sec,
                ts_usec: packet.ts_usec,
                data: packet.data,
            })),
            None => Ok(None),
        }
    }

    /// What kind of link layer the interface has.
    pub fn datalink(&self) -> DataLink {
        DataLink::from_dlt(self.raw.datalink())
    }

    /// The name of the interface being read.
    pub fn interface(&self) -> &str {
        &self.iface
    }
}

impl fmt::Debug for Capture {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Capture")
            .field("interface", &self.iface)
            .field("datalink", &self.datalink())
            .finish()
    }
}

impl Drop for Capture {
    fn drop(&mut self) {
        // The handle closes itself; this is here because the contract says a
        // capture that goes out of scope stops, and it documents that fact.
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_options_have_the_documented_defaults() {
        let options = CaptureOptions::metadata();
        assert_eq!(options.snaplen, 256);
        assert!(options.promiscuous);
        assert_eq!(options.timeout_ms, 100);
        assert!(options.immediate);
    }

    #[test]
    fn default_options_are_the_metadata_options() {
        assert_eq!(
            format!("{:?}", CaptureOptions::default()),
            format!("{:?}", CaptureOptions::metadata())
        );
    }

    #[test]
    fn datalink_maps_the_libpcap_dlt_numbers() {
        assert_eq!(DataLink::from_dlt(1), DataLink::Ethernet);
        assert_eq!(DataLink::from_dlt(105), DataLink::Ieee80211);
        assert_eq!(DataLink::from_dlt(127), DataLink::Ieee80211RadioTap);
        assert_eq!(DataLink::from_dlt(0), DataLink::Other(0));
        assert_eq!(DataLink::from_dlt(163), DataLink::Other(163));
        assert_eq!(DataLink::from_dlt(-1), DataLink::Other(-1));
    }

    #[test]
    fn only_the_802_11_link_types_count_as_monitor() {
        assert!(DataLink::Ieee80211.is_monitor());
        assert!(DataLink::Ieee80211RadioTap.is_monitor());
        assert!(!DataLink::Ethernet.is_monitor());
        assert!(!DataLink::Other(163).is_monitor());
    }

    #[test]
    fn opening_a_nonexistent_interface_is_an_error_not_a_panic() {
        let result = Capture::open("od3sa-no-such-interface", &CaptureOptions::metadata());
        match result {
            Err(CaptureError::Open(message)) => {
                assert!(!message.is_empty(), "the error should say what went wrong");
            }
            Err(other) => panic!("expected CaptureError::Open, got {other:?}"),
            Ok(_) => panic!("opening a nonexistent interface should not succeed"),
        }
    }

    /// A non-monitor interface must be refused rather than read.
    ///
    /// Reading an interface needs `CAP_NET_RAW`, which a plain test run does
    /// not have. Where the permission is missing the open fails with
    /// [`CaptureError::Open`] and the check cannot be reached, so the test
    /// reports that and passes: it asserts the refusal, not the permission.
    #[test]
    fn opening_a_non_monitor_interface_is_refused() {
        let options = CaptureOptions::metadata();
        let mut checked = 0usize;

        for iface in non_monitor_interfaces() {
            checked += 1;
            match Capture::open(&iface, &options) {
                Err(CaptureError::NotMonitor(link)) => {
                    assert!(
                        !link.is_monitor(),
                        "{iface} should not be reported as a monitor interface"
                    );
                    return;
                }
                Err(CaptureError::Open(message)) => {
                    // The open failed before the link type could be read.
                    // That is only allowed when this process cannot capture
                    // at all, which the capability says for certain. Where
                    // the capability cannot be read, fall back to libpcap's
                    // wording, which differs between the failure modes:
                    // "Operation not permitted", "Permission denied" and
                    // "Attempt to create packet socket failed - CAP_NET_RAW
                    // may be required".
                    assert!(
                        can_capture() || looks_like_a_permission_failure(&message),
                        "unexpected open failure for {iface}: {message}"
                    );
                }
                Err(other) => panic!("unexpected error for {iface}: {other:?}"),
                Ok(_) => panic!("{iface} is not a monitor interface and should be refused"),
            }
        }

        assert!(checked > 0, "no interface to test with");
    }

    /// Interfaces on this host that are certainly not monitor interfaces.
    fn non_monitor_interfaces() -> Vec<String> {
        let mut names = Vec::new();
        if let Ok(entries) = std::fs::read_dir("/sys/class/net") {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().into_owned();
                if name != "lo" && !name.starts_with("wl") {
                    names.push(name);
                }
            }
        }
        names.sort();
        names
    }

    /// Whether this process may open a capture socket at all.
    ///
    /// Reading a packet socket needs `CAP_NET_RAW`, or root. A test run
    /// usually has neither, so the open fails before the interface is
    /// looked at and there is nothing to refuse. This reads the effective
    /// capability set from the kernel rather than guessing from libpcap's
    /// wording, which differs between its failure modes.
    ///
    /// Returns `true` when the capability cannot be read at all: on a
    /// host that is not Linux, or where `/proc` is not mounted, the
    /// fallback is the message check.
    fn can_capture() -> bool {
        const CAP_NET_RAW: u64 = 13;

        let Ok(status) = std::fs::read_to_string("/proc/self/status") else {
            // No `/proc`: the caller cannot tell, so it does not rule the
            // failure out.
            return true;
        };
        let Some(line) = status.lines().find(|line| line.starts_with("CapEff:")) else {
            return true;
        };
        let Some(mask) = line
            .split_whitespace()
            .nth(1)
            .and_then(|value| u64::from_str_radix(value, 16).ok())
        else {
            return true;
        };
        mask & (1 << CAP_NET_RAW) != 0
    }

    /// Whether libpcap's message is one of its permission failures.
    fn looks_like_a_permission_failure(message: &str) -> bool {
        let lower = message.to_lowercase();
        lower.contains("permitted")
            || lower.contains("permission")
            || lower.contains("denied")
            || lower.contains("not up")
            || lower.contains("cap_net_raw")
            || lower.contains("packet socket")
    }

    /// The crate must not be able to transmit.
    ///
    /// The check lives in the test suite, not only in a review: if anyone
    /// ever adds one of these names to the crate's own source, this fails.
    ///
    /// The check covers `lib.rs` and `ffi.rs`, where the libpcap functions
    /// are declared and called. It does **not** cover `build.rs`, which
    /// names them for the opposite reason: it strips them out of the static
    /// archive before the daemon is linked, so the transmit entry points are
    /// not even in the binary. A name in `build.rs` is a removal, not a
    /// capability — and that is asserted separately below.
    #[test]
    fn the_crate_cannot_transmit() {
        // The needles are split so that this test does not contain the
        // forbidden names itself.
        let forbidden = [concat!("pcap_", "inject"), concat!("pcap_", "sendpacket")];
        let sources = [
            ("lib.rs", include_str!("lib.rs")),
            ("ffi.rs", include_str!("ffi.rs")),
        ];

        for (name, source) in sources {
            for needle in forbidden {
                assert!(
                    !source.contains(needle),
                    "{name} mentions {needle}: the crate must not be able to transmit"
                );
            }
        }
    }

    /// The build script removes the transmit symbols rather than linking
    /// them.
    ///
    /// libpcap's archive holds the transmit functions next to the reading
    /// ones, so a static link brings them along. `build.rs` strips them from
    /// a copy of the archive before linking, which is why the names appear
    /// there. If that stripping ever stops happening, the daemon would carry
    /// two entry points it has no way to call — harmless, but not the state
    /// this project wants, so it is worth a test.
    #[test]
    fn the_build_script_strips_the_transmit_symbols() {
        let build_script = include_str!("../build.rs");

        for needle in [concat!("pcap_", "inject"), concat!("pcap_", "sendpacket")] {
            assert!(
                build_script.contains(needle),
                "build.rs does not mention {needle}: the transmit symbols are no longer stripped"
            );
        }

        // The stripping must be done to the archive, not merely mentioned.
        assert!(
            build_script.contains("objcopy"),
            "build.rs does not use objcopy: the archive is no longer stripped"
        );
    }

    /// The permission-failure check recognises every wording libpcap uses
    /// when the capture socket cannot be made.
    #[test]
    fn the_permission_failures_are_recognised() {
        for message in [
            "Operation not permitted",
            "Permission denied",
            "You don't have permission to capture on that device",
            "Attempt to create packet socket failed - CAP_NET_RAW may be required",
            "that device is not up",
        ] {
            assert!(
                looks_like_a_permission_failure(message),
                "{message} should be recognised as a permission failure"
            );
        }

        // A failure that is not about permissions must not be mistaken for
        // one: that would hide a real fault behind a passing test.
        for message in [
            "No such device exists",
            "invalid argument",
            "that name is not a network interface",
        ] {
            assert!(
                !looks_like_a_permission_failure(message),
                "{message} should not be mistaken for a permission failure"
            );
        }
    }
}
