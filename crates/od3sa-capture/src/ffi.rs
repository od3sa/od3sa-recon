//! The libpcap boundary: the only place in this crate that may use `unsafe`.
//!
//! This module declares exactly the *reading* subset of libpcap's API. The
//! transmit-side entry points of libpcap are deliberately not declared, so
//! there is no call site for them anywhere in the tree and no way for this
//! crate to put a frame on the air.
//!
//! Nothing here changes a channel, a mode, or the up/down state of an
//! interface: libpcap has no such API, and this crate shells out to nothing.
//! The interface is expected to already be in monitor mode, which the device's
//! own daemon sets up.
//!
//! # Safety
//!
//! Every `unsafe` block below is a thin, audited call into libpcap. The
//! reasons are given in a comment next to each one.

#![allow(unsafe_code)]

use std::ffi::{CStr, CString, c_char, c_int};
use std::ptr::NonNull;

/// The size of libpcap's error buffer (`PCAP_ERRBUF_SIZE`).
const ERRBUF_SIZE: usize = 256;

/// libpcap's opaque capture handle (`pcap_t`).
#[repr(C)]
pub struct PcapT {
    _opaque: [u8; 0],
}

/// `struct timeval` as libpcap uses it in a packet header.
///
/// libpcap stores the capture timestamp as a `struct timeval`. On the targets
/// this crate builds for (x86_64 glibc and 32-bit mipsel musl) `time_t` and
/// `suseconds_t` are both 64 bits wide, so the struct is two `i64`s. The
/// compile-time checks below make a layout change a build failure rather than
/// a silent misreading of the timestamp.
#[repr(C)]
pub struct TimeVal {
    /// Whole seconds since the epoch.
    pub tv_sec: i64,
    /// Microseconds within the second.
    pub tv_usec: i64,
}

/// `struct pcap_pkthdr`: libpcap's per-packet header.
#[repr(C)]
pub struct PcapPkthdr {
    /// When the packet was captured.
    pub ts: TimeVal,
    /// How many bytes of the packet were captured.
    pub caplen: u32,
    /// How long the packet was on the wire.
    pub len: u32,
}

const _: () = {
    assert!(std::mem::size_of::<TimeVal>() == 16);
    assert!(std::mem::align_of::<TimeVal>() == 8);
    assert!(std::mem::size_of::<PcapPkthdr>() == 24);
    assert!(std::mem::align_of::<PcapPkthdr>() == 8);
};

// The reading subset of libpcap.
//
// Nothing in this block can transmit: the functions that write frames onto an
// interface are not declared.
//
// The contract also lists `pcap_free_datalink`, "release the datalink name".
// libpcap 1.10.5 has no such symbol (it exports `pcap_free_datalinks`, for
// the array `pcap_datalink_ext` returns, and `pcap_datalink_val_to_name`,
// which returns a static string). This crate maps the link-layer *number* to
// a `DataLink` and never allocates a datalink name, so there is nothing to
// free and the symbol is not declared.
unsafe extern "C" {
    /// Make a handle for an interface, without capturing anything yet.
    fn pcap_create(device: *const c_char, errbuf: *mut c_char) -> *mut PcapT;

    /// How many bytes of each frame to keep.
    fn pcap_set_snaplen(p: *mut PcapT, snaplen: c_int) -> c_int;

    /// Whether to see frames that are not addressed to this host.
    fn pcap_set_promisc(p: *mut PcapT, promisc: c_int) -> c_int;

    /// Deliver packets as they arrive rather than in a batch.
    fn pcap_set_immediate_mode(p: *mut PcapT, immediate: c_int) -> c_int;

    /// How long a read may block, in milliseconds.
    fn pcap_set_timeout(p: *mut PcapT, timeout_ms: c_int) -> c_int;

    /// Start the capture.
    fn pcap_activate(p: *mut PcapT) -> c_int;

    /// Read the next packet.
    fn pcap_next_ex(
        p: *mut PcapT,
        pkt_header: *mut *mut PcapPkthdr,
        pkt_data: *mut *const u8,
    ) -> c_int;

    /// The link-layer type of the interface.
    fn pcap_datalink(p: *mut PcapT) -> c_int;

    /// The last error message of a handle.
    fn pcap_geterr(p: *mut PcapT) -> *mut c_char;

    /// Stop the capture and release the handle.
    fn pcap_close(p: *mut PcapT);
}

/// A packet as libpcap reports it, borrowed from the capture handle.
pub(crate) struct RawPacket<'a> {
    /// Seconds since the epoch.
    pub ts_sec: i64,
    /// Microseconds within the second.
    pub ts_usec: i64,
    /// The captured bytes.
    pub data: &'a [u8],
}

/// A live libpcap capture handle.
///
/// The handle is closed when the value is dropped, so a capture that goes out
/// of scope stops. Nothing else stops it.
pub(crate) struct RawCapture {
    /// The libpcap handle. `None` once the capture has been closed.
    handle: Option<NonNull<PcapT>>,
}

impl RawCapture {
    /// Open an interface for reading.
    ///
    /// The interface must already be in monitor mode; this only ever reads.
    pub(crate) fn open(
        iface: &str,
        snaplen: u32,
        promiscuous: bool,
        timeout_ms: i32,
        immediate: bool,
    ) -> Result<Self, String> {
        let name =
            CString::new(iface).map_err(|_| "interface name contains a NUL byte".to_string())?;
        let mut errbuf = [0 as c_char; ERRBUF_SIZE];

        // SAFETY: `name` is a valid NUL-terminated C string and `errbuf` is a
        // live buffer of the size libpcap documents for `PCAP_ERRBUF_SIZE`.
        let handle = unsafe { pcap_create(name.as_ptr(), errbuf.as_mut_ptr()) };
        let Some(handle) = NonNull::new(handle) else {
            return Err(errbuf_message(&errbuf));
        };
        let capture = RawCapture {
            handle: Some(handle),
        };

        // SAFETY: the handle was just created by libpcap and is still live;
        // each of these setters only records a parameter on it.
        let configured = unsafe {
            pcap_set_snaplen(capture.as_ptr(), snaplen.min(c_int::MAX as u32) as c_int) == 0
                && pcap_set_promisc(capture.as_ptr(), c_int::from(promiscuous)) == 0
                && pcap_set_timeout(capture.as_ptr(), timeout_ms) == 0
                && pcap_set_immediate_mode(capture.as_ptr(), c_int::from(immediate)) == 0
        };
        if !configured {
            return Err(format!(
                "libpcap rejected the capture settings for {iface}: {}",
                capture.last_error()
            ));
        }

        // SAFETY: the handle is live and configured; `pcap_activate` only
        // opens it for reading.
        let activated = unsafe { pcap_activate(capture.as_ptr()) };
        if activated != 0 {
            return Err(format!(
                "cannot open {iface} for reading (pcap_activate: {activated}): {}",
                capture.last_error()
            ));
        }

        Ok(capture)
    }

    /// The link-layer type of the interface, as libpcap's `DLT_*` number.
    pub(crate) fn datalink(&self) -> i32 {
        // SAFETY: the handle is live and activated; `pcap_datalink` only
        // reads a field of it.
        unsafe { pcap_datalink(self.as_ptr()) }
    }

    /// The next packet, or `None` if the read timed out with nothing to read.
    pub(crate) fn next_packet(&mut self) -> Result<Option<RawPacket<'_>>, String> {
        let mut header: *mut PcapPkthdr = std::ptr::null_mut();
        let mut data: *const u8 = std::ptr::null();

        // SAFETY: the handle is live and activated; `pcap_next_ex` fills in
        // the two out-parameters when it returns 1.
        let rc = unsafe { pcap_next_ex(self.as_ptr(), &mut header, &mut data) };
        match rc {
            1 => {
                if header.is_null() {
                    return Err("libpcap returned a packet with no header".to_string());
                }
                // SAFETY: libpcap returned 1, so both out-parameters are valid:
                // `header` points at a `pcap_pkthdr` owned by the handle.
                let header = unsafe { &*header };
                let len = header.caplen as usize;
                // SAFETY: `data` points at `caplen` readable bytes that
                // libpcap owns and keeps valid until the next read on this
                // handle. The returned slice borrows the handle, so no other
                // read (or close) can happen while it is alive.
                let bytes = if len == 0 {
                    &[][..]
                } else {
                    unsafe { std::slice::from_raw_parts(data, len) }
                };
                Ok(Some(RawPacket {
                    ts_sec: header.ts.tv_sec,
                    ts_usec: header.ts.tv_usec,
                    data: bytes,
                }))
            }
            0 => Ok(None),
            _ => Err(self.last_error()),
        }
    }

    /// Stop the capture and release the handle.
    pub(crate) fn close(&mut self) {
        if let Some(handle) = self.handle.take() {
            // SAFETY: the handle was created by libpcap and is not closed yet;
            // `pcap_close` releases it and the pointer is not used again.
            unsafe { pcap_close(handle.as_ptr()) };
        }
    }

    /// The libpcap error message of the handle.
    fn last_error(&self) -> String {
        // SAFETY: the handle is live; `pcap_geterr` returns a NUL-terminated
        // string owned by libpcap, which we copy immediately.
        let message = unsafe { pcap_geterr(self.as_ptr()) };
        if message.is_null() {
            return "unknown libpcap error".to_string();
        }
        // SAFETY: `message` is a non-null NUL-terminated string.
        unsafe { CStr::from_ptr(message) }
            .to_string_lossy()
            .into_owned()
    }

    /// The raw handle, for the calls into libpcap.
    fn as_ptr(&self) -> *mut PcapT {
        match self.handle {
            // SAFETY: the handle was created by libpcap and is still live:
            // it is only taken in `close`, which no other method can race
            // with, because every method takes `&self` or `&mut self`.
            Some(handle) => handle.as_ptr(),
            // SAFETY: a closed handle is never used again; `close` is the only
            // place that clears it, and it takes `&mut self`.
            None => std::ptr::null_mut(),
        }
    }
}

impl Drop for RawCapture {
    fn drop(&mut self) {
        self.close();
    }
}

/// The message libpcap left in an error buffer.
fn errbuf_message(errbuf: &[c_char]) -> String {
    // SAFETY: libpcap writes a NUL-terminated string into the error buffer.
    unsafe { CStr::from_ptr(errbuf.as_ptr()) }
        .to_string_lossy()
        .into_owned()
}
