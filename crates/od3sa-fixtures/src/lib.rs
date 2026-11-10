//! Synthetic 802.11 fixture generation for `od3sa-recon`.
//!
//! The parser tests need frames to work on, and the project guardrail says
//! that **no real capture is ever committed**. This crate therefore builds
//! every frame from scratch, byte by byte, out of obviously fake values:
//! MAC addresses from the `00:11:22:33:44:xx` family and SSIDs that start
//! with `example-`.
//!
//! Nothing here touches a radio, a capture handle or the network. The crate
//! only writes and reads *files*; a pcap file it produces contains frames it
//! invented itself.
//!
//! # What is in the box
//!
//! * [`radiotap`] builds the pseudo-header that monitor-mode drivers prepend
//!   to every captured frame.
//! * [`beacon`], [`probe_request`], [`data_frame`] and [`eapol_frame`] build
//!   802.11 frames with a radiotap header in front of them.
//! * [`write_pcap`] writes those frames into a classic libpcap file, and
//!   [`read_pcap`] reads the file back.
//! * [`standard_fixtures`] returns the named set of fixtures that the binary
//!   and the tests use.
//!
//! # Example
//!
//! ```
//! use od3sa_fixtures::{beacon, mac, write_pcap};
//!
//! let frame = beacon(mac(1), "example-ssid", 2412, -42, true);
//! assert!(!frame.is_empty());
//! # let dir = std::env::temp_dir().join("od3sa-fixtures-doc-example");
//! # std::fs::create_dir_all(&dir).unwrap();
//! # write_pcap(&dir.join("beacon.pcap"), &[frame]).unwrap();
//! # std::fs::remove_dir_all(&dir).unwrap();
//! ```

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used)]

use std::fs::File;
use std::io::{self, Read, Write};
use std::path::Path;

/// The five bytes every synthetic MAC address starts with.
pub const SYNTHETIC_MAC_PREFIX: [u8; 5] = [0x00, 0x11, 0x22, 0x33, 0x44];

/// The stand-in this crate uses for the 802.11 broadcast address.
///
/// It is deliberately *not* `ff:ff:ff:ff:ff:ff`: every address that appears
/// in a fixture has to be traceable to [`SYNTHETIC_MAC_PREFIX`], so that the
/// "no real data" guardrail can be checked by a test.
pub const BROADCAST_ADDR: [u8; 6] = [0x00, 0x11, 0x22, 0x33, 0x44, 0xff];

/// Every SSID in a fixture starts with this prefix.
pub const SYNTHETIC_SSID_PREFIX: &str = "example-";

/// The `it_present` bitmask of the radiotap headers this crate writes.
///
/// Bit 1 is `Flags`, bit 2 is `Rate`, bit 3 is `Channel` and bit 5 is `DBM`.
pub const RADIOTAP_PRESENT: u32 = (1 << 1) | (1 << 2) | (1 << 3) | (1 << 5);

/// The libpcap file magic number, in the little-endian form used here.
pub const PCAP_MAGIC: u32 = 0xa1b2_c3d4;

/// The major version of the libpcap file format.
pub const PCAP_VERSION_MAJOR: u16 = 2;

/// The minor version of the libpcap file format.
pub const PCAP_VERSION_MINOR: u16 = 4;

/// The snap length written in the pcap global header.
pub const PCAP_SNAPLEN: u32 = 65535;

/// The link type of the pcap files: `DLT_IEEE802_11_RADIOTAP`.
pub const PCAP_NETWORK_RADIOTAP: u32 = 127;

/// The first epoch second of the fixture timestamps: 2023-11-14T22:13:20Z.
///
/// The fixtures must be reproducible, so the timestamps are fixed constants
/// and never the current time.
pub const FIXTURE_EPOCH_SEC: u32 = 1_700_000_000;

/// The step between two fixture frames, in microseconds.
pub const FIXTURE_STEP_USEC: u32 = 100_000;

/// The radiotap `Rate` field of a fixture frame, in units of 500 kbit/s.
///
/// 2 means 1 Mbit/s, the basic rate a beacon is sent at.
const FIXTURE_RATE: u8 = 2;

/// The timestamp put in every fixture beacon: obviously synthetic.
const BEACON_TIMESTAMP: u64 = 0x1122_3344_5566_7788;

/// The beacon interval of a fixture beacon, in time units of 1024 us.
const BEACON_INTERVAL: u16 = 100;

/// The capability info of an open fixture network.
const CAPABILITY_ESS: u16 = 0x0001;

/// The capability info bit that marks a network as protected.
const CAPABILITY_PRIVACY: u16 = 0x0010;

/// The supported rates of a fixture beacon, in units of 500 kbit/s.
///
/// 1, 2, 5.5, 11, 18, 24, 36 and 54 Mbit/s.
const SUPPORTED_RATES: [u8; 8] = [0x8c, 0x12, 0x98, 0x24, 0xb0, 0x48, 0x60, 0x6c];

/// The RSN version a fixture beacon reports.
const RSN_VERSION: u16 = 1;

/// The RSN capabilities a fixture beacon reports.
const RSN_CAPABILITIES: u16 = 0x008c;

/// The AKM suite selector of WPA2-Personal: pre-shared key.
///
/// IEEE 802.11 Table 12-6, as tabulated by the Wi-Fi Alliance WPA3
/// specification v3.5. The selector is `00:0f:ac:2`.
pub const AKM_PSK: [u8; 4] = [0x00, 0x0f, 0xac, 0x02];

/// The AKM suite selector of WPA3-Personal: simultaneous authentication of
/// equals.
///
/// IEEE 802.11 Table 12-6: the selector is `00:0f:ac:8`. It must not be
/// confused with [`AKM_PSK`], which is `00:0f:ac:2`.
pub const AKM_SAE: [u8; 4] = [0x00, 0x0f, 0xac, 0x08];

/// Build the `n`-th synthetic MAC address, `00:11:22:33:44:{n}`.
///
/// Every MAC in a fixture comes from this family, so a reviewer can tell at a
/// glance that a file contains no real hardware.
pub fn mac(n: u8) -> [u8; 6] {
    let mut address = [0u8; 6];
    address[..5].copy_from_slice(&SYNTHETIC_MAC_PREFIX);
    address[5] = n;
    address
}

/// True when the address belongs to the synthetic fixture family.
pub fn is_synthetic_mac(address: &[u8; 6]) -> bool {
    address[..5] == SYNTHETIC_MAC_PREFIX
}

/// True when the SSID is a synthetic one, that is, when it starts with
/// `example-`.
pub fn is_synthetic_ssid(ssid: &str) -> bool {
    ssid.starts_with(SYNTHETIC_SSID_PREFIX)
}

/// Build a radiotap header.
///
/// The header carries the `Flags`, `Rate`, `Channel` and `DBM` fields, in
/// that order, each aligned to its natural alignment. `it_len` covers the
/// whole header, the 8-byte preamble included.
///
/// ```
/// use od3sa_fixtures::radiotap;
///
/// let header = radiotap(-42, 2412, 2);
/// assert_eq!(&header[0..2], &[0, 0]); // it_version, it_pad
/// assert_eq!(u16::from_le_bytes([header[2], header[3]]), header.len() as u16);
/// ```
pub fn radiotap(signal_dbm: i8, freq_mhz: u16, rate: u8) -> Vec<u8> {
    let mut header: Vec<u8> = Vec::with_capacity(16);
    header.push(0); // it_version
    header.push(0); // it_pad
    header.extend_from_slice(&[0, 0]); // it_len, patched below
    header.extend_from_slice(&RADIOTAP_PRESENT.to_le_bytes());

    // The fields follow in bit order, each aligned to its natural alignment
    // relative to the start of the radiotap header.
    header.push(0x00); // bit 1: Flags
    header.push(rate); // bit 2: Rate, in units of 500 kbit/s
    align_to(&mut header, 2); // bit 3: Channel
    header.extend_from_slice(&freq_mhz.to_le_bytes()); // channel frequency
    header.extend_from_slice(&0u16.to_le_bytes()); // channel flags
    header.extend_from_slice(&signal_dbm.to_le_bytes()); // bit 5: DBM

    let length = u16::try_from(header.len()).unwrap_or(u16::MAX);
    header[2..4].copy_from_slice(&length.to_le_bytes());
    header
}

/// Pad the buffer with zero bytes until its length is a multiple of `alignment`.
fn align_to(buffer: &mut Vec<u8>, alignment: usize) {
    while !buffer.len().is_multiple_of(alignment) {
        buffer.push(0);
    }
}

/// Build the frame control word of a frame.
///
/// `frame_type` is the two-bit type field, `subtype` the four-bit subtype
/// field and `flags` the bits from bit 8 up (`ToDS`, `FromDS`, ...).
fn frame_control(frame_type: u8, subtype: u8, flags: u16) -> u16 {
    (u16::from(frame_type & 0x03) << 2) | (u16::from(subtype & 0x0f) << 4) | flags
}

/// The `ToDS` bit of the frame control word.
const FLAG_TO_DS: u16 = 0x0100;

/// The `FromDS` bit of the frame control word.
const FLAG_FROM_DS: u16 = 0x0200;

/// Append an information element with the given id and body.
fn push_ie(frame: &mut Vec<u8>, id: u8, body: &[u8]) {
    frame.push(id);
    let length = u8::try_from(body.len()).unwrap_or(u8::MAX);
    frame.push(length);
    frame.extend_from_slice(body);
}

/// Append an SSID information element.
///
/// The SSID is truncated to the 32 bytes the standard allows.
fn push_ssid_ie(frame: &mut Vec<u8>, ssid: &str) {
    let bytes = ssid.as_bytes();
    let body = &bytes[..bytes.len().min(32)];
    push_ie(frame, 0, body);
}

/// Append the supported rates information element.
fn push_supported_rates_ie(frame: &mut Vec<u8>) {
    push_ie(frame, 1, &SUPPORTED_RATES);
}

/// Append the DS parameter set information element for a channel.
fn push_ds_parameter_ie(frame: &mut Vec<u8>, channel: u8) {
    push_ie(frame, 3, &[channel]);
}

/// Append an RSN information element with the given AKM suites.
///
/// The element holds the group cipher, one pairwise cipher and the AKM
/// suites, in the layout `docs/PARSER-API.md` describes: version (2), group
/// cipher (4), pairwise count (2), pairwise suites (4 each), AKM count (2),
/// AKM suites (4 each) and the RSN capabilities (2).
///
/// The ciphers are CCMP (`00:0f:ac:4`); the AKM suites are the caller's, so
/// a fixture can be a WPA2-Personal network, a WPA3-Personal one or a
/// transition-mode one that offers both.
fn push_rsn_ie(frame: &mut Vec<u8>, akm_suites: &[[u8; 4]]) {
    let mut body: Vec<u8> = Vec::with_capacity(20);
    body.extend_from_slice(&RSN_VERSION.to_le_bytes());
    body.extend_from_slice(&[0x00, 0x0f, 0xac, 0x04]); // group cipher: CCMP
    body.extend_from_slice(&1u16.to_le_bytes()); // pairwise cipher count
    body.extend_from_slice(&[0x00, 0x0f, 0xac, 0x04]); // pairwise cipher: CCMP
    body.extend_from_slice(
        &u16::try_from(akm_suites.len())
            .unwrap_or(u16::MAX)
            .to_le_bytes(),
    );
    for suite in akm_suites {
        body.extend_from_slice(suite);
    }
    body.extend_from_slice(&RSN_CAPABILITIES.to_le_bytes());
    push_ie(frame, 48, &body);
}

/// The 802.11 channel number of a centre frequency.
///
/// The mapping is the one in `docs/PARSER-API.md`: 2412..2484 MHz to channels
/// 1..14, 5000..5900 MHz to `(freq - 5000) / 5` and 5955..7115 MHz to
/// `(freq - 5950) / 5`.
fn channel_number(freq_mhz: u16) -> Option<u16> {
    match freq_mhz {
        2412..=2484 => Some((freq_mhz - 2407) / 5),
        5000..=5900 => Some((freq_mhz - 5000) / 5),
        5955..=7115 => Some((freq_mhz - 5950) / 5),
        _ => None,
    }
}

/// Build a beacon frame, with a radiotap header in front of it.
///
/// The frame is a management beacon (type 0, subtype 8) for the given BSSID
/// and SSID, on the given frequency. When `rsn` is true the frame carries an
/// RSN element for WPA2-Personal (AKM `00:0f:ac:2`) with CCMP, otherwise it
/// is an open network.
///
/// Use [`beacon_with_akm`] for a WPA3-Personal beacon or a transition-mode
/// one.
///
/// ```
/// use od3sa_fixtures::{beacon, mac};
///
/// let frame = beacon(mac(1), "example-ssid", 2412, -42, true);
/// // radiotap header, then the 802.11 frame control word.
/// assert_eq!(u16::from_le_bytes([frame[15], frame[16]]), 0x0080);
/// ```
pub fn beacon(bssid: [u8; 6], ssid: &str, freq_mhz: u16, signal_dbm: i8, rsn: bool) -> Vec<u8> {
    if rsn {
        beacon_with_akm(bssid, ssid, freq_mhz, signal_dbm, &[AKM_PSK])
    } else {
        beacon_with_akm(bssid, ssid, freq_mhz, signal_dbm, &[])
    }
}

/// Build a beacon frame with the given AKM suites.
///
/// This is [`beacon`] with the RSN element's AKM suite list spelled out, so
/// that a fixture can be a WPA2-Personal network ([`AKM_PSK`]), a
/// WPA3-Personal one ([`AKM_SAE`]) or a transition-mode network that offers
/// both.
///
/// An empty list of suites makes an open network, without an RSN element.
pub fn beacon_with_akm(
    bssid: [u8; 6],
    ssid: &str,
    freq_mhz: u16,
    signal_dbm: i8,
    akm_suites: &[[u8; 4]],
) -> Vec<u8> {
    let mut frame = radiotap(signal_dbm, freq_mhz, FIXTURE_RATE);

    frame.extend_from_slice(&frame_control(0, 8, 0).to_le_bytes()); // beacon
    frame.extend_from_slice(&0u16.to_le_bytes()); // duration
    frame.extend_from_slice(&BROADCAST_ADDR); // addr1: the broadcast address
    frame.extend_from_slice(&bssid); // addr2: the transmitter
    frame.extend_from_slice(&bssid); // addr3: the BSSID
    frame.extend_from_slice(&0u16.to_le_bytes()); // sequence control

    frame.extend_from_slice(&BEACON_TIMESTAMP.to_le_bytes()); // timestamp
    frame.extend_from_slice(&BEACON_INTERVAL.to_le_bytes()); // beacon interval
    let capability = CAPABILITY_ESS
        | if akm_suites.is_empty() {
            0
        } else {
            CAPABILITY_PRIVACY
        };
    frame.extend_from_slice(&capability.to_le_bytes()); // capability info

    push_ssid_ie(&mut frame, ssid);
    push_supported_rates_ie(&mut frame);
    push_ds_parameter_ie(&mut frame, channel_number(freq_mhz).unwrap_or(0) as u8);
    if !akm_suites.is_empty() {
        push_rsn_ie(&mut frame, akm_suites);
    }

    frame
}

/// Build a probe request frame, with a radiotap header in front of it.
///
/// The frame is a management probe request (type 0, subtype 4) sent by `src`
/// and asking for the given SSID.
///
/// ```
/// use od3sa_fixtures::{mac, probe_request};
///
/// let frame = probe_request(mac(11), "example-ssid", -48, 2412);
/// // radiotap header, then the 802.11 frame control word.
/// assert_eq!(u16::from_le_bytes([frame[15], frame[16]]), 0x0040);
/// ```
pub fn probe_request(src: [u8; 6], ssid: &str, signal_dbm: i8, freq_mhz: u16) -> Vec<u8> {
    let mut frame = radiotap(signal_dbm, freq_mhz, FIXTURE_RATE);

    frame.extend_from_slice(&frame_control(0, 4, 0).to_le_bytes()); // probe request
    frame.extend_from_slice(&0u16.to_le_bytes()); // duration
    frame.extend_from_slice(&BROADCAST_ADDR); // addr1: the broadcast address
    frame.extend_from_slice(&src); // addr2: the transmitter
    frame.extend_from_slice(&BROADCAST_ADDR); // addr3: the broadcast address
    frame.extend_from_slice(&0u16.to_le_bytes()); // sequence control

    push_ssid_ie(&mut frame, ssid);

    frame
}

/// Build a data frame, with a radiotap header in front of it.
///
/// The frame is a plain data frame (type 2, subtype 0). The addresses are
/// placed according to IEEE 802.11-2020 Table 9-30, the same table the Linux
/// kernel documents in `include/linux/ieee80211.h`:
///
/// | ToDS | FromDS | addr1 | addr2 | addr3 | addr4 |
/// |---|---|---|---|---|---|
/// | 0 | 0 | destination | source | BSSID | absent |
/// | 0 | 1 | destination | BSSID | source | absent |
/// | 1 | 0 | BSSID | source | destination | absent |
/// | 1 | 1 | destination | BSSID | destination | source |
///
/// The four-address form, the one with both DS bits set, has a 30-byte MAC
/// header; the other three have 24. There is no address-4 bit in the frame
/// control word: the fourth address exists exactly when the frame is a data
/// frame with both DS bits set.
///
/// The body is copied verbatim. A caller that wants an EAPOL frame passes an
/// LLC/SNAP header with EtherType `0x888E` as the body; see
/// [`eapol_frame`].
///
/// ```
/// use od3sa_fixtures::{data_frame, mac};
///
/// let frame = data_frame(mac(21), mac(31), mac(1), true, false, &[0x01, 0x02]);
/// assert!(frame.len() > 24);
/// ```
pub fn data_frame(
    src: [u8; 6],
    dst: [u8; 6],
    bssid: [u8; 6],
    to_ds: bool,
    from_ds: bool,
    body: &[u8],
) -> Vec<u8> {
    let mut flags = 0u16;
    if to_ds {
        flags |= FLAG_TO_DS;
    }
    if from_ds {
        flags |= FLAG_FROM_DS;
    }

    let mut frame = radiotap(-45, 2412, FIXTURE_RATE);
    frame.extend_from_slice(&frame_control(2, 0, flags).to_le_bytes()); // data
    frame.extend_from_slice(&0u16.to_le_bytes()); // duration

    match (to_ds, from_ds) {
        (false, false) => {
            frame.extend_from_slice(&dst);
            frame.extend_from_slice(&src);
            frame.extend_from_slice(&bssid);
        }
        (true, false) => {
            frame.extend_from_slice(&bssid);
            frame.extend_from_slice(&src);
            frame.extend_from_slice(&dst);
        }
        (false, true) => {
            frame.extend_from_slice(&dst);
            frame.extend_from_slice(&bssid);
            frame.extend_from_slice(&src);
        }
        (true, true) => {
            // The four-address form: the MAC header grows to 30 bytes.
            frame.extend_from_slice(&dst); // addr1: the receiver
            frame.extend_from_slice(&bssid); // addr2: the transmitter
            frame.extend_from_slice(&dst); // addr3: the destination
        }
    }

    // The sequence control field sits after address 3, and address 4, when
    // it is there, comes after the sequence control field.
    frame.extend_from_slice(&0u16.to_le_bytes()); // sequence control
    if to_ds && from_ds {
        frame.extend_from_slice(&src); // addr4: the source address
    }

    frame.extend_from_slice(body);

    frame
}

/// Build a deauthentication frame, with a radiotap header in front of it.
///
/// The frame is sent by `src`, normally the access point, to `dst`, the
/// station being deauthenticated, and carries a reason code.
pub fn deauth_frame(src: [u8; 6], dst: [u8; 6], reason: u16) -> Vec<u8> {
    let mut frame = radiotap(-45, 2412, FIXTURE_RATE);
    frame.extend_from_slice(&frame_control(0, 12, 0).to_le_bytes()); // management, deauthentication
    frame.extend_from_slice(&0u16.to_le_bytes()); // duration
    frame.extend_from_slice(&dst); // addr1: the station being deauthenticated
    frame.extend_from_slice(&src); // addr2: the sender
    frame.extend_from_slice(&dst); // addr3: the bssid of the sender
    frame.extend_from_slice(&0u16.to_le_bytes()); // sequence control
    frame.extend_from_slice(&reason.to_le_bytes()); // the reason code

    frame
}

/// The LLC/SNAP header of an EAPOL frame, with EtherType `0x888E`.
pub const LLC_SNAP_EAPOL: [u8; 8] = [0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8e];

/// Build an EAPOL frame, with a radiotap header in front of it.
///
/// The frame is a data frame from `src` to `dst` inside the BSS `bssid`,
/// whose body is the LLC/SNAP header of an EAPOL frame followed by a few
/// EAPOL-looking bytes. The payload is invented: it carries no key material
/// of any kind.
pub fn eapol_frame(src: [u8; 6], dst: [u8; 6], bssid: [u8; 6]) -> Vec<u8> {
    let mut body = LLC_SNAP_EAPOL.to_vec();
    body.extend_from_slice(&[0x01, 0x00, 0x00, 0x04]); // EAPOL version, type, length
    body.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // a placeholder payload
    data_frame(src, dst, bssid, true, false, &body)
}

/// The 24-byte global header of a libpcap file.
pub fn pcap_global_header() -> [u8; 24] {
    let mut header = [0u8; 24];
    header[0..4].copy_from_slice(&PCAP_MAGIC.to_le_bytes());
    header[4..6].copy_from_slice(&PCAP_VERSION_MAJOR.to_le_bytes());
    header[6..8].copy_from_slice(&PCAP_VERSION_MINOR.to_le_bytes());
    header[8..12].copy_from_slice(&0i32.to_le_bytes()); // thiszone
    header[12..16].copy_from_slice(&0u32.to_le_bytes()); // sigfigs
    header[16..20].copy_from_slice(&PCAP_SNAPLEN.to_le_bytes());
    header[20..24].copy_from_slice(&PCAP_NETWORK_RADIOTAP.to_le_bytes());
    header
}

/// The timestamp of the `index`-th frame of a fixture file.
///
/// The timestamps are fixed constants, so that two runs of the generator
/// produce byte-identical files.
fn fixture_timestamp(index: usize) -> (u32, u32) {
    let offset_usec = u64::from(FIXTURE_STEP_USEC) * index as u64;
    let seconds = FIXTURE_EPOCH_SEC + (offset_usec / 1_000_000) as u32;
    let usec = (offset_usec % 1_000_000) as u32;
    (seconds, usec)
}

/// Write the frames into a classic libpcap file.
///
/// The file has a 24-byte global header (magic `0xa1b2c3d4`, version 2.4,
/// thiszone 0, sigfigs 0, snaplen 65535 and link type 127, which is
/// `DLT_IEEE802_11_RADIOTAP`) and, for every frame, a 16-byte record header
/// followed by the frame bytes.
///
/// The timestamps are deterministic: they start at [`FIXTURE_EPOCH_SEC`] and
/// step by [`FIXTURE_STEP_USEC`]. The current time is never used.
///
/// ```
/// use od3sa_fixtures::{beacon, mac, read_pcap, write_pcap};
///
/// let dir = std::env::temp_dir().join("od3sa-fixtures-doc-round-trip");
/// std::fs::create_dir_all(&dir).unwrap();
/// let path = dir.join("beacon.pcap");
/// let frame = beacon(mac(1), "example-ssid", 2412, -42, true);
/// write_pcap(&path, std::slice::from_ref(&frame)).unwrap();
/// assert_eq!(read_pcap(&path).unwrap(), vec![frame]);
/// std::fs::remove_dir_all(&dir).unwrap();
/// ```
pub fn write_pcap(path: &Path, frames: &[Vec<u8>]) -> io::Result<()> {
    let mut file = File::create(path)?;
    file.write_all(&pcap_global_header())?;
    for (index, frame) in frames.iter().enumerate() {
        let (seconds, usec) = fixture_timestamp(index);
        let length = u32::try_from(frame.len()).unwrap_or(u32::MAX);
        let mut record = Vec::with_capacity(16 + frame.len());
        record.extend_from_slice(&seconds.to_le_bytes());
        record.extend_from_slice(&usec.to_le_bytes());
        record.extend_from_slice(&length.to_le_bytes()); // incl_len
        record.extend_from_slice(&length.to_le_bytes()); // orig_len
        record.extend_from_slice(frame);
        file.write_all(&record)?;
    }
    file.flush()
}

/// Read the frames of a classic libpcap file.
///
/// This is the inverse of [`write_pcap`]; it reads the files this crate
/// writes.
pub fn read_pcap(path: &Path) -> io::Result<Vec<Vec<u8>>> {
    let mut data = Vec::new();
    File::open(path)?.read_to_end(&mut data)?;
    parse_pcap(&data)
}

/// Read the frames of a classic libpcap file from a byte buffer.
pub fn parse_pcap(data: &[u8]) -> io::Result<Vec<Vec<u8>>> {
    if data.len() < 24 {
        return Err(invalid_data(
            "the pcap file is shorter than its global header",
        ));
    }
    let magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    if magic != PCAP_MAGIC {
        return Err(invalid_data("the pcap file has an unknown magic number"));
    }

    let mut frames = Vec::new();
    let mut offset = 24;
    while offset < data.len() {
        let header_end = offset + 16;
        let Some(header) = data.get(offset..header_end) else {
            return Err(invalid_data("the pcap record header is truncated"));
        };
        let length = u32::from_le_bytes([header[8], header[9], header[10], header[11]]);
        offset = header_end;

        let length =
            usize::try_from(length).map_err(|_| invalid_data("the record length is too large"))?;
        let Some(frame) = data.get(offset..offset + length) else {
            return Err(invalid_data("the pcap record is truncated"));
        };
        frames.push(frame.to_vec());
        offset += length;
    }

    Ok(frames)
}

/// Build an `io::Error` of the "invalid data" kind.
fn invalid_data(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

/// A named group of synthetic frames.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fixture {
    /// The file name the fixture is written under.
    pub name: &'static str,
    /// The frames of the fixture, each one a full radiotap + 802.11 frame.
    pub frames: Vec<Vec<u8>>,
}

/// The standard set of synthetic fixtures.
///
/// Every frame in the set uses a MAC address of the `00:11:22:33:44:xx`
/// family and every SSID starts with `example-`, so the "no real data"
/// guardrail can be checked mechanically.
///
/// | Fixture | Contents |
/// |---|---|
/// | `beacon.pcap` | beacons of four networks: open, WPA2-PSK, WPA3-SAE and transition mode |
/// | `probe.pcap` | probe requests for the networks |
/// | `data.pcap` | data frames between a client and an access point |
/// | `eapol.pcap` | EAPOL frames with an LLC/SNAP header |
/// | `mixed.pcap` | one of each frame kind, in one file |
pub fn standard_fixtures() -> Vec<Fixture> {
    let beacon_frames = vec![
        // An open network.
        beacon(mac(3), "example-open", 5180, -67, false),
        // WPA2-Personal: AKM 00:0f:ac:2.
        beacon(mac(1), "example-ssid", 2412, -42, true),
        // WPA3-Personal: AKM 00:0f:ac:8.
        beacon_with_akm(mac(4), "example-wpa3", 2412, -50, &[AKM_SAE]),
        // Transition mode: both AKM suites.
        beacon_with_akm(mac(5), "example-mixed", 2412, -58, &[AKM_PSK, AKM_SAE]),
    ];

    let probe_frames = vec![
        probe_request(mac(11), "example-ssid", -48, 2412),
        probe_request(mac(12), "example-net", -60, 5180),
        probe_request(mac(13), "example-open", -51, 2412),
    ];

    let data_frames = vec![
        data_frame(mac(21), mac(31), mac(1), true, false, b"example-payload"),
        data_frame(mac(31), mac(21), mac(1), false, true, b"example-payload"),
        data_frame(mac(22), mac(32), mac(2), true, false, b"example-payload"),
        // The four-address form: both DS bits are set.
        data_frame(mac(23), mac(33), mac(3), true, true, b"example-payload"),
    ];

    let eapol_frames = vec![
        eapol_frame(mac(21), mac(1), mac(1)),
        eapol_frame(mac(22), mac(2), mac(2)),
    ];

    let mixed_frames = vec![
        beacon(mac(1), "example-ssid", 2412, -42, true),
        probe_request(mac(11), "example-ssid", -48, 2412),
        data_frame(mac(21), mac(31), mac(1), true, false, b"example-payload"),
        eapol_frame(mac(22), mac(1), mac(1)),
    ];

    vec![
        Fixture {
            name: "beacon.pcap",
            frames: beacon_frames,
        },
        Fixture {
            name: "probe.pcap",
            frames: probe_frames,
        },
        Fixture {
            name: "data.pcap",
            frames: data_frames,
        },
        Fixture {
            name: "eapol.pcap",
            frames: eapol_frames,
        },
        Fixture {
            name: "mixed.pcap",
            frames: mixed_frames,
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A unique path inside the system temporary directory.
    fn temp_path(tag: &str) -> std::path::PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!("od3sa-fixtures-{}-{tag}", std::process::id()));
        path
    }

    /// The radiotap header length of a frame, read from `it_len`.
    fn radiotap_len(frame: &[u8]) -> usize {
        u16::from_le_bytes([frame[2], frame[3]]) as usize
    }

    /// The frame control word of a frame, without its radiotap header.
    fn frame_control_of(frame: &[u8]) -> u16 {
        let start = radiotap_len(frame);
        u16::from_le_bytes([frame[start], frame[start + 1]])
    }

    /// The type and subtype of a frame.
    fn frame_type_and_subtype(frame: &[u8]) -> (u8, u8) {
        let control = frame_control_of(frame);
        (((control >> 2) & 0x03) as u8, ((control >> 4) & 0x0f) as u8)
    }

    /// The three addresses of a frame, without its radiotap header.
    fn addresses_of(frame: &[u8]) -> [[u8; 6]; 3] {
        let start = radiotap_len(frame);
        let mut addresses = [[0u8; 6]; 3];
        for (index, address) in addresses.iter_mut().enumerate() {
            let offset = start + 4 + index * 6;
            address.copy_from_slice(&frame[offset..offset + 6]);
        }
        addresses
    }

    /// The information elements of a management frame body.
    fn information_elements(frame: &[u8]) -> Vec<(u8, Vec<u8>)> {
        let start = radiotap_len(frame);
        let (_type, subtype) = frame_type_and_subtype(frame);
        let fixed = match subtype {
            8 => 12, // beacon
            5 => 12, // probe response
            4 => 0,  // probe request
            _ => 0,
        };
        let mut elements = Vec::new();
        let mut offset = start + 24 + fixed;
        while offset + 2 <= frame.len() {
            let id = frame[offset];
            let length = frame[offset + 1] as usize;
            offset += 2;
            if offset + length > frame.len() {
                break;
            }
            elements.push((id, frame[offset..offset + length].to_vec()));
            offset += length;
        }
        elements
    }

    #[test]
    fn radiotap_header_has_the_expected_fields() {
        let header = radiotap(-42, 2412, 2);

        assert_eq!(&header[0..2], &[0, 0], "it_version and it_pad");
        assert_eq!(
            u16::from_le_bytes([header[2], header[3]]),
            header.len() as u16,
            "it_len covers the whole header"
        );
        assert_eq!(
            u32::from_le_bytes([header[4], header[5], header[6], header[7]]),
            RADIOTAP_PRESENT,
            "it_present"
        );
        assert_eq!(RADIOTAP_PRESENT, 0b0000_0000_0010_1110);
    }

    #[test]
    fn radiotap_fields_are_aligned_and_ordered() {
        let header = radiotap(-42, 2412, 2);
        let present_end = 8;

        // bit 1: Flags, one byte at offset 8.
        assert_eq!(header[present_end], 0x00);
        // bit 2: Rate, one byte at offset 9.
        assert_eq!(header[present_end + 1], 2);
        // bit 3: Channel, two 16-bit values at offset 10, which is even.
        assert_eq!(present_end + 2, 10);
        assert_eq!(
            u16::from_le_bytes([header[10], header[11]]),
            2412,
            "channel frequency"
        );
        // bit 5: DBM, one byte at offset 14.
        assert_eq!(i8::from_le_bytes([header[14]]), -42);
        assert_eq!(header.len(), 15, "no trailing padding");
    }

    #[test]
    fn beacon_frame_has_the_expected_header() {
        let bssid = mac(1);
        let frame = beacon(bssid, "example-ssid", 2412, -42, true);

        assert_eq!(frame_type_and_subtype(&frame), (0, 8), "management beacon");
        let addresses = addresses_of(&frame);
        assert_eq!(addresses[0], BROADCAST_ADDR, "addr1");
        assert_eq!(addresses[1], bssid, "addr2 is the transmitter");
        assert_eq!(addresses[2], bssid, "addr3 is the BSSID");
    }

    #[test]
    fn beacon_frame_carries_the_expected_elements() {
        let frame = beacon(mac(1), "example-ssid", 2412, -42, true);
        let elements = information_elements(&frame);

        let ssid = elements
            .iter()
            .find(|(id, _)| *id == 0)
            .expect("an SSID element");
        assert_eq!(ssid.1, b"example-ssid".to_vec());

        assert!(elements.iter().any(|(id, _)| *id == 1), "supported rates");
        let ds = elements
            .iter()
            .find(|(id, _)| *id == 3)
            .expect("a DS parameter set");
        assert_eq!(ds.1, vec![1], "channel 1 for 2412 MHz");

        let rsn = elements
            .iter()
            .find(|(id, _)| *id == 48)
            .expect("an RSN element");
        assert_eq!(&rsn.1[0..2], &RSN_VERSION.to_le_bytes());
        assert_eq!(&rsn.1[2..6], &[0x00, 0x0f, 0xac, 0x04], "group cipher CCMP");
        assert_eq!(
            &rsn.1[8..12],
            &[0x00, 0x0f, 0xac, 0x04],
            "pairwise cipher CCMP"
        );
        assert_eq!(&rsn.1[14..18], &AKM_PSK, "AKM PSK");
    }

    #[test]
    fn an_open_beacon_has_no_rsn_element() {
        let frame = beacon(mac(3), "example-open", 5180, -67, false);
        let elements = information_elements(&frame);

        assert!(!elements.iter().any(|(id, _)| *id == 48), "no RSN element");
        let ds = elements
            .iter()
            .find(|(id, _)| *id == 3)
            .expect("a DS parameter set");
        assert_eq!(ds.1, vec![36], "channel 36 for 5180 MHz");
    }

    #[test]
    fn probe_request_frame_has_the_expected_header() {
        let src = mac(11);
        let frame = probe_request(src, "example-ssid", -48, 2412);

        assert_eq!(
            frame_type_and_subtype(&frame),
            (0, 4),
            "management probe request"
        );
        let addresses = addresses_of(&frame);
        assert_eq!(addresses[0], BROADCAST_ADDR, "addr1");
        assert_eq!(addresses[1], src, "addr2 is the transmitter");
        assert_eq!(addresses[2], BROADCAST_ADDR, "addr3");

        let elements = information_elements(&frame);
        let ssid = elements
            .iter()
            .find(|(id, _)| *id == 0)
            .expect("an SSID element");
        assert_eq!(ssid.1, b"example-ssid".to_vec());
    }

    #[test]
    fn data_frame_places_the_addresses_by_direction() {
        let src = mac(21);
        let dst = mac(31);
        let bssid = mac(1);

        let to_ds = data_frame(src, dst, bssid, true, false, b"body");
        assert_eq!(frame_type_and_subtype(&to_ds), (2, 0), "data frame");
        assert_eq!(frame_control_of(&to_ds) & FLAG_TO_DS, FLAG_TO_DS);
        let addresses = addresses_of(&to_ds);
        assert_eq!(addresses[0], bssid, "addr1 is the BSSID");
        assert_eq!(addresses[1], src, "addr2 is the source");
        assert_eq!(addresses[2], dst, "addr3 is the destination");
        assert!(to_ds.ends_with(b"body"));

        let from_ds = data_frame(src, dst, bssid, false, true, b"body");
        let addresses = addresses_of(&from_ds);
        assert_eq!(addresses[0], dst, "addr1 is the destination");
        assert_eq!(addresses[1], bssid, "addr2 is the BSSID");
        assert_eq!(addresses[2], src, "addr3 is the source");
    }

    #[test]
    fn eapol_frame_carries_the_llc_snap_header() {
        let frame = eapol_frame(mac(21), mac(1), mac(1));

        assert_eq!(frame_type_and_subtype(&frame), (2, 0), "data frame");
        assert!(
            frame
                .windows(LLC_SNAP_EAPOL.len())
                .any(|w| w == LLC_SNAP_EAPOL),
            "the LLC/SNAP header of an EAPOL frame"
        );
    }

    #[test]
    fn pcap_round_trip_preserves_the_frames() {
        let path = temp_path("round-trip.pcap");
        let frames = vec![
            beacon(mac(1), "example-ssid", 2412, -42, true),
            probe_request(mac(11), "example-ssid", -48, 2412),
            data_frame(mac(21), mac(31), mac(1), true, false, b"example-payload"),
        ];

        write_pcap(&path, &frames).expect("the fixture file is written");
        let read = read_pcap(&path).expect("the fixture file is read back");

        assert_eq!(read, frames, "the frames are byte-identical");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn pcap_global_header_is_exactly_as_specified() {
        let path = temp_path("header.pcap");
        write_pcap(&path, &[beacon(mac(1), "example-ssid", 2412, -42, true)])
            .expect("the fixture file is written");
        let bytes = std::fs::read(&path).expect("the fixture file is read");

        assert_eq!(
            &bytes[0..4],
            &[0xd4, 0xc3, 0xb2, 0xa1],
            "the little-endian magic"
        );
        assert_eq!(
            u16::from_le_bytes([bytes[4], bytes[5]]),
            2,
            "the major version"
        );
        assert_eq!(
            u16::from_le_bytes([bytes[6], bytes[7]]),
            4,
            "the minor version"
        );
        assert_eq!(
            u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]),
            0,
            "thiszone"
        );
        assert_eq!(
            u32::from_le_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]),
            0,
            "sigfigs"
        );
        assert_eq!(
            u32::from_le_bytes([bytes[16], bytes[17], bytes[18], bytes[19]]),
            65535,
            "snaplen"
        );
        assert_eq!(
            u32::from_le_bytes([bytes[20], bytes[21], bytes[22], bytes[23]]),
            127,
            "DLT_IEEE802_11_RADIOTAP"
        );

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn pcap_timestamps_are_deterministic() {
        let path = temp_path("timestamps.pcap");
        let frames = vec![
            beacon(mac(1), "example-ssid", 2412, -42, true),
            beacon(mac(2), "example-net", 2412, -55, true),
        ];

        write_pcap(&path, &frames).expect("the fixture file is written");
        let bytes = std::fs::read(&path).expect("the fixture file is read");

        let seconds = u32::from_le_bytes([bytes[24], bytes[25], bytes[26], bytes[27]]);
        let usec = u32::from_le_bytes([bytes[28], bytes[29], bytes[30], bytes[31]]);
        assert_eq!(seconds, FIXTURE_EPOCH_SEC);
        assert_eq!(usec, 0);

        let offset = 24 + 16 + frames[0].len();
        let seconds = u32::from_le_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
        ]);
        let usec = u32::from_le_bytes([
            bytes[offset + 4],
            bytes[offset + 5],
            bytes[offset + 6],
            bytes[offset + 7],
        ]);
        assert_eq!(seconds, FIXTURE_EPOCH_SEC);
        assert_eq!(usec, FIXTURE_STEP_USEC);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn the_standard_fixtures_are_the_expected_files() {
        let names: Vec<&str> = standard_fixtures().iter().map(|f| f.name).collect();
        assert_eq!(
            names,
            vec![
                "beacon.pcap",
                "probe.pcap",
                "data.pcap",
                "eapol.pcap",
                "mixed.pcap"
            ]
        );
        for fixture in standard_fixtures() {
            assert!(!fixture.frames.is_empty(), "{} has frames", fixture.name);
        }
    }

    #[test]
    fn the_mac_helper_stays_in_the_family() {
        for n in 0u8..=255 {
            let address = mac(n);
            assert!(is_synthetic_mac(&address));
            assert_eq!(address[5], n);
        }
    }

    /// The tests that use the parser crate.
    ///
    /// They prove that the frames this crate builds are the frames the
    /// daemon will read: the same radiotap header, the same MAC header and
    /// the same information elements.
    mod parser {
        use super::*;

        use od3sa_parse::frame::{BodyKind, classify_body, map_data_addresses};
        use od3sa_parse::ie::{Akm, Cipher, parse_ies, summarize};
        use od3sa_parse::ieee80211::{FrameType, MacHeader, management_ie_offset};
        use od3sa_parse::radiotap;

        /// The length of a MAC header without the address-4 field.
        const MAC_HEADER_LEN: usize = 24;

        /// The information elements of a management frame.
        fn elements_of(frame: &[u8], subtype: u8) -> Vec<od3sa_parse::ie::Ie<'_>> {
            let header = radiotap::parse(frame).expect("the radiotap header parses");
            let start = header.len as usize;
            let offset = management_ie_offset(subtype).expect("the subtype has elements");
            let body = &frame[start + MAC_HEADER_LEN + offset..];
            parse_ies(body).expect("the information elements parse")
        }

        #[test]
        fn the_generated_beacon_parses_with_the_expected_ssid() {
            let frame = beacon(mac(1), "example-ssid", 2412, -42, true);

            let header = radiotap::parse(&frame).expect("the radiotap header parses");
            assert_eq!(header.signal_dbm, Some(-42));
            assert_eq!(header.rate, Some(2));
            assert_eq!(header.channel.map(|c| c.freq_mhz), Some(2412));

            let start = header.len as usize;
            let mac_header = MacHeader::parse(&frame[start..]).expect("the MAC header parses");
            assert_eq!(mac_header.frame_type(), FrameType::Management);
            assert_eq!(mac_header.subtype(), 8);
            assert_eq!(mac_header.addr2, mac(1), "the transmitter");
            assert_eq!(mac_header.addr3, mac(1), "the BSSID");
            assert_eq!(mac_header.addr4, None);

            let ies = elements_of(&frame, 8);
            let summary = summarize(&ies);

            let ssid = summary.ssid.expect("the beacon has an SSID");
            assert_eq!(ssid.bytes, b"example-ssid".to_vec());
            assert!(!ssid.hidden);

            let security = summary.security.expect("the beacon has security");
            assert!(security.rsn);
            assert_eq!(security.akm, vec![Akm::Psk]);
            assert_eq!(security.pairwise, vec![Cipher::Ccmp]);
            assert_eq!(security.group, Some(Cipher::Ccmp));
        }

        #[test]
        fn an_open_beacon_has_no_security() {
            let frame = beacon(mac(3), "example-open", 5180, -67, false);

            let ies = elements_of(&frame, 8);
            let summary = summarize(&ies);

            let ssid = summary.ssid.expect("the beacon has an SSID");
            assert_eq!(ssid.bytes, b"example-open".to_vec());
            assert!(summary.security.is_none(), "an open network has no RSN");
        }

        #[test]
        fn the_generated_probe_request_parses() {
            let frame = probe_request(mac(11), "example-ssid", -48, 2412);

            let header = radiotap::parse(&frame).expect("the radiotap header parses");
            assert_eq!(header.signal_dbm, Some(-48));
            assert_eq!(header.channel.map(|c| c.freq_mhz), Some(2412));

            let start = header.len as usize;
            let mac_header = MacHeader::parse(&frame[start..]).expect("the MAC header parses");
            assert_eq!(mac_header.frame_type(), FrameType::Management);
            assert_eq!(mac_header.subtype(), 4);
            assert_eq!(mac_header.addr2, mac(11));

            let ies = elements_of(&frame, 4);
            let summary = summarize(&ies);
            let ssid = summary.ssid.expect("the probe request has an SSID");
            assert_eq!(ssid.bytes, b"example-ssid".to_vec());
        }

        #[test]
        fn the_generated_data_frames_map_to_a_client_and_a_bssid() {
            let src = mac(21);
            let dst = mac(31);
            let bssid = mac(1);

            for (to_ds, from_ds) in [(false, false), (true, false), (false, true), (true, true)] {
                let frame = data_frame(src, dst, bssid, to_ds, from_ds, b"example-payload");
                let header = radiotap::parse(&frame).expect("the radiotap header parses");
                let start = header.len as usize;
                let mac_header = MacHeader::parse(&frame[start..]).expect("the MAC header parses");

                assert_eq!(mac_header.frame_type(), FrameType::Data);
                assert_eq!(mac_header.subtype(), 0);
                assert_eq!(mac_header.to_ds(), to_ds);
                assert_eq!(mac_header.from_ds(), from_ds);

                let mapping = map_data_addresses(&mac_header);
                if to_ds && from_ds {
                    // The four-address form: the station is addr4 and the
                    // BSSID is not in the frame at all.
                    assert_eq!(mapping.client, Some(src));
                    assert_eq!(mapping.bssid, None);
                    assert_eq!(mac_header.addr4, Some(src));
                } else {
                    assert_eq!(mapping.bssid, Some(bssid));
                }
            }
        }

        #[test]
        fn the_generated_eapol_frame_is_classified_as_eapol() {
            let frame = eapol_frame(mac(21), mac(1), mac(1));

            let header = radiotap::parse(&frame).expect("the radiotap header parses");
            let start = header.len as usize;
            let mac_header = MacHeader::parse(&frame[start..]).expect("the MAC header parses");
            assert_eq!(mac_header.frame_type(), FrameType::Data);

            let body = &frame[start + MAC_HEADER_LEN..];
            assert_eq!(classify_body(body), BodyKind::Eapol);
        }

        #[test]
        fn every_standard_fixture_frame_parses() {
            for fixture in standard_fixtures() {
                for frame in &fixture.frames {
                    let header =
                        radiotap::parse(frame).unwrap_or_else(|e| panic!("{}: {e}", fixture.name));
                    let start = header.len as usize;
                    MacHeader::parse(&frame[start..])
                        .unwrap_or_else(|e| panic!("{}: {e}", fixture.name));
                }
            }
        }

        #[test]
        fn a_wpa3_beacon_is_told_apart_from_a_wpa2_one() {
            // The AKM suite table is IEEE 802.11 Table 12-6: `00:0f:ac:2` is
            // PSK (WPA2-Personal) and `00:0f:ac:8` is SAE (WPA3-Personal).
            // Keeping the two apart is the whole point of the table.
            let wpa2 = beacon_with_akm(mac(1), "example-wpa2", 2412, -42, &[AKM_PSK]);
            let wpa3 = beacon_with_akm(mac(2), "example-wpa3", 2412, -42, &[AKM_SAE]);
            let mixed = beacon_with_akm(mac(3), "example-mixed", 2412, -42, &[AKM_PSK, AKM_SAE]);

            let akm_of = |frame: &[u8]| -> Vec<Akm> {
                let ies = elements_of(frame, 8);
                summarize(&ies)
                    .security
                    .expect("the beacon has security")
                    .akm
            };

            assert_eq!(akm_of(&wpa2), vec![Akm::Psk]);
            assert_eq!(akm_of(&wpa3), vec![Akm::Sae]);
            assert_eq!(akm_of(&mixed), vec![Akm::Psk, Akm::Sae]);
        }

        /// The addresses a frame carries, in the order they appear.
        fn addresses_of(frame: &[u8]) -> Vec<[u8; 6]> {
            let header = radiotap::parse(frame).expect("the radiotap header parses");
            let start = header.len as usize;
            let mac_header = MacHeader::parse(&frame[start..]).expect("the MAC header parses");

            let mut addresses = vec![mac_header.addr1, mac_header.addr2, mac_header.addr3];
            if let Some(addr4) = mac_header.addr4 {
                addresses.push(addr4);
            }
            addresses
        }

        #[test]
        fn every_fixture_mac_is_synthetic() {
            // The guardrail: no real MAC address may end up in a fixture.
            // The check is on the parsed address fields, not on a scan of the
            // raw file, which would trip over the pcap header and over the
            // payload markers.
            for fixture in standard_fixtures() {
                for frame in &fixture.frames {
                    for address in addresses_of(frame) {
                        assert!(
                            is_synthetic_mac(&address),
                            "{address:02x?} in {} is not a synthetic address",
                            fixture.name
                        );
                    }
                }
            }
        }

        #[test]
        fn every_fixture_ssid_is_synthetic() {
            // The guardrail: no real SSID may end up in a fixture. Only the
            // SSID elements of the management frames are checked; a data
            // frame has no information elements.
            for fixture in standard_fixtures() {
                for frame in &fixture.frames {
                    let header = radiotap::parse(frame).expect("the radiotap header parses");
                    let start = header.len as usize;
                    let mac_header =
                        MacHeader::parse(&frame[start..]).expect("the MAC header parses");
                    if mac_header.frame_type() != FrameType::Management {
                        continue;
                    }

                    let offset = management_ie_offset(mac_header.subtype())
                        .expect("the subtype has information elements");
                    let body = &frame[start + MAC_HEADER_LEN + offset..];
                    let ies = parse_ies(body).expect("the information elements parse");

                    for ie in ies {
                        if ie.id != 0 {
                            continue;
                        }
                        // An empty SSID element is a hidden network, which is
                        // fine; anything else must be a synthetic name.
                        if ie.body.is_empty() {
                            continue;
                        }
                        let ssid = String::from_utf8_lossy(ie.body);
                        assert!(
                            is_synthetic_ssid(&ssid),
                            "{ssid:?} in {} is not a synthetic SSID",
                            fixture.name
                        );
                    }
                }
            }
        }
    }
}
