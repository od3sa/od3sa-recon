//! The `pcapng-meta` plugin: a pcapng file that holds **frame headers only**.
//!
//! This is the plugin with the sharpest edge in the project, because a capture
//! file is the one thing people feed to a decoder. Two rules hold it together:
//!
//! * **Every packet in the file is synthetic.** It is built from the metadata
//!   the daemon has — a radiotap header with the channel and the signal
//!   level, and an 802.11 management frame with the address and the SSID. No
//!   frame that was ever on the air is copied into the file ✓.
//! * **There is no payload.** The synthetic frames carry headers only, and
//!   there is no code path that copies a payload, because the daemon does not
//!   have one to copy ✓.
//!
//! The plugin is **off by default**: it runs only when someone asks for it.
//!
//! # The file
//!
//! The pcapng format is written here, by hand, because it is not complicated:
//!
//! * a **Section Header Block** (type `0x0A0D0D0A`) with the byte-order magic
//!   `0x1A2B3C4D`, major version 1 and minor version 0;
//! * an **Interface Description Block** (type `0x00000001`) with link type
//!   127 — 802.11 with a radiotap header in front of it;
//! * one **Enhanced Packet Block** (type `0x00000006`) per observation.
//!
//! Every block carries its total length at its start and at its end, and the
//! two agree. A file that claims a length it does not have is worse than no
//! file at all.
//!
//! # What goes in
//!
//! One observation per access point sighting: the access point's address, its
//! SSID, the channel it was seen on and the signal level. The signal level
//! and the channel come from the sightings the daemon has; the address and
//! the SSID come from the access points it knows.
//!
//! Nothing else goes in. There is no code path here that could carry a
//! payload, a key, or a frame that was on the air.

use serde_json::Value;

/// The link type for 802.11 frames that carry a radiotap header.
pub const LINKTYPE_RADIOTAP_80211: u16 = 127;

/// The snap length written into the interface description block.
const SNAP_LEN: u32 = 65535;

/// One synthetic frame: what the daemon knows about one sighting.
///
/// A frame is a header and nothing else. There is no field for a payload,
/// because there is no payload to put in one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observation {
    /// When it was seen, in unix epoch milliseconds.
    pub timestamp_ms: u64,
    /// The address it was seen at: the access point's BSSID.
    pub bssid: [u8; 6],
    /// The network name, when the daemon knows one.
    pub ssid: Option<String>,
    /// The channel it was seen on, when the daemon knows one.
    pub channel: Option<u16>,
    /// The centre frequency, when the daemon knows one.
    pub freq_mhz: Option<u16>,
    /// The signal level in dBm, when the daemon knows one.
    pub signal_dbm: Option<i16>,
}

/// An access point, as the query API reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApMeta {
    /// The access point's address.
    pub bssid: [u8; 6],
    /// The network name, when the SSID is known.
    pub ssid: Option<String>,
    /// The channel the access point was last seen on.
    pub channel: Option<u16>,
    /// The centre frequency of that channel.
    pub freq_mhz: Option<u16>,
    /// The band the access point is on: `2.4`, `5` or `6`.
    pub band: Option<String>,
    /// When a beacon was last heard.
    pub last_beacon_ms: Option<u64>,
}

/// A device, as the query API reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceMeta {
    /// The device's address.
    pub mac: [u8; 6],
    /// The best signal level the daemon has for it.
    pub rssi: Option<i16>,
    /// When it was last seen.
    pub last_seen_ms: Option<u64>,
}

/// One sighting bucket, as the query API reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SightingMeta {
    /// The start of the bucket, in unix epoch milliseconds.
    pub bucket_ms: u64,
    /// The channel the sighting was heard on.
    pub channel: Option<u16>,
    /// The mean signal level in the bucket.
    pub rssi_avg: Option<i16>,
}

impl ApMeta {
    /// Read an access point out of one `aps.list` item.
    ///
    /// Returns `None` when the item holds no address: an access point
    /// without an address is not something a frame can be built from.
    pub fn from_json(item: &Value) -> Option<ApMeta> {
        let bssid = parse_mac(item.get("bssid")?.as_str()?)?;
        Some(ApMeta {
            bssid,
            ssid: item.get("ssid").and_then(Value::as_str).map(str::to_string),
            channel: item
                .get("channel")
                .and_then(Value::as_u64)
                .and_then(|value| u16::try_from(value).ok()),
            freq_mhz: item
                .get("freq_mhz")
                .and_then(Value::as_u64)
                .and_then(|value| u16::try_from(value).ok()),
            band: item.get("band").and_then(Value::as_str).map(str::to_string),
            last_beacon_ms: item.get("last_beacon_ms").and_then(Value::as_u64),
        })
    }

    /// The synthetic frame for this access point.
    ///
    /// The sighting, when there is one, gives the time, the channel and the
    /// signal level. Without a sighting the access point's own last beacon
    /// and the device's signal level are used instead.
    pub fn observation(
        &self,
        sighting: Option<&SightingMeta>,
        device: Option<&DeviceMeta>,
    ) -> Observation {
        let channel = sighting
            .and_then(|sighting| sighting.channel)
            .or(self.channel);
        let freq_mhz = self
            .freq_mhz
            .or_else(|| freq_for_channel(channel, self.band.as_deref()));
        let signal_dbm = sighting
            .and_then(|sighting| sighting.rssi_avg)
            .or_else(|| device.and_then(|device| device.rssi));
        let timestamp_ms = sighting
            .map(|sighting| sighting.bucket_ms)
            .or(self.last_beacon_ms)
            .or_else(|| device.and_then(|device| device.last_seen_ms))
            .unwrap_or(0);
        Observation {
            timestamp_ms,
            bssid: self.bssid,
            ssid: self.ssid.clone(),
            channel,
            freq_mhz,
            signal_dbm,
        }
    }
}

impl DeviceMeta {
    /// Read a device out of one `devices.list` item.
    ///
    /// Returns `None` when the item holds no address.
    pub fn from_json(item: &Value) -> Option<DeviceMeta> {
        let mac = parse_mac(item.get("mac")?.as_str()?)?;
        Some(DeviceMeta {
            mac,
            rssi: item
                .get("max_rssi")
                .and_then(Value::as_i64)
                .or_else(|| item.get("last_rssi").and_then(Value::as_i64))
                .and_then(|value| i16::try_from(value).ok()),
            last_seen_ms: item.get("last_seen_ms").and_then(Value::as_u64),
        })
    }
}

impl SightingMeta {
    /// Read a sighting out of one `sightings.list` item.
    ///
    /// Returns `None` when the item holds no bucket time: a sighting
    /// without a time cannot be placed in a file.
    pub fn from_json(item: &Value) -> Option<SightingMeta> {
        let bucket_ms = item.get("bucket_ms").and_then(Value::as_u64)?;
        let rssi_avg = item
            .get("rssi_avg")
            .and_then(Value::as_f64)
            .map(|value| value.round() as i32)
            .and_then(|value| i16::try_from(value).ok());
        Some(SightingMeta {
            bucket_ms,
            channel: item
                .get("channel")
                .and_then(Value::as_u64)
                .and_then(|value| u16::try_from(value).ok()),
            rssi_avg,
        })
    }
}

/// Read a MAC address out of a string.
///
/// The query API writes addresses as `aa:bb:cc:dd:ee:ff`, lower case. A
/// string that is not six groups of two hex digits is not an address, and
/// `None` says so rather than guessing.
pub fn parse_mac(text: &str) -> Option<[u8; 6]> {
    let mut bytes = [0u8; 6];
    let mut parts = text.trim().split(':');
    for byte in bytes.iter_mut() {
        let part = parts.next()?;
        *byte = u8::from_str_radix(part, 16).ok()?;
    }
    if parts.next().is_some() {
        return None;
    }
    Some(bytes)
}

/// Write a MAC address as the query API writes it.
pub fn mac_string(mac: &[u8; 6]) -> String {
    mac.iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<String>>()
        .join(":")
}

/// The centre frequency of a channel number.
///
/// The band is needed, because channel 1 means different things in the
/// 2.4 GHz, 5 GHz and 6 GHz bands. When the band is not known, the channel
/// number is taken at face value: 1 to 14 are read as 2.4 GHz, and 34 to
/// 165 as 5 GHz. That is an **assumption** — the daemon knows the band, so
/// the caller should pass it when it has one.
pub fn freq_for_channel(channel: Option<u16>, band: Option<&str>) -> Option<u16> {
    let channel = channel?;
    match band {
        Some("2.4") => match channel {
            1..=13 => Some(2407 + 5 * channel),
            14 => Some(2484),
            _ => None,
        },
        Some("5") => match channel {
            1..=196 => Some(5000 + 5 * channel),
            _ => None,
        },
        Some("6") => match channel {
            1..=233 => Some(5950 + 5 * channel),
            _ => None,
        },
        _ => match channel {
            1..=13 => Some(2407 + 5 * channel),
            14 => Some(2484),
            34..=165 => Some(5000 + 5 * channel),
            _ => None,
        },
    }
}

/// Build the whole file.
///
/// The file is a section header, one interface description, and one
/// enhanced packet block per observation.
pub fn write(observations: &[Observation]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&section_header());
    out.extend_from_slice(&interface_description());
    for observation in observations {
        out.extend_from_slice(&enhanced_packet(observation));
    }
    out
}

/// The section header block: the first thing in the file.
fn section_header() -> Vec<u8> {
    // The block is 28 bytes long. The section length field says the length
    // of the section that follows; it is written as -1, meaning "not known",
    // because the file grows as the observations are written.
    let mut block = Vec::with_capacity(28);
    block.extend_from_slice(&0x0A0D_0D0Au32.to_le_bytes());
    block.extend_from_slice(&28u32.to_le_bytes());
    block.extend_from_slice(&0x1A2B_3C4Du32.to_le_bytes());
    block.extend_from_slice(&1u16.to_le_bytes());
    block.extend_from_slice(&0u16.to_le_bytes());
    block.extend_from_slice(&(-1i64).to_le_bytes());
    block.extend_from_slice(&28u32.to_le_bytes());
    block
}

/// The interface description block: what the packets in the file look like.
fn interface_description() -> Vec<u8> {
    // 32 bytes: the block header and trailer, the link type, the reserved
    // word, the snap length, the timestamp-resolution option and the
    // end-of-options option.
    let mut block = Vec::with_capacity(32);
    block.extend_from_slice(&1u32.to_le_bytes());
    block.extend_from_slice(&32u32.to_le_bytes());
    block.extend_from_slice(&LINKTYPE_RADIOTAP_80211.to_le_bytes());
    block.extend_from_slice(&0u16.to_le_bytes());
    block.extend_from_slice(&SNAP_LEN.to_le_bytes());
    // Option 9 is `if_tsresol`: the timestamps in the file are in
    // microseconds. The value is padded to a four-byte boundary.
    block.extend_from_slice(&9u16.to_le_bytes());
    block.extend_from_slice(&1u16.to_le_bytes());
    block.push(6u8);
    block.extend_from_slice(&[0u8; 3]);
    // Option 0 ends the list.
    block.extend_from_slice(&0u32.to_le_bytes());
    block.extend_from_slice(&32u32.to_le_bytes());
    block
}

/// The enhanced packet block for one observation.
fn enhanced_packet(observation: &Observation) -> Vec<u8> {
    let packet = frame_bytes(observation);
    let captured = packet.len() as u32;

    // The packet data is padded to a multiple of four bytes. The padding is
    // not part of the packet: the captured length stays the length of the
    // frame itself.
    let mut padded = packet.clone();
    while !padded.len().is_multiple_of(4) {
        padded.push(0);
    }

    let micros = observation.timestamp_ms.saturating_mul(1000);
    let mut block = Vec::with_capacity(32 + padded.len());
    block.extend_from_slice(&6u32.to_le_bytes());
    block.extend_from_slice(&0u32.to_le_bytes());
    block.extend_from_slice(&0u32.to_le_bytes());
    block.extend_from_slice(&((micros >> 32) as u32).to_le_bytes());
    block.extend_from_slice(&(micros as u32).to_le_bytes());
    block.extend_from_slice(&captured.to_le_bytes());
    block.extend_from_slice(&captured.to_le_bytes());
    block.extend_from_slice(&padded);

    let total = (block.len() + 4) as u32;
    block[4..8].copy_from_slice(&total.to_le_bytes());
    block.extend_from_slice(&total.to_le_bytes());
    block
}

/// The bytes of one synthetic frame: a radiotap header and a beacon.
///
/// The frame is a management frame and nothing else. A management frame has
/// no payload field, so there is nowhere for one to hide.
fn frame_bytes(observation: &Observation) -> Vec<u8> {
    let mut frame = Vec::new();
    frame.extend_from_slice(&radiotap(observation));
    frame.extend_from_slice(&beacon(observation));
    frame
}

/// The radiotap header: the channel and the signal level.
///
/// The present word says which fields are there: bit 3 is the channel
/// (the centre frequency and the driver flags) and bit 5 is the signal
/// level in dBm. A field that is not known is left out rather than filled
/// with a made-up value.
fn radiotap(observation: &Observation) -> Vec<u8> {
    const BIT_CHANNEL: u32 = 1 << 3;
    const BIT_DBM: u32 = 1 << 5;

    let mut present = 0u32;
    let mut body = Vec::new();

    if let Some(freq) = observation.freq_mhz {
        present |= BIT_CHANNEL;
        body.extend_from_slice(&freq.to_le_bytes());
        body.extend_from_slice(&0u16.to_le_bytes());
    }
    if let Some(signal) = observation.signal_dbm {
        present |= BIT_DBM;
        body.push(signal.clamp(-127, 127) as i8 as u8);
    }

    // The fields are laid out in bit order, each at its own alignment, and
    // the length says how long the whole header is. Nothing follows the
    // last field: the 802.11 frame starts right after the header.
    let length = 8 + body.len();
    let mut header = Vec::with_capacity(length);
    header.push(0u8); // version
    header.push(0u8); // padding
    header.extend_from_slice(&(length as u16).to_le_bytes());
    header.extend_from_slice(&present.to_le_bytes());
    header.extend_from_slice(&body);
    header
}

/// The 802.11 management frame: the address and the SSID.
///
/// It is a beacon, because a beacon is the frame that carries an access
/// point's address and its network name. The fixed fields are filled with
/// the time of the sighting and with zeroes, and the only tagged parameter
/// is the SSID.
fn beacon(observation: &Observation) -> Vec<u8> {
    let mut frame = Vec::new();
    // Frame control: type 0 (management), subtype 8 (beacon).
    frame.extend_from_slice(&0x0080u16.to_le_bytes());
    frame.extend_from_slice(&0u16.to_le_bytes()); // duration
    frame.extend_from_slice(&0u16.to_le_bytes()); // sequence control
    frame.extend_from_slice(&[0xffu8; 6]); // address 1: broadcast
    frame.extend_from_slice(&observation.bssid); // address 2: the source
    frame.extend_from_slice(&observation.bssid); // address 3: the BSSID
    frame.extend_from_slice(&observation.timestamp_ms.saturating_mul(1000).to_le_bytes());
    frame.extend_from_slice(&100u16.to_le_bytes()); // beacon interval, in TU
    frame.extend_from_slice(&0u16.to_le_bytes()); // capability information

    if let Some(ssid) = &observation.ssid {
        // The SSID element is at most 32 bytes long; a longer name is cut,
        // the way the standard cuts it.
        let bytes = ssid.as_bytes();
        let length = bytes.len().min(32);
        frame.push(0u8); // element id: SSID
        frame.push(length as u8);
        frame.extend_from_slice(&bytes[..length]);
    }
    frame
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A synthetic observation, for the tests.
    fn example() -> Observation {
        Observation {
            timestamp_ms: 1_762_300_060_000,
            bssid: [0x00, 0x11, 0x22, 0x33, 0x44, 0x01],
            ssid: Some("example-ssid".to_string()),
            channel: Some(36),
            freq_mhz: Some(5180),
            signal_dbm: Some(-42),
        }
    }

    /// One block of a pcapng file, read back.
    #[derive(Debug)]
    struct Block {
        /// The block type.
        kind: u32,
        /// The bytes between the two length fields.
        body: Vec<u8>,
    }

    /// Read the blocks of a pcapng file.
    ///
    /// The reader is deliberately strict: a block whose length at the end
    /// does not match the one at the start is an error, because a file that
    /// claims a length it does not have is worse than no file.
    fn blocks(bytes: &[u8]) -> Result<Vec<Block>, String> {
        let mut blocks = Vec::new();
        let mut offset = 0usize;
        while offset < bytes.len() {
            if bytes.len() - offset < 12 {
                return Err("a block header does not fit".to_string());
            }
            let kind = u32::from_le_bytes(
                bytes[offset..offset + 4]
                    .try_into()
                    .map_err(|_| "a block type does not fit".to_string())?,
            );
            let total = u32::from_le_bytes(
                bytes[offset + 4..offset + 8]
                    .try_into()
                    .map_err(|_| "a block length does not fit".to_string())?,
            ) as usize;
            if total < 12 || !total.is_multiple_of(4) || offset + total > bytes.len() {
                return Err(format!("a block claims {total} bytes"));
            }
            let trailer = u32::from_le_bytes(
                bytes[offset + total - 4..offset + total]
                    .try_into()
                    .map_err(|_| "a block trailer does not fit".to_string())?,
            ) as usize;
            if trailer != total {
                return Err(format!(
                    "a block claims {total} bytes and ends with {trailer}"
                ));
            }
            blocks.push(Block {
                kind,
                body: bytes[offset + 8..offset + total - 4].to_vec(),
            });
            offset += total;
        }
        Ok(blocks)
    }

    /// The packet data of one enhanced packet block.
    ///
    /// The packet data in the block is padded to a multiple of four bytes;
    /// the captured length says how much of it is the packet itself.
    fn packet_of(block: &Block) -> &[u8] {
        // interface id, timestamp high, timestamp low, captured length,
        // original length, then the packet.
        let captured = u32::from_le_bytes([
            block.body[12],
            block.body[13],
            block.body[14],
            block.body[15],
        ]) as usize;
        &block.body[20..20 + captured]
    }

    #[test]
    fn the_file_starts_with_a_section_header_block() {
        let file = write(&[example()]);

        assert_eq!(&file[0..4], &0x0A0D_0D0Au32.to_le_bytes());
        assert_eq!(&file[8..12], &0x1A2B_3C4Du32.to_le_bytes());
        assert_eq!(&file[12..14], &1u16.to_le_bytes());
        assert_eq!(&file[14..16], &0u16.to_le_bytes());
        assert_eq!(&file[4..8], &28u32.to_le_bytes());
        assert_eq!(&file[24..28], &28u32.to_le_bytes());
    }

    #[test]
    fn every_block_ends_with_the_length_it_starts_with() {
        let file = write(&[example(), example()]);

        let blocks = blocks(&file).expect("the file should parse");
        assert_eq!(blocks.len(), 4);
        for block in &blocks {
            assert_eq!(block.body.len() % 4, 0);
        }
        // The reader above refuses a file whose lengths disagree, so
        // reaching this point is the check.
    }

    #[test]
    fn the_blocks_are_padded_to_four_bytes() {
        let file = write(&[example()]);

        let blocks = blocks(&file).expect("the file should parse");
        let total: usize = blocks.iter().map(|block| block.body.len() + 12).sum();
        assert_eq!(total, file.len());
        assert_eq!(file.len() % 4, 0);
    }

    #[test]
    fn the_interface_description_names_link_type_127() {
        let file = write(&[example()]);

        let blocks = blocks(&file).expect("the file should parse");
        let interfaces: Vec<&Block> = blocks.iter().filter(|block| block.kind == 1).collect();
        assert_eq!(interfaces.len(), 1);
        let link_type = u16::from_le_bytes([interfaces[0].body[0], interfaces[0].body[1]]);
        assert_eq!(link_type, LINKTYPE_RADIOTAP_80211);
        assert_eq!(link_type, 127);
    }

    #[test]
    fn every_packet_refers_to_an_interface_that_exists() {
        let file = write(&[example(), example(), example()]);

        let blocks = blocks(&file).expect("the file should parse");
        let interfaces = blocks.iter().filter(|block| block.kind == 1).count();
        assert!(interfaces > 0);
        for block in blocks.iter().filter(|block| block.kind == 6) {
            let interface_id =
                u32::from_le_bytes([block.body[0], block.body[1], block.body[2], block.body[3]]);
            assert!(interface_id < interfaces as u32);
        }
    }

    #[test]
    fn the_file_holds_no_payload() {
        // A marker that a payload would carry. If the file ever held a
        // payload, this is what would show up in it.
        const PAYLOAD_MARKER: &[u8] = b"OD3SA-PAYLOAD-MARKER";
        let file = write(&[example(), example()]);

        assert!(
            !file
                .windows(PAYLOAD_MARKER.len())
                .any(|window| window == PAYLOAD_MARKER),
            "the file must not hold a payload"
        );
    }

    #[test]
    fn every_packet_ends_where_its_last_element_ends() {
        // A frame that carried a payload would have bytes after the last
        // tagged parameter. Every packet in the file must end exactly where
        // its SSID element ends.
        let file = write(&[example(), example()]);

        let blocks = blocks(&file).expect("the file should parse");
        let packets: Vec<&Block> = blocks.iter().filter(|block| block.kind == 6).collect();
        assert_eq!(packets.len(), 2);
        for packet in packets {
            let packet = packet_of(packet);
            let header_length = u16::from_le_bytes([packet[2], packet[3]]) as usize;
            let frame = &packet[header_length..];
            // The tagged parameters start after the 24-byte MAC header and
            // the 12 bytes of fixed fields.
            let mut offset = 24 + 12;
            while offset < frame.len() {
                let length = frame[offset + 1] as usize;
                offset += 2 + length;
            }
            assert_eq!(
                offset,
                frame.len(),
                "the frame must end where its last element ends"
            );
        }
    }

    #[test]
    fn every_packet_is_a_header_only_synthetic_frame() {
        let file = write(&[example()]);

        let blocks = blocks(&file).expect("the file should parse");
        let packets: Vec<&Block> = blocks.iter().filter(|block| block.kind == 6).collect();
        assert_eq!(packets.len(), 1);

        let packet = packet_of(packets[0]);
        // The radiotap header: version, padding, length, present word.
        let header_length = u16::from_le_bytes([packet[2], packet[3]]) as usize;
        assert_eq!(packet[0], 0);
        assert_eq!(packet[1], 0);
        assert!(header_length >= 8);
        assert!(header_length < packet.len());

        let present = u32::from_le_bytes([packet[4], packet[5], packet[6], packet[7]]);
        // Only the channel and the signal level are ever present.
        assert_eq!(present & !(1 << 3 | 1 << 5), 0);

        // The 802.11 frame that follows: a management beacon.
        let frame = &packet[header_length..];
        let control = u16::from_le_bytes([frame[0], frame[1]]);
        assert_eq!(control >> 2 & 0b11, 0, "the frame type must be management");
        assert_eq!(control >> 4 & 0b1111, 8, "the frame subtype must be beacon");
        // 24 bytes of MAC header, 12 bytes of fixed fields, and the SSID
        // element: 2 bytes of header and 12 bytes of name.
        assert_eq!(frame.len(), 24 + 12 + 2 + "example-ssid".len());
        // The SSID is the only tagged parameter, and nothing follows it.
        assert_eq!(frame[frame.len() - 14], 0, "the element id must be SSID");
        assert_eq!(frame[frame.len() - 13] as usize, "example-ssid".len());
    }

    #[test]
    fn a_frame_without_an_ssid_carries_no_ssid_element() {
        let mut observation = example();
        observation.ssid = None;

        let file = write(&[observation]);

        let blocks = blocks(&file).expect("the file should parse");
        let packets: Vec<&Block> = blocks.iter().filter(|block| block.kind == 6).collect();
        let packet = packet_of(packets[0]);
        let header_length = u16::from_le_bytes([packet[2], packet[3]]) as usize;
        let frame = &packet[header_length..];
        assert_eq!(frame.len(), 24 + 12);
    }

    #[test]
    fn the_timestamps_are_written_in_microseconds() {
        let file = write(&[example()]);

        let blocks = blocks(&file).expect("the file should parse");
        let packets: Vec<&Block> = blocks.iter().filter(|block| block.kind == 6).collect();
        let body = &packets[0].body;
        let high = u32::from_le_bytes([body[4], body[5], body[6], body[7]]) as u64;
        let low = u32::from_le_bytes([body[8], body[9], body[10], body[11]]) as u64;
        let micros = (high << 32) | low;
        assert_eq!(micros, 1_762_300_060_000 * 1000);
    }

    #[test]
    fn a_mac_address_is_read_and_written_the_way_the_api_writes_it() {
        let mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];

        assert_eq!(mac_string(&mac), "00:11:22:33:44:55");
        assert_eq!(parse_mac("00:11:22:33:44:55"), Some(mac));
        assert_eq!(parse_mac("00:11:22:33:44"), None);
        assert_eq!(parse_mac("00:11:22:33:44:55:66"), None);
        assert_eq!(parse_mac("not-a-mac"), None);
        assert_eq!(parse_mac("00:11:22:33:44:zz"), None);
    }

    #[test]
    fn a_channel_is_read_with_the_band_it_belongs_to() {
        assert_eq!(freq_for_channel(Some(36), Some("5")), Some(5180));
        assert_eq!(freq_for_channel(Some(6), Some("2.4")), Some(2437));
        assert_eq!(freq_for_channel(Some(14), Some("2.4")), Some(2484));
        assert_eq!(freq_for_channel(Some(1), Some("6")), Some(5955));
        assert_eq!(freq_for_channel(Some(36), None), Some(5180));
        assert_eq!(freq_for_channel(None, Some("5")), None);
    }

    #[test]
    fn an_access_point_is_read_out_of_a_query_item() {
        let item = serde_json::json!({
            "bssid": "00:11:22:33:44:01",
            "ssid": "example-ssid",
            "channel": 36,
            "freq_mhz": 5180,
            "band": "5",
            "last_beacon_ms": 1_762_300_060_000u64,
        });

        let ap = ApMeta::from_json(&item).expect("the item should parse");

        assert_eq!(ap.bssid, [0x00, 0x11, 0x22, 0x33, 0x44, 0x01]);
        assert_eq!(ap.ssid.as_deref(), Some("example-ssid"));
        assert_eq!(ap.channel, Some(36));
        assert_eq!(ap.freq_mhz, Some(5180));
        assert_eq!(ap.band.as_deref(), Some("5"));
        assert_eq!(ap.last_beacon_ms, Some(1_762_300_060_000));
    }

    #[test]
    fn an_access_point_without_an_address_is_not_an_access_point() {
        let item = serde_json::json!({ "ssid": "example-ssid" });

        assert!(ApMeta::from_json(&item).is_none());
    }

    #[test]
    fn a_sighting_gives_the_frame_its_time_channel_and_signal() {
        let ap = ApMeta {
            bssid: [0x00, 0x11, 0x22, 0x33, 0x44, 0x01],
            ssid: Some("example-ssid".to_string()),
            channel: Some(36),
            freq_mhz: Some(5180),
            band: Some("5".to_string()),
            last_beacon_ms: Some(1_762_300_060_000),
        };
        let sighting = SightingMeta {
            bucket_ms: 1_762_300_060_500,
            channel: Some(6),
            rssi_avg: Some(-51),
        };

        let observation = ap.observation(Some(&sighting), None);

        assert_eq!(observation.timestamp_ms, 1_762_300_060_500);
        assert_eq!(observation.channel, Some(6));
        assert_eq!(observation.freq_mhz, Some(5180));
        assert_eq!(observation.signal_dbm, Some(-51));
        assert_eq!(observation.ssid.as_deref(), Some("example-ssid"));
    }

    #[test]
    fn an_access_point_without_a_sighting_falls_back_to_its_own_metadata() {
        let ap = ApMeta {
            bssid: [0x00, 0x11, 0x22, 0x33, 0x44, 0x01],
            ssid: Some("example-ssid".to_string()),
            channel: Some(36),
            freq_mhz: Some(5180),
            band: Some("5".to_string()),
            last_beacon_ms: Some(1_762_300_060_000),
        };
        let device = DeviceMeta {
            mac: [0x00, 0x11, 0x22, 0x33, 0x44, 0x01],
            rssi: Some(-42),
            last_seen_ms: Some(1_762_300_059_000),
        };

        let observation = ap.observation(None, Some(&device));

        assert_eq!(observation.timestamp_ms, 1_762_300_060_000);
        assert_eq!(observation.signal_dbm, Some(-42));
        assert_eq!(observation.channel, Some(36));
    }

    #[test]
    fn a_sighting_is_read_out_of_a_query_item() {
        let item = serde_json::json!({
            "bucket_ms": 1_762_300_060_000u64,
            "n": 3,
            "rssi_min": -60,
            "rssi_max": -42,
            "rssi_avg": -51.4,
            "channel": 36,
        });

        let sighting = SightingMeta::from_json(&item).expect("the item should parse");

        assert_eq!(sighting.bucket_ms, 1_762_300_060_000);
        assert_eq!(sighting.channel, Some(36));
        assert_eq!(sighting.rssi_avg, Some(-51));
    }

    #[test]
    fn a_device_is_read_out_of_a_query_item() {
        let item = serde_json::json!({
            "mac": "00:11:22:33:44:02",
            "kind": "client",
            "last_seen_ms": 1_762_300_060_000u64,
            "max_rssi": -42,
        });

        let device = DeviceMeta::from_json(&item).expect("the item should parse");

        assert_eq!(device.mac, [0x00, 0x11, 0x22, 0x33, 0x44, 0x02]);
        assert_eq!(device.rssi, Some(-42));
        assert_eq!(device.last_seen_ms, Some(1_762_300_060_000));
    }

    #[test]
    fn a_file_with_no_observations_still_holds_a_header_and_an_interface() {
        let file = write(&[]);

        let blocks = blocks(&file).expect("the file should parse");
        assert_eq!(blocks.len(), 2);
        assert_eq!(blocks[0].kind, 0x0A0D_0D0A);
        assert_eq!(blocks[1].kind, 1);
    }
}
