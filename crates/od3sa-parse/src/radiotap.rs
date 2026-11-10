//! Radiotap header parsing.
//!
//! Radiotap is the pseudo-header that monitor-mode drivers prepend to every
//! captured frame. It is a variable-length list of fields, each with a fixed
//! size and a natural alignment, described by a bitmask in the first four
//! bytes.
//!
//! The daemon reads four things out of it:
//!
//! * **signal** (`DBM` field), converted to dBm,
//! * **channel** (`CHANNEL` field: centre frequency and driver flags),
//! * **rate** (`Rate` field, in units of 500 kbps),
//! * **flags** (`Flags` field), used for statistics only.
//!
//! Every other field is skipped: the parser walks the field bitmask and, for
//! fields it does not care about, advances by the size and alignment given in
//! the radiotap specification, without reading the contents.
//!
//! # Header layout
//!
//! The header starts with eight bytes, the preamble:
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |     it_version    |     it_pad        |            it_len |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                            it_present                           |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```
//!
//! `it_version` is a byte, `it_pad` is a byte, `it_len` is a little-endian
//! `u16` and `it_present` is a little-endian `u32`. `it_len` covers the whole
//! header, the eight preamble bytes included, so the 802.11 frame that
//! follows starts at `buf[it_len]`.
//!
//! # Field bit positions
//!
//! Bit positions in `it_present`, with the size and alignment the parser uses
//! to skip each one:
//!
//! | Bit | Field | Size | Alignment |
//! |-----|-------|------|-----------|
//! | 0 | TSFT | 8 | 8 |
//! | 1 | Flags | 1 | 1 |
//! | 2 | Rate | 1 | 1 |
//! | 3 | Channel | 4 | 2 |
//! | 4 | FHSS | 2 | 2 |
//! | 5 | DBM | 1 | 1 |
//! | 6 | Antenna | 1 | 1 |
//! | 7 | DBMSGI | 1 | 1 |
//! | 8 | MCS | 3 | 1 |
//! | 9 | AMPDU | 4 | 4 |
//! | 10 | VHT | 12 | 2 |
//! | 11 | TIMESTAMP | 8 | 8 |
//! | 12 | HE | 12 | 2 |
//! | 13 | HE-MU | 12 | 2 |
//! | 14 | 0-length PSDU | 2 | 2 |
//! | 15 | L-SIG | 4 | 2 |
//!
//! # Fields this parser cannot size
//!
//! Bit 16 (the radiotap TLV), bits 17 to 19 (the radiotap and vendor
//! namespaces and the namespace extension), bits 29 and 30 and bit 31 (the
//! extension bit) describe variable-length data: their length cannot be
//! known without parsing them.
//!
//! They are not an error. Radiotap fields appear in the header in bit order,
//! so the flags (bit 1), rate (bit 2), channel (bit 3) and DBM (bit 5) fields
//! are always read before any of them. When the walk reaches a bit whose size
//! is unknown it stops and the header is returned with the fields read so
//! far, so a frame is never thrown away over a field the daemon does not use.
//!
//! The extension bit is a special case: it means that another 32-bit present
//! word follows the first one, before any field. The parser reads those extra
//! words so that the fields still start at the right offset, and ignores
//! their contents: the fields they describe belong to a namespace this parser
//! does not know. If the header is too short to hold them, the extension is
//! ignored and the fields are read at their plain offsets.
//!
//! # Safety
//!
//! The parser never panics. Every length is bounds-checked against the buffer
//! and against the header length before it is used, and no field that does
//! not fit inside the header is read.
//!
//! Implemented in OR-101.

use crate::error::{ParseError, Result, take};

/// The length of the `it_present` bitmask.
pub const PRESENT_MASK_LEN: usize = 4;

/// The size of the radiotap preamble: `it_version`, `it_pad`, `it_len` and
/// `it_present`.
const PREAMBLE_LEN: usize = 8;

/// The bit of `it_present` that means "another present word follows".
const EXT_BIT: u32 = 1 << 31;

/// The most present words the parser reads before giving up.
const MAX_PRESENT_WORDS: usize = 16;

/// The size and natural alignment of every fixed-size radiotap field, indexed
/// by its bit position in `it_present`.
///
/// Bits 16 and up are absent on purpose: they have no fixed size.
const FIELDS: [(usize, usize); 16] = [
    (8, 8),  // 0: TSFT
    (1, 1),  // 1: Flags
    (1, 1),  // 2: Rate
    (4, 2),  // 3: Channel
    (2, 2),  // 4: FHSS
    (1, 1),  // 5: DBM
    (1, 1),  // 6: Antenna
    (1, 1),  // 7: DBMSGI
    (3, 1),  // 8: MCS
    (4, 4),  // 9: AMPDU
    (12, 2), // 10: VHT
    (8, 8),  // 11: TIMESTAMP
    (12, 2), // 12: HE
    (12, 2), // 13: HE-MU
    (2, 2),  // 14: 0-length PSDU
    (4, 2),  // 15: L-SIG
];

/// The bit of `it_present` that carries the flags byte.
const BIT_FLAGS: u32 = 1;
/// The bit of `it_present` that carries the data rate.
const BIT_RATE: u32 = 2;
/// The bit of `it_present` that carries the channel.
const BIT_CHANNEL: u32 = 3;
/// The bit of `it_present` that carries the signal level in dBm.
const BIT_DBM: u32 = 5;

/// The radiotap header of a captured frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RadiotapHeader {
    /// Total header length, as stated by `it_len` (includes the 8-byte preamble).
    pub len: u16,
    /// The `it_present` bitmask.
    pub present: u32,
    /// `it_version`; 0 for every header in the wild.
    pub version: u8,
    /// Signal strength in dBm, from the `DBM` field.
    pub signal_dbm: Option<i8>,
    /// Channel, from the `CHANNEL` field.
    pub channel: Option<Channel>,
    /// Data rate in units of 500 kbps, from the `Rate` field.
    pub rate: Option<u8>,
    /// Radiotap flags byte, from the `Flags` field.
    pub flags: Option<u8>,
}

/// The channel a frame was seen on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Channel {
    /// Centre frequency in MHz.
    pub freq_mhz: u16,
    /// The channel flags the driver reported.
    pub flags: u16,
}

/// Parse the radiotap header at the start of `buf`.
///
/// `buf` may hold more than the header: the 802.11 frame follows it. Only
/// the header is read, and nothing outside it is ever interpreted.
///
/// Returns an error, never a panic, for a malformed header.
pub fn parse(buf: &[u8]) -> Result<RadiotapHeader> {
    if buf.len() < PREAMBLE_LEN {
        return Err(ParseError::TooShort {
            expected: PREAMBLE_LEN,
            available: buf.len(),
        });
    }

    let version = slice_at(buf, 0, 1)?[0];
    let it_len = u16_le(slice_at(buf, 2, 2)?)? as usize;
    let present = u32_le(slice_at(buf, 4, 4)?)?;

    if it_len < PREAMBLE_LEN {
        return Err(ParseError::Invalid(
            "radiotap it_len is shorter than the 8-byte preamble",
        ));
    }
    if it_len > buf.len() {
        return Err(ParseError::Truncated {
            needed: it_len,
            available: buf.len(),
        });
    }

    // The present words come first, before any field. The extension bit means
    // that another present word follows. Those extra words describe namespace
    // fields, which have no fixed size, so they are read for their length and
    // then ignored. If the header is too short to hold them, the extension is
    // ignored as well and the fields are read at their plain offsets.
    let mut offset = PREAMBLE_LEN;
    let mut current = present;
    for _ in 0..MAX_PRESENT_WORDS {
        if current & EXT_BIT == 0 {
            break;
        }
        if offset + 4 > it_len {
            break;
        }
        current = u32_le(slice_at(buf, offset, 4)?)?;
        offset += 4;
    }

    let mut signal_dbm = None;
    let mut channel = None;
    let mut rate = None;
    let mut flags = None;

    // Walk the fields in ascending bit order, which is the order they appear
    // in the header. Only the first present word is interpreted; the extra
    // words of an extended header describe namespace fields, whose size is
    // unknown, so they are read for their length and then ignored.
    'walk: {
        let mut remaining = present;
        while remaining != 0 {
            let bit = remaining.trailing_zeros();
            remaining &= remaining - 1;

            let (size, align) = match FIELDS.get(bit as usize) {
                Some(spec) => *spec,
                // A field of unknown size: the TLV, the namespaces and the
                // extension bit. Everything the daemon reads is below bit 16,
                // so the walk stops here and the fields read so far are
                // returned.
                None => break 'walk,
            };

            // Padding is inserted before a field whose alignment is not
            // satisfied, measured from the start of the header.
            let padding = (align - (offset % align)) % align;
            offset += padding;

            let end = offset + size;
            if end > it_len {
                return Err(ParseError::Truncated {
                    needed: end,
                    available: it_len,
                });
            }
            let data = slice_at(buf, offset, size)?;

            match bit {
                BIT_FLAGS => flags = Some(data[0]),
                BIT_RATE => rate = Some(data[0]),
                BIT_CHANNEL => {
                    let freq = u16_le(&data[0..2])?;
                    let channel_flags = u16_le(&data[2..4])?;
                    channel = Some(Channel {
                        freq_mhz: freq,
                        flags: channel_flags,
                    });
                }
                BIT_DBM => signal_dbm = Some(i8::from_le_bytes([data[0]])),
                _ => {}
            }

            offset = end;
        }
    }

    Ok(RadiotapHeader {
        len: it_len as u16,
        present,
        version,
        signal_dbm,
        channel,
        rate,
        flags,
    })
}

/// The 802.11 channel number for a centre frequency, if there is one.
///
/// * 2.4 GHz: 2412 to 2472 MHz are channels 1 to 13, 2484 MHz is channel 14.
/// * 5 GHz: 5000 to 5900 MHz map to `(freq - 5000) / 5`.
/// * 6 GHz: 5955 to 7115 MHz map to `(freq - 5950) / 5`.
///
/// Any other frequency, and any frequency that is not a channel centre, gives
/// `None`.
pub fn channel_number(freq_mhz: u16) -> Option<u16> {
    match freq_mhz {
        2412..=2472 if (freq_mhz - 2407).is_multiple_of(5) => Some((freq_mhz - 2407) / 5),
        2484 => Some(14),
        5000..=5900 if freq_mhz > 5000 && (freq_mhz - 5000).is_multiple_of(5) => {
            Some((freq_mhz - 5000) / 5)
        }
        5955..=7115 if (freq_mhz - 5950).is_multiple_of(5) => Some((freq_mhz - 5950) / 5),
        _ => None,
    }
}

/// Borrow `len` bytes at `start`, or fail with [`ParseError::Truncated`].
fn slice_at(buf: &[u8], start: usize, len: usize) -> Result<&[u8]> {
    let rest = buf.get(start..).ok_or(ParseError::Truncated {
        needed: start.saturating_add(len),
        available: buf.len(),
    })?;
    take(rest, len)
}

/// Read a little-endian `u16` from the front of `buf`.
fn u16_le(buf: &[u8]) -> Result<u16> {
    let bytes = take_exact::<2>(buf)?;
    Ok(u16::from_le_bytes(bytes))
}

/// Read a little-endian `u32` from the front of `buf`.
fn u32_le(buf: &[u8]) -> Result<u32> {
    let bytes = take_exact::<4>(buf)?;
    Ok(u32::from_le_bytes(bytes))
}

/// Borrow exactly `N` bytes from the front of `buf`.
fn take_exact<const N: usize>(buf: &[u8]) -> Result<[u8; N]> {
    let slice = take(buf, N)?;
    slice.try_into().map_err(|_| ParseError::Truncated {
        needed: N,
        available: slice.len(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The preamble length the synthetic builder assumes.
    const PREAMBLE: usize = PREAMBLE_LEN;

    /// Builds a synthetic radiotap header, padding fields the way the
    /// alignment rules require. Every value is made up.
    struct HeaderBuilder {
        present: u32,
        body: Vec<u8>,
    }

    impl HeaderBuilder {
        fn new() -> Self {
            Self {
                present: 0,
                body: Vec::new(),
            }
        }

        /// Append a field of `size` bytes with natural alignment `align`.
        fn field(&mut self, bit: u32, size: usize, align: usize, data: &[u8]) -> &mut Self {
            assert_eq!(data.len(), size);
            let offset = PREAMBLE + self.body.len();
            let padding = (align - (offset % align)) % align;
            self.body.resize(self.body.len() + padding, 0);
            self.body.extend_from_slice(data);
            self.present |= 1 << bit;
            self
        }

        fn tsft(&mut self, value: u64) -> &mut Self {
            self.field(0, 8, 8, &value.to_le_bytes())
        }

        fn flags(&mut self, value: u8) -> &mut Self {
            self.field(1, 1, 1, &[value])
        }

        fn rate(&mut self, value: u8) -> &mut Self {
            self.field(2, 1, 1, &[value])
        }

        fn channel(&mut self, freq_mhz: u16, channel_flags: u16) -> &mut Self {
            let mut data = [0u8; 4];
            data[0..2].copy_from_slice(&freq_mhz.to_le_bytes());
            data[2..4].copy_from_slice(&channel_flags.to_le_bytes());
            self.field(3, 4, 2, &data)
        }

        fn dbm(&mut self, value: i8) -> &mut Self {
            self.field(5, 1, 1, &value.to_le_bytes())
        }

        /// The finished header, with `it_len` and `it_present` filled in.
        fn build(&self) -> Vec<u8> {
            let total = PREAMBLE + self.body.len();
            let mut out = Vec::with_capacity(total);
            out.push(0u8); // it_version
            out.push(0u8); // it_pad
            out.extend_from_slice(&(total as u16).to_le_bytes());
            out.extend_from_slice(&self.present.to_le_bytes());
            out.extend_from_slice(&self.body);
            out
        }
    }

    /// Unwrap a parse result, panicking with the error when it failed.
    fn ok(result: Result<RadiotapHeader>) -> RadiotapHeader {
        match result {
            Ok(header) => header,
            Err(err) => panic!("expected a successful parse, got {err}"),
        }
    }

    #[test]
    fn minimal_header_parses_signal_only() {
        let header = HeaderBuilder::new().dbm(-70).build();

        let parsed = ok(parse(&header));

        assert_eq!(parsed.version, 0);
        assert_eq!(parsed.present, 1 << BIT_DBM);
        assert_eq!(parsed.len as usize, header.len());
        assert_eq!(parsed.signal_dbm, Some(-70));
        assert_eq!(parsed.channel, None);
        assert_eq!(parsed.rate, None);
        assert_eq!(parsed.flags, None);
    }

    #[test]
    fn multi_field_header_parses_every_interpreted_field() {
        let header = HeaderBuilder::new()
            .tsft(0x0102_0304_0506_0708)
            .flags(0x41)
            .rate(2)
            .channel(2437, 0x0001)
            .dbm(-42)
            .build();

        let parsed = ok(parse(&header));

        assert_eq!(parsed.signal_dbm, Some(-42));
        assert_eq!(
            parsed.channel,
            Some(Channel {
                freq_mhz: 2437,
                flags: 0x0001
            })
        );
        assert_eq!(parsed.rate, Some(2));
        assert_eq!(parsed.flags, Some(0x41));
        assert_eq!(parsed.len as usize, header.len());
    }

    #[test]
    fn padding_before_the_channel_field_is_skipped() {
        // The channel field is 2-byte aligned. After the TSFT and the flags
        // byte the offset is odd, so one byte of padding goes in front of it.
        let header = HeaderBuilder::new()
            .tsft(1)
            .flags(0x10)
            .channel(5180, 0x0040)
            .dbm(-55)
            .build();

        let parsed = ok(parse(&header));

        assert_eq!(
            parsed.channel,
            Some(Channel {
                freq_mhz: 5180,
                flags: 0x0040
            })
        );
        assert_eq!(parsed.flags, Some(0x10));
        assert_eq!(parsed.signal_dbm, Some(-55));
    }

    #[test]
    fn header_length_beyond_the_buffer_is_an_error() {
        let mut header = HeaderBuilder::new().dbm(-50).build();
        header[2..4].copy_from_slice(&999u16.to_le_bytes());

        assert!(parse(&header).is_err());
    }

    #[test]
    fn header_length_below_the_preamble_is_an_error() {
        let mut header = HeaderBuilder::new().dbm(-50).build();
        header[2..4].copy_from_slice(&4u16.to_le_bytes());

        assert!(parse(&header).is_err());
    }

    #[test]
    fn every_truncation_of_a_header_is_an_error() {
        let header = HeaderBuilder::new()
            .tsft(1)
            .flags(0x41)
            .rate(2)
            .channel(2412, 0)
            .dbm(-30)
            .build();

        for cut in 0..header.len() {
            assert!(
                parse(&header[..cut]).is_err(),
                "a header cut to {cut} bytes should not parse"
            );
        }
    }

    #[test]
    fn pseudo_random_bytes_never_panic() {
        let mut state: u32 = 0x1234_5678;
        let mut next = move || {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            state
        };

        for len in 0..300usize {
            let mut buf = Vec::with_capacity(len);
            for _ in 0..len {
                buf.push((next() >> 24) as u8);
            }
            if let Ok(header) = parse(&buf) {
                assert!(header.len >= 8);
            }
        }
    }

    #[test]
    fn channel_number_maps_known_frequencies() {
        assert_eq!(channel_number(2412), Some(1));
        assert_eq!(channel_number(2437), Some(6));
        assert_eq!(channel_number(2484), Some(14));
        assert_eq!(channel_number(5180), Some(36));
        assert_eq!(channel_number(5745), Some(149));
        assert_eq!(channel_number(5955), Some(1));
        assert_eq!(channel_number(7115), Some(233));
        assert_eq!(channel_number(1000), None);
    }

    #[test]
    fn channel_number_rejects_frequencies_outside_the_bands() {
        assert_eq!(channel_number(0), None);
        assert_eq!(channel_number(2400), None);
        assert_eq!(channel_number(2480), None);
        assert_eq!(channel_number(3000), None);
        assert_eq!(channel_number(5925), None);
        assert_eq!(channel_number(7120), None);
    }

    #[test]
    fn fields_of_unknown_size_stop_the_walk_without_failing() {
        // The TLV, the namespaces and the namespace extension have no fixed
        // size, but they come after every field this parser reads, so the
        // header still parses and the fields below them are still there.
        for bit in [16u32, 17, 18, 19, 29, 30] {
            let mut header = HeaderBuilder::new().dbm(-40).build();
            let present = (1u32 << bit) | (1 << BIT_DBM);
            header[4..8].copy_from_slice(&present.to_le_bytes());
            let parsed = ok(parse(&header));
            assert_eq!(parsed.signal_dbm, Some(-40));
        }
    }

    #[test]
    fn the_extension_bit_means_more_present_words() {
        // One extra present word, then the DBM field.
        let mut header = Vec::new();
        header.push(0u8); // it_version
        header.push(0u8); // it_pad
        header.extend_from_slice(&13u16.to_le_bytes()); // it_len
        header.extend_from_slice(&(EXT_BIT | (1 << BIT_DBM)).to_le_bytes());
        header.extend_from_slice(&0u32.to_le_bytes()); // the extra present word
        header.push(0xc4); // DBM: -60

        let parsed = ok(parse(&header));

        assert_eq!(parsed.signal_dbm, Some(-60));
        assert_eq!(parsed.len, 13);
    }

    #[test]
    fn an_extension_bit_with_no_room_for_the_extra_word_is_not_fatal() {
        // The header is too short to hold the second present word the
        // extension bit promises. The fields are still read at their plain
        // offsets rather than the frame being thrown away.
        let mut header = Vec::new();
        header.push(0u8); // it_version
        header.push(0u8); // it_pad
        header.extend_from_slice(&9u16.to_le_bytes()); // it_len
        header.extend_from_slice(&(EXT_BIT | (1 << BIT_DBM)).to_le_bytes());
        header.push(0xc4); // DBM: -60

        let parsed = ok(parse(&header));

        assert_eq!(parsed.signal_dbm, Some(-60));
        assert_eq!(parsed.len, 9);
    }

    #[test]
    fn nothing_outside_the_header_is_retained() {
        let mut frame = HeaderBuilder::new().dbm(-33).build();
        frame.extend_from_slice(b"PAYLOAD-MARKER-NOT-KEPT");

        let parsed = ok(parse(&frame));

        let rendered = format!("{parsed:?}");
        assert!(!rendered.contains("PAYLOAD-MARKER-NOT-KEPT"));
    }
}
