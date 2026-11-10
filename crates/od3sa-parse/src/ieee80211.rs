//! 802.11 MAC header and frame control parsing.
//!
//! The MAC header is 24 bytes (or 30 with the address-4 field), preceded by a
//! 2-byte frame control field. The parser extracts:
//!
//! * the frame type and subtype (management, control, data),
//! * the `ToDS` / `FromDS` bits, used to map a data frame to a client and a
//!   BSSID,
//! * the receiver (`addr1`), transmitter (`addr2`) and `addr3` addresses,
//! * the sequence control number,
//! * whether the frame is protected.
//!
//! Only the *header* is ever read. The payload that follows is skipped, never
//! copied out and never stored.
//!
//! # Frame control layout
//!
//! The frame control word is little-endian:
//!
//! ```text
//! bit  15 14 13 12 11 10  9  8  7  6  5  4  3  2  1  0
//!      Order Prot More Pwr Ret Frag From To  subtype  type  ver
//! ```
//!
//! * protocol version: bits 0..1 (`0x0003`)
//! * type: bits 2..3 (`0x000c`)
//! * subtype: bits 4..7 (`0x00f0`)
//! * To DS bit 8, From DS bit 9, More Fragments bit 10, Retry bit 11,
//!   Power Management bit 12, More Data bit 13, Protected bit 14, Order bit 15
//!
//! # Address 4
//!
//! There is no address-4 bit in the frame control. The presence of the fourth
//! address follows from the two distribution-system bits: a **data** frame
//! carries address 4 if and only if `To DS` and `From DS` are both set
//! (IEEE 802.11-2020, Table 9-30). A management frame never carries address
//! 4, whatever its `To DS` and `From DS` bits say.
//!
//! # Control frames
//!
//! A control frame has a shorter header than a MAC header: frame control,
//! duration and address 1 only, which is 10 bytes for ACK and CTS. Control
//! frames are parsed with [`ControlHeader`], not with [`MacHeader`].
//!
//! Implemented in OR-102.

use crate::error::{ParseError, Result, take};

/// Length of the frame control field.
pub const FRAME_CONTROL_LEN: usize = 2;

/// Length of a MAC header without the address-4 field.
pub const MAC_HEADER_LEN: usize = 24;

/// Length of a MAC header with the address-4 field.
pub const MAC_HEADER_LEN_ADDR4: usize = 30;

/// Length of the header of a control frame: frame control, duration and
/// address 1.
pub const CONTROL_HEADER_LEN: usize = 10;

/// Protocol version mask.
const PROTOCOL_VERSION_MASK: u16 = 0x0003;
/// Frame type mask.
const FRAME_TYPE_MASK: u16 = 0x000c;
/// Frame type shift.
const FRAME_TYPE_SHIFT: u16 = 2;
/// Subtype mask.
const SUBTYPE_MASK: u16 = 0x00f0;
/// Subtype shift.
const SUBTYPE_SHIFT: u16 = 4;
/// The `To DS` bit.
const TO_DS: u16 = 0x0100;
/// The `From DS` bit.
const FROM_DS: u16 = 0x0200;
/// The `Protected Frame` bit.
const PROTECTED_FRAME: u16 = 0x4000;
/// The frame control value of a data frame.
const FRAME_TYPE_DATA: u16 = 2 << FRAME_TYPE_SHIFT;

/// The frame type field of the frame control word.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameType {
    /// Type 0: management frames.
    Management,
    /// Type 1: control frames.
    Control,
    /// Type 2: data frames.
    Data,
    /// Type 3: extension frames.
    Extension,
    /// A type value outside the four defined ones.
    Unknown(u8),
}

impl FrameType {
    /// Map a raw type value to a [`FrameType`].
    fn from_bits(bits: u8) -> FrameType {
        match bits {
            0 => FrameType::Management,
            1 => FrameType::Control,
            2 => FrameType::Data,
            3 => FrameType::Extension,
            other => FrameType::Unknown(other),
        }
    }
}

/// The MAC header of a frame, without the frame body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MacHeader {
    /// The raw frame control word, little-endian on the wire.
    pub frame_control: u16,
    /// The duration field, in microseconds.
    pub duration: u16,
    /// Address 1: the receiver of the frame.
    pub addr1: [u8; 6],
    /// Address 2: the transmitter of the frame.
    pub addr2: [u8; 6],
    /// Address 3: the source for data frames, the BSSID for management frames.
    pub addr3: [u8; 6],
    /// Address 4, present only in a data frame with `To DS` and `From DS` both
    /// set.
    pub addr4: Option<[u8; 6]>,
    /// The sequence control field: a 4-bit fragment number and a 12-bit
    /// sequence number.
    pub sequence_control: u16,
}

impl MacHeader {
    /// Parse the MAC header at the start of `buf`.
    ///
    /// Only the header is read. The frame body that follows is not touched.
    /// A buffer that is shorter than the header the frame needs is a
    /// [`ParseError::Truncated`], never a panic.
    pub fn parse(buf: &[u8]) -> Result<MacHeader> {
        let fc = take(buf, FRAME_CONTROL_LEN)?;
        let frame_control = u16::from_le_bytes([fc[0], fc[1]]);

        // Address 4 is present only in a data frame with both distribution
        // system bits set; such a header is 30 bytes, every other MAC header
        // is 24 bytes.
        let has_addr4 = has_address_4(frame_control);

        let fixed = take(buf, MAC_HEADER_LEN)?;
        let duration = u16::from_le_bytes([fixed[2], fixed[3]]);
        let addr1 = read_mac(fixed, 4)?;
        let addr2 = read_mac(fixed, 10)?;
        let addr3 = read_mac(fixed, 16)?;
        let sequence_control = u16::from_le_bytes([fixed[22], fixed[23]]);

        let addr4 = if has_addr4 {
            let ext = take(buf, MAC_HEADER_LEN_ADDR4)?;
            Some(read_mac(ext, MAC_HEADER_LEN)?)
        } else {
            None
        };

        Ok(MacHeader {
            frame_control,
            duration,
            addr1,
            addr2,
            addr3,
            addr4,
            sequence_control,
        })
    }

    /// The frame type of this frame.
    pub fn frame_type(&self) -> FrameType {
        FrameType::from_bits(((self.frame_control & FRAME_TYPE_MASK) >> FRAME_TYPE_SHIFT) as u8)
    }

    /// The subtype within the frame type.
    pub fn subtype(&self) -> u8 {
        ((self.frame_control & SUBTYPE_MASK) >> SUBTYPE_SHIFT) as u8
    }

    /// The protocol version of this frame.
    pub fn protocol_version(&self) -> u8 {
        (self.frame_control & PROTOCOL_VERSION_MASK) as u8
    }

    /// The `To DS` bit: the frame is going towards the distribution system.
    pub fn to_ds(&self) -> bool {
        self.frame_control & TO_DS != 0
    }

    /// The `From DS` bit: the frame comes from the distribution system.
    pub fn from_ds(&self) -> bool {
        self.frame_control & FROM_DS != 0
    }

    /// The `Protected Frame` bit: the body of the frame is encrypted.
    pub fn is_protected(&self) -> bool {
        self.frame_control & PROTECTED_FRAME != 0
    }
}

/// The header of a control frame, which is shorter than a MAC header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ControlHeader {
    /// The raw frame control word, little-endian on the wire.
    pub frame_control: u16,
    /// The duration field, in microseconds.
    pub duration: u16,
    /// The receiver of the frame.
    pub addr1: [u8; 6],
}

impl ControlHeader {
    /// Parse a control frame header: frame control, duration and address 1.
    ///
    /// A control frame carries no second or third address. Only the ten
    /// header bytes are read; anything that follows them, such as the extra
    /// fields of an RTS frame, is not touched.
    pub fn parse(buf: &[u8]) -> Result<ControlHeader> {
        let fixed = take(buf, CONTROL_HEADER_LEN)?;
        let frame_control = u16::from_le_bytes([fixed[0], fixed[1]]);
        let duration = u16::from_le_bytes([fixed[2], fixed[3]]);
        let addr1 = read_mac(fixed, 4)?;

        Ok(ControlHeader {
            frame_control,
            duration,
            addr1,
        })
    }

    /// The subtype within the frame type.
    pub fn subtype(&self) -> u8 {
        ((self.frame_control & SUBTYPE_MASK) >> SUBTYPE_SHIFT) as u8
    }

    /// The frame type of this frame.
    pub fn frame_type(&self) -> FrameType {
        FrameType::from_bits(((self.frame_control & FRAME_TYPE_MASK) >> FRAME_TYPE_SHIFT) as u8)
    }
}

/// Whether a frame with this frame control word carries address 4.
///
/// Only a data frame does, and only when both distribution system bits are
/// set (IEEE 802.11-2020, Table 9-30).
fn has_address_4(frame_control: u16) -> bool {
    frame_control & FRAME_TYPE_MASK == FRAME_TYPE_DATA
        && frame_control & TO_DS != 0
        && frame_control & FROM_DS != 0
}

/// Read the six address bytes at `offset` in `buf`.
fn read_mac(buf: &[u8], offset: usize) -> Result<[u8; 6]> {
    let end = offset + 6;
    let slice = buf.get(offset..end).ok_or(ParseError::Truncated {
        needed: end,
        available: buf.len(),
    })?;
    slice
        .try_into()
        .map_err(|_| ParseError::Invalid("six byte address"))
}

/// The offset of the information elements inside a management frame body.
///
/// The offset is counted from the start of the frame body, that is from the
/// byte after the MAC header, and skips the fixed fields that precede the
/// information elements of that frame type.
///
/// * association request (0): 4 bytes, capability information and listen
///   interval,
/// * association response (1): 6 bytes, capability information, status code
///   and association id,
/// * reassociation request (2): 10 bytes, capability information, listen
///   interval and the current access point address,
/// * reassociation response (3): 6 bytes, capability information, status code
///   and association id,
/// * probe request (4): 0 bytes,
/// * probe response (5): 12 bytes, timestamp, beacon interval and capability
///   information,
/// * beacon (8): 12 bytes, timestamp, beacon interval and capability
///   information,
/// * disassociation (10): 2 bytes, the reason code,
/// * authentication (11): 6 bytes, algorithm, sequence number and status code,
/// * deauthentication (12): 2 bytes, the reason code,
/// * anything else: `None`.
pub fn management_ie_offset(subtype: u8) -> Option<usize> {
    match subtype {
        // Association request: capability information and listen interval.
        0 => Some(4),
        // Association response: capability information, status code and
        // association id.
        1 => Some(6),
        // Reassociation request: capability information, listen interval and
        // the current access point address.
        2 => Some(10),
        // Reassociation response: capability information, status code and
        // association id.
        3 => Some(6),
        // Probe request: no fixed fields.
        4 => Some(0),
        // Probe response and beacon: timestamp, beacon interval and capability
        // information.
        5 | 8 => Some(12),
        // Disassociation and deauthentication: reason code.
        10 | 12 => Some(2),
        // Authentication: algorithm, sequence number and status code.
        11 => Some(6),
        // ATIM, action frames and every other subtype have no fixed fields
        // that this parser knows about.
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A synthetic MAC address. Only the last byte varies, so every address
    /// in the tests is obviously fake.
    fn mac(last: u8) -> [u8; 6] {
        [0x00, 0x11, 0x22, 0x33, 0x44, last]
    }

    /// The frame control word of a management frame.
    fn mgmt_control(subtype: u8) -> u16 {
        (u16::from(subtype) << SUBTYPE_SHIFT) & SUBTYPE_MASK
    }

    /// The frame control word of a data frame.
    fn data_control(subtype: u8) -> u16 {
        FRAME_TYPE_DATA | ((u16::from(subtype) << SUBTYPE_SHIFT) & SUBTYPE_MASK)
    }

    /// Build the fixed fields of a MAC header: duration, three addresses and
    /// the sequence control field.
    fn fixed_fields() -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&0x0027u16.to_le_bytes()); // duration
        v.extend_from_slice(&mac(0x01)); // addr1
        v.extend_from_slice(&mac(0x02)); // addr2
        v.extend_from_slice(&mac(0x03)); // addr3
        v.extend_from_slice(&0x1234u16.to_le_bytes()); // sequence control
        v
    }

    /// A management frame of the given subtype, with a 12-byte fixed body
    /// after the header.
    fn management_frame(subtype: u8) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&mgmt_control(subtype).to_le_bytes());
        v.extend_from_slice(&fixed_fields());
        v.extend_from_slice(&[0u8; 12]); // fixed body, never read
        v
    }

    /// A data frame with the given distribution-system bits.
    fn data_frame(to_ds: bool, from_ds: bool) -> Vec<u8> {
        let mut frame_control = data_control(0);
        if to_ds {
            frame_control |= TO_DS;
        }
        if from_ds {
            frame_control |= FROM_DS;
        }
        let mut v = Vec::new();
        v.extend_from_slice(&frame_control.to_le_bytes());
        v.extend_from_slice(&fixed_fields());
        v
    }

    #[test]
    fn beacon_header_parses() {
        let frame = management_frame(8);
        let header = MacHeader::parse(&frame).expect("beacon header parses");

        assert_eq!(header.frame_control, mgmt_control(8));
        assert_eq!(header.frame_type(), FrameType::Management);
        assert_eq!(header.subtype(), 8);
        assert_eq!(header.protocol_version(), 0);
        assert_eq!(header.duration, 0x0027);
        assert_eq!(header.addr1, mac(0x01));
        assert_eq!(header.addr2, mac(0x02));
        assert_eq!(header.addr3, mac(0x03));
        assert_eq!(header.addr4, None);
        assert_eq!(header.sequence_control, 0x1234);
        assert!(!header.to_ds());
        assert!(!header.from_ds());
        assert!(!header.is_protected());
    }

    #[test]
    fn data_frame_flags_parse() {
        let frame = data_frame(true, false);
        let header = MacHeader::parse(&frame).expect("data header parses");

        assert_eq!(header.frame_type(), FrameType::Data);
        assert_eq!(header.subtype(), 0);
        assert!(header.to_ds());
        assert!(!header.from_ds());
        assert!(!header.is_protected());
        // Only one distribution system bit is set, so no address 4.
        assert_eq!(header.addr4, None);
    }

    #[test]
    fn data_frame_from_ds_only() {
        let frame = data_frame(false, true);
        let header = MacHeader::parse(&frame).expect("data header parses");

        assert!(!header.to_ds());
        assert!(header.from_ds());
        assert_eq!(header.addr4, None);
    }

    #[test]
    fn four_address_data_frame_has_addr4() {
        // A data frame with To DS and From DS both set carries address 4, so
        // its header is 30 bytes long.
        let mut frame = data_frame(true, true);
        frame.extend_from_slice(&mac(0x04)); // addr4

        let header = MacHeader::parse(&frame).expect("four address header parses");
        assert_eq!(header.frame_type(), FrameType::Data);
        assert!(header.to_ds());
        assert!(header.from_ds());
        assert_eq!(header.addr4, Some(mac(0x04)));
        assert_eq!(header.addr1, mac(0x01));
        assert_eq!(header.addr2, mac(0x02));
        assert_eq!(header.addr3, mac(0x03));
    }

    #[test]
    fn three_address_frame_has_no_addr4() {
        let frame = management_frame(8);
        let header = MacHeader::parse(&frame).expect("beacon header parses");
        assert_eq!(header.addr4, None);
    }

    #[test]
    fn management_frame_never_has_addr4() {
        // Both distribution system bits are set, but a management frame has
        // no address 4 and its header stays 24 bytes long.
        let frame_control = mgmt_control(8) | TO_DS | FROM_DS;
        let mut frame = Vec::new();
        frame.extend_from_slice(&frame_control.to_le_bytes());
        frame.extend_from_slice(&fixed_fields());
        // The bytes that would be address 4 in a data frame are part of the
        // frame body here.
        frame.extend_from_slice(&mac(0x04));

        let header = MacHeader::parse(&frame).expect("management header parses");
        assert_eq!(header.frame_type(), FrameType::Management);
        assert!(header.to_ds());
        assert!(header.from_ds());
        assert_eq!(header.addr4, None);
        assert_eq!(header.addr1, mac(0x01));
        assert_eq!(header.addr2, mac(0x02));
        assert_eq!(header.addr3, mac(0x03));
    }

    #[test]
    fn protected_bit_is_read_from_bit_14() {
        let frame_control = mgmt_control(8) | PROTECTED_FRAME;
        let mut frame = Vec::new();
        frame.extend_from_slice(&frame_control.to_le_bytes());
        frame.extend_from_slice(&fixed_fields());

        let header = MacHeader::parse(&frame).expect("header parses");
        assert!(header.is_protected());
        // The neighbouring flags stay clear.
        assert!(!header.to_ds());
        assert!(!header.from_ds());
    }

    #[test]
    fn unprotected_frame_is_not_protected() {
        let header = MacHeader::parse(&management_frame(8)).expect("header parses");
        assert!(!header.is_protected());
    }

    #[test]
    fn management_ie_offsets_match_the_contract() {
        assert_eq!(management_ie_offset(0), Some(4)); // association request
        assert_eq!(management_ie_offset(1), Some(6)); // association response
        assert_eq!(management_ie_offset(2), Some(10)); // reassociation request
        assert_eq!(management_ie_offset(3), Some(6)); // reassociation response
        assert_eq!(management_ie_offset(4), Some(0)); // probe request
        assert_eq!(management_ie_offset(5), Some(12)); // probe response
        assert_eq!(management_ie_offset(8), Some(12)); // beacon
        assert_eq!(management_ie_offset(10), Some(2)); // disassociation
        assert_eq!(management_ie_offset(11), Some(6)); // authentication
        assert_eq!(management_ie_offset(12), Some(2)); // deauthentication
    }

    #[test]
    fn management_ie_offset_is_none_for_other_subtypes() {
        // ATIM, action frames and action-no-ack have no known fixed fields.
        assert_eq!(management_ie_offset(9), None);
        assert_eq!(management_ie_offset(13), None);
        assert_eq!(management_ie_offset(14), None);
        // Reserved and out-of-range subtypes.
        assert_eq!(management_ie_offset(6), None);
        assert_eq!(management_ie_offset(7), None);
        assert_eq!(management_ie_offset(15), None);
        assert_eq!(management_ie_offset(200), None);
    }

    #[test]
    fn truncated_headers_are_an_error() {
        // Every prefix of a valid header must fail cleanly.
        let three_address = management_frame(8);
        for len in 0..MAC_HEADER_LEN {
            let err = MacHeader::parse(&three_address[..len]);
            assert!(err.is_err(), "prefix of length {len} must not parse");
        }
        // The full header parses.
        assert!(MacHeader::parse(&three_address[..MAC_HEADER_LEN]).is_ok());

        // And the same for the four-address form.
        let mut four_address = data_frame(true, true);
        four_address.extend_from_slice(&mac(0x04));
        for len in 0..MAC_HEADER_LEN_ADDR4 {
            let err = MacHeader::parse(&four_address[..len]);
            assert!(err.is_err(), "prefix of length {len} must not parse");
        }
        assert!(MacHeader::parse(&four_address[..MAC_HEADER_LEN_ADDR4]).is_ok());
    }

    #[test]
    fn empty_and_tiny_buffers_are_errors() {
        assert!(MacHeader::parse(&[]).is_err());
        assert!(MacHeader::parse(&[0x80]).is_err());
        assert!(MacHeader::parse(&[0x80, 0x00]).is_err());
    }

    #[test]
    fn control_header_parses() {
        // An ACK: type 1 (control), subtype 13.
        let frame_control: u16 = (1 << FRAME_TYPE_SHIFT) | (13 << SUBTYPE_SHIFT);
        let mut frame = Vec::new();
        frame.extend_from_slice(&frame_control.to_le_bytes());
        frame.extend_from_slice(&0x000au16.to_le_bytes()); // duration
        frame.extend_from_slice(&mac(0x01)); // address 1

        let header = ControlHeader::parse(&frame).expect("control header parses");
        assert_eq!(header.frame_control, frame_control);
        assert_eq!(header.duration, 0x000a);
        assert_eq!(header.addr1, mac(0x01));
        assert_eq!(header.subtype(), 13);
        assert_eq!(header.frame_type(), FrameType::Control);
    }

    #[test]
    fn control_header_truncation_is_an_error() {
        // A CTS frame: type 1 (control), subtype 12, ten header bytes.
        let frame_control: u16 = (1 << FRAME_TYPE_SHIFT) | (12 << SUBTYPE_SHIFT);
        let mut frame = Vec::new();
        frame.extend_from_slice(&frame_control.to_le_bytes());
        frame.extend_from_slice(&0x0010u16.to_le_bytes()); // duration
        frame.extend_from_slice(&mac(0x02)); // address 1

        for len in 0..CONTROL_HEADER_LEN {
            let err = ControlHeader::parse(&frame[..len]);
            assert!(err.is_err(), "prefix of length {len} must not parse");
        }
        assert!(ControlHeader::parse(&frame[..CONTROL_HEADER_LEN]).is_ok());
        // A MAC header parser cannot read a control frame.
        assert!(MacHeader::parse(&frame[..CONTROL_HEADER_LEN]).is_err());
    }

    #[test]
    fn no_payload_is_retained() {
        // The body of the frame carries a marker. It must not show up
        // anywhere in the parsed result.
        let mut frame = management_frame(8);
        frame.extend_from_slice(b"PAYLOADMARKER");
        let header = MacHeader::parse(&frame).expect("header parses");
        let rendered = format!("{header:?}");
        assert!(!rendered.contains("PAYLOADMARKER"));
    }

    /// A small deterministic linear congruential generator, so the fuzzing
    /// test is reproducible without pulling in a dependency.
    struct Lcg(u64);

    impl Lcg {
        fn new(seed: u64) -> Lcg {
            Lcg(seed)
        }

        fn next_u64(&mut self) -> u64 {
            self.0 = self
                .0
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            self.0
        }

        fn next_u8(&mut self) -> u8 {
            (self.next_u64() >> 24) as u8
        }
    }

    #[test]
    fn pseudo_random_input_never_panics() {
        let mut rng = Lcg::new(0x00d3_5a11_0000_0001);
        for _ in 0..4000 {
            let len = (rng.next_u64() % 64) as usize;
            let mut buf: Vec<u8> = Vec::with_capacity(len);
            for _ in 0..len {
                buf.push(rng.next_u8());
            }

            let parsed = MacHeader::parse(&buf);

            // The result is always one of the two, and it agrees with the
            // header length the frame calls for.
            let expected_len = if buf.len() >= 2 {
                let frame_control = u16::from_le_bytes([buf[0], buf[1]]);
                if has_address_4(frame_control) {
                    Some(MAC_HEADER_LEN_ADDR4)
                } else {
                    Some(MAC_HEADER_LEN)
                }
            } else {
                None
            };

            match (expected_len, parsed) {
                (None, Err(_)) => {}
                (None, Ok(_)) => panic!("a buffer shorter than the frame control must not parse"),
                (Some(required), Ok(header)) => {
                    assert!(buf.len() >= required);
                    assert_eq!(header.addr4.is_some(), required == MAC_HEADER_LEN_ADDR4);
                }
                (Some(required), Err(_)) => {
                    assert!(
                        buf.len() < required,
                        "a buffer long enough for the header must parse"
                    );
                }
            }

            // The control header parser and the helper must also stay total.
            let _ = ControlHeader::parse(&buf);
            let _ = management_ie_offset(rng.next_u8());
        }
    }
}
