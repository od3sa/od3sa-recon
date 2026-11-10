//! Fuzz target for the 802.11 MAC header and control header parsers.
//!
//! Both headers are read out of the front of the buffer, and both have a
//! length that depends on the frame control word: a MAC header is 24 bytes,
//! or 30 when the frame carries the address-4 field, and a control header
//! is ten bytes. The address-4 rule is the interesting one, because it
//! follows from the two distribution system bits rather than from a bit of
//! its own.
//!
//! The target asserts that:
//!
//! * neither parser panics,
//! * the address-4 field is present exactly for a data frame with both
//!   distribution system bits set,
//! * the frame type, the subtype and the flags agree with the raw frame
//!   control word.
//!
//! A violated invariant is a panic, and a panic fails the target.

#![no_main]

use libfuzzer_sys::fuzz_target;
use od3sa_parse::ieee80211::FrameType;

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

/// The frame type the raw frame control bits name.
fn expected_frame_type(frame_control: u16) -> FrameType {
    match ((frame_control & FRAME_TYPE_MASK) >> FRAME_TYPE_SHIFT) as u8 {
        0 => FrameType::Management,
        1 => FrameType::Control,
        2 => FrameType::Data,
        3 => FrameType::Extension,
        other => FrameType::Unknown(other),
    }
}

fuzz_target!(|data: &[u8]| {
    // The MAC header parser must answer for every input.
    if let Ok(header) = od3sa_parse::ieee80211::MacHeader::parse(data) {
        let fc = header.frame_control;

        // The address-4 field is present if and only if the frame is a data
        // frame with both distribution system bits set.
        let has_addr4 =
            fc & FRAME_TYPE_MASK == FRAME_TYPE_DATA && fc & TO_DS != 0 && fc & FROM_DS != 0;
        assert_eq!(
            header.addr4.is_some(),
            has_addr4,
            "the address-4 field follows the two distribution system bits"
        );

        // The parsed flags agree with the raw frame control word.
        assert_eq!(header.to_ds(), fc & TO_DS != 0);
        assert_eq!(header.from_ds(), fc & FROM_DS != 0);
        assert_eq!(header.is_protected(), fc & PROTECTED_FRAME != 0);

        // The subtype, the protocol version and the frame type are the bits
        // they claim to be.
        assert_eq!(
            header.subtype(),
            ((fc & SUBTYPE_MASK) >> SUBTYPE_SHIFT) as u8
        );
        assert_eq!(
            header.protocol_version(),
            (fc & PROTOCOL_VERSION_MASK) as u8
        );
        assert_eq!(header.frame_type(), expected_frame_type(fc));
    }

    // The control header parser must answer too. It reads ten bytes, so it
    // succeeds on any buffer of ten bytes or more.
    if let Ok(header) = od3sa_parse::ieee80211::ControlHeader::parse(data) {
        let fc = header.frame_control;
        assert_eq!(
            header.subtype(),
            ((fc & SUBTYPE_MASK) >> SUBTYPE_SHIFT) as u8
        );
        // The control header parser does not insist on a control frame: it
        // is used to peek at the frame type, so it reports the type of any
        // frame control word it is given.
        assert_eq!(header.frame_type(), expected_frame_type(fc));
    }
});
