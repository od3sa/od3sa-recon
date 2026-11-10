//! Fuzz target for the frame dispatcher and the body classifier.
//!
//! The dispatcher looks at the frame control word and hands the frame to the
//! right sub-parser: a management frame, a control frame, a data frame or an
//! extension frame. The classifier looks at the first eight bytes of a data
//! body and tells an EAPOL frame from ordinary data.
//!
//! The invariants asserted are the ones the contract states:
//!
//! * the dispatcher never panics,
//! * the class of a frame agrees with the frame type in its frame control
//!   word,
//! * the body of a data frame is classified as EAPOL exactly when it starts
//!   with an LLC/SNAP header carrying the EAPOL EtherType.
//!
//! A violated invariant is a panic, and a panic fails the target.

#![no_main]

use libfuzzer_sys::fuzz_target;
use od3sa_parse::frame::{BodyKind, FrameClass};
use od3sa_parse::ieee80211::FrameType;

/// Frame type mask.
const FRAME_TYPE_MASK: u16 = 0x000c;
/// Frame type shift.
const FRAME_TYPE_SHIFT: u16 = 2;
/// Length of a MAC header without the address-4 field.
const MAC_HEADER_LEN: usize = 24;
/// Length of a MAC header with the address-4 field.
const MAC_HEADER_LEN_ADDR4: usize = 30;
/// The QoS bit of the subtype.
const QOS_BIT: u8 = 0x08;
/// The length of the QoS control field.
const QOS_CONTROL_LEN: usize = 2;
/// The first three bytes of an LLC/SNAP header: the LLC `AA AA 03`.
const LLC_SNAP_PREFIX: [u8; 3] = [0xAA, 0xAA, 0x03];
/// The EtherType of an EAPOL frame (IEEE 802.1X).
const ETHER_TYPE_EAPOL: u16 = 0x888E;

/// The bytes the dispatcher classifies: what follows the MAC header, with the
/// QoS control field of a QoS data frame removed.
fn payload_of<'a>(data: &'a [u8], header: &od3sa_parse::ieee80211::MacHeader) -> &'a [u8] {
    let header_len = if header.addr4.is_some() {
        MAC_HEADER_LEN_ADDR4
    } else {
        MAC_HEADER_LEN
    };

    let body = data.get(header_len..).unwrap_or(&[]);

    if header.subtype() & QOS_BIT != 0 {
        body.get(QOS_CONTROL_LEN..).unwrap_or(&[])
    } else {
        body
    }
}

fuzz_target!(|data: &[u8]| {
    // The body classifier must answer for every input.
    let kind = od3sa_parse::frame::classify_body(data);

    // An EAPOL body is an LLC/SNAP header with the EAPOL EtherType, and
    // nothing else is.
    let expected_eapol = data.len() >= 8
        && data[..3] == LLC_SNAP_PREFIX
        && u16::from_be_bytes([data[6], data[7]]) == ETHER_TYPE_EAPOL;
    match kind {
        BodyKind::Eapol => assert!(
            expected_eapol,
            "a body is EAPOL only with an LLC/SNAP header and the EAPOL EtherType"
        ),
        BodyKind::Data => assert!(
            data.len() >= 8 && data[..3] == LLC_SNAP_PREFIX,
            "an ordinary data body starts with an LLC/SNAP header"
        ),
        BodyKind::Other => assert!(
            !expected_eapol,
            "an EAPOL body is never classified as something else"
        ),
    }

    // The dispatcher must answer for every input.
    let Ok(class) = od3sa_parse::frame::dispatch(data) else {
        return;
    };

    match class {
        FrameClass::Management {
            header,
            subtype,
            ie_offset,
        } => {
            assert_eq!(header.frame_type(), FrameType::Management);
            assert_eq!(subtype, header.subtype());
            // The information element offset is the one the contract gives
            // for the subtype.
            assert_eq!(
                ie_offset,
                od3sa_parse::ieee80211::management_ie_offset(subtype)
            );
        }
        FrameClass::Control { header, subtype } => {
            assert_eq!(header.frame_type(), FrameType::Control);
            assert_eq!(subtype, header.subtype());
        }
        FrameClass::Data {
            header,
            mapping,
            body,
        } => {
            assert_eq!(header.frame_type(), FrameType::Data);
            // The mapping follows the two distribution system bits of the
            // frame control word.
            assert_eq!(mapping.to_ds, header.to_ds());
            assert_eq!(mapping.from_ds, header.from_ds());
            // A four-address frame has no BSSID: it carries the addresses of
            // the bridge that relayed it.
            if header.addr4.is_some() {
                assert!(
                    !mapping.bssid.is_some(),
                    "a four-address frame has no BSSID"
                );
            }
            // The body is classified from the bytes that follow the MAC
            // header, so an EAPOL body has an LLC/SNAP header with the EAPOL
            // EtherType at that offset.
            if body == BodyKind::Eapol {
                let payload = payload_of(data, &header);
                assert!(
                    payload.len() >= 8
                        && payload[..3] == LLC_SNAP_PREFIX
                        && u16::from_be_bytes([payload[6], payload[7]]) == ETHER_TYPE_EAPOL,
                    "an EAPOL body has an LLC/SNAP header with the EAPOL EtherType"
                );
            }
        }
        FrameClass::Extension { header } => {
            assert_eq!(header.frame_type(), FrameType::Extension);
        }
        FrameClass::Unknown { header, frame_type } => {
            assert_eq!(header.frame_type(), FrameType::Unknown(frame_type));
            // An unknown type is one of the values the standard does not
            // define.
            assert!(frame_type > 3, "a defined type is not unknown");
            assert_eq!(
                (header.frame_control & FRAME_TYPE_MASK) >> FRAME_TYPE_SHIFT,
                frame_type as u16
            );
        }
    }
});
