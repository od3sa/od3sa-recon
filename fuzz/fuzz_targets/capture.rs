//! Fuzz target for a whole captured frame: radiotap header plus 802.11 frame.
//!
//! This is the shape the daemon sees on the wire: a radiotap header, whose
//! length (`it_len`) says where the 802.11 frame starts, followed by that
//! frame. The target drives the two steps separately as well as together:
//!
//! * `radiotap::parse` gives the header and its length,
//! * the bytes after that length are the 802.11 frame, and are dispatched
//!   with `frame::dispatch`,
//! * `frame::dispatch_capture` does both at once.
//!
//! The invariants asserted are the ones the contract states: the radiotap
//! header length covers the preamble and fits the buffer, and the two paths
//! agree on the frame they see.
//!
//! A violated invariant is a panic, and a panic fails the target.

#![no_main]

use libfuzzer_sys::fuzz_target;
use od3sa_parse::frame::FrameClass;
use od3sa_parse::ieee80211::FrameType;

/// The size of the radiotap preamble: `it_version`, `it_pad`, `it_len` and
/// `it_present`.
const PREAMBLE_LEN: usize = 8;

/// Frame type mask.
const FRAME_TYPE_MASK: u16 = 0x000c;
/// Frame type shift.
const FRAME_TYPE_SHIFT: u16 = 2;

fuzz_target!(|data: &[u8]| {
    // The radiotap header must parse, or report an error.
    let Ok(radiotap) = od3sa_parse::radiotap::parse(data) else {
        return;
    };

    let len = radiotap.len as usize;

    // `it_len` covers the preamble and never points past the buffer.
    assert!(len >= PREAMBLE_LEN, "it_len is shorter than the preamble");
    assert!(len <= data.len(), "it_len points past the buffer");

    // The 802.11 frame is what follows the radiotap header. It is dispatched
    // on its own here, so that the frame path is reached with the same
    // bytes the capture path would give it.
    let frame = &data[len..];
    let through_dispatch = od3sa_parse::frame::dispatch(frame);

    // The same capture through the one-call entry point. It must answer for
    // every input, and it must agree with the two-step path above.
    let through_capture = od3sa_parse::frame::dispatch_capture(data);

    match (&through_capture, &through_dispatch) {
        (Ok(capture_class), Ok(dispatch_class)) => {
            assert_eq!(
                class_kind(capture_class),
                class_kind(dispatch_class),
                "the capture path and the frame path must agree"
            );
        }
        (Err(_), Err(_)) => {}
        (capture_result, dispatch_result) => {
            // `dispatch_capture` reads the radiotap header itself and then
            // dispatches the rest, so the two paths must agree on whether
            // they succeed. If they do not, one of them is wrong.
            panic!(
                "the two paths disagree: capture ok = {}, dispatch ok = {}",
                capture_result.is_ok(),
                dispatch_result.is_ok()
            );
        }
    }

    // The class of a frame agrees with the frame type in its frame control
    // word.
    if let Ok(class) = &through_capture {
        let frame_control = match class {
            FrameClass::Management { header, .. } => header.frame_control,
            FrameClass::Control { header, .. } => header.frame_control,
            FrameClass::Data { header, .. } => header.frame_control,
            FrameClass::Extension { header } => header.frame_control,
            FrameClass::Unknown { header, .. } => header.frame_control,
        };
        let raw_type = (frame_control & FRAME_TYPE_MASK) >> FRAME_TYPE_SHIFT;
        match class {
            FrameClass::Management { .. } => assert_eq!(raw_type, 0),
            FrameClass::Control { .. } => assert_eq!(raw_type, 1),
            FrameClass::Data { .. } => assert_eq!(raw_type, 2),
            FrameClass::Extension { .. } => assert_eq!(raw_type, 3),
            FrameClass::Unknown { frame_type, .. } => assert!(*frame_type > 3),
        }

        // A control frame is the one the dispatcher hands to the control
        // header parser, because it is shorter than a MAC header.
        if let FrameClass::Control { header, .. } = class {
            assert_eq!(header.frame_type(), FrameType::Control);
        }
    }
});

/// The kind of a frame class, so that two results can be compared without
/// comparing every field.
fn class_kind(class: &FrameClass) -> u8 {
    match class {
        FrameClass::Management { .. } => 0,
        FrameClass::Control { .. } => 1,
        FrameClass::Data { .. } => 2,
        FrameClass::Extension { .. } => 3,
        FrameClass::Unknown { .. } => 4,
    }
}
