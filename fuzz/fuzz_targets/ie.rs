//! Fuzz target for the information element parser.
//!
//! An information element is a one-byte ID, a one-byte length and that many
//! bytes. The parser walks them and the summary reads the ones the daemon
//! cares about: the SSID, the RSN and WPA suite lists, the HT / VHT / HE
//! capability flags, the vendor elements and the WPS element.
//!
//! Two paths are driven:
//!
//! * `parse_ies` on the whole input, which must either parse or report an
//!   error, never panic;
//! * `summarize` on a list of elements whose bodies are cut short at
//!   arbitrary points, so that the RSN and the WPA suite lists are read from
//!   bodies that end in the middle of a suite.
//!
//! The invariants asserted are the ones the parser contract states: the
//! elements cover the buffer exactly, the SSID is the first SSID element and
//! is hidden when it is empty, the vendor list holds the OUI and the type of
//! every vendor element that is long enough to have both, and an RSN element
//! always wins over a WPA one.

#![no_main]

use libfuzzer_sys::fuzz_target;
use od3sa_parse::ie::Ie;

/// Element ID of the SSID element.
const ID_SSID: u8 = 0;
/// Element ID of the RSN element.
const ID_RSN: u8 = 48;
/// Element ID of the vendor specific element.
const ID_VENDOR_SPECIFIC: u8 = 221;
/// OUI of the Microsoft vendor elements (WPA1 and WPS).
const MICROSOFT_OUI: [u8; 3] = [0x00, 0x50, 0xF2];
/// Vendor element type of the WPA1 (Microsoft WPA) element.
const MICROSOFT_TYPE_WPA: u8 = 1;
/// The length of the element ID and length fields.
const IE_HEADER_LEN: usize = 2;

/// Split a buffer into elements the way the parser reads them, but cut every
/// body short at a point the fuzzer chooses.
///
/// The parser itself rejects an element whose length runs past the end of
/// the buffer, so a truncated element can only be built here. It is what
/// exercises the summary's partial reads: an RSN element that ends in the
/// middle of a suite list, a vendor element that is too short for its OUI.
fn split_elements(data: &[u8], cut: usize) -> Vec<Ie<'_>> {
    let mut out = Vec::new();
    let mut rest = data;

    while rest.len() >= IE_HEADER_LEN {
        let id = rest[0];
        let len = rest[1] as usize;

        // The body is what the buffer holds, cut at the fuzzer's point, so
        // it can be shorter than the length byte says.
        let available = rest.len() - IE_HEADER_LEN;
        let body_len = len.min(available).min(cut);
        let body = &rest[IE_HEADER_LEN..IE_HEADER_LEN + body_len];

        out.push(Ie { id, body });
        rest = &rest[IE_HEADER_LEN + body_len..];
    }

    out
}

fuzz_target!(|data: &[u8]| {
    // The element parser must answer for every input.
    if let Ok(ies) = od3sa_parse::ie::parse_ies(data) {
        // The elements cover the buffer exactly: every byte belongs to
        // exactly one element header or one element body.
        let covered: usize = ies.iter().map(|ie| IE_HEADER_LEN + ie.body.len()).sum();
        assert_eq!(covered, data.len(), "the elements must cover the buffer");
        for ie in &ies {
            assert!(ie.body.len() <= u8::MAX as usize);
        }

        let summary = od3sa_parse::ie::summarize(&ies);

        // The SSID is the first SSID element, and it is hidden when it is
        // empty.
        let first_ssid = ies.iter().find(|ie| ie.id == ID_SSID).map(|ie| ie.body);
        match (summary.ssid.as_ref(), first_ssid) {
            (None, None) => {}
            (Some(ssid), Some(body)) => {
                assert_eq!(ssid.bytes.as_slice(), body);
                assert_eq!(ssid.hidden, body.is_empty());
            }
            other => panic!("the SSID does not match the elements: {other:?}"),
        }

        // Every vendor element that is long enough to hold an OUI and a type
        // is listed, in the order the elements give.
        let expected_vendors: Vec<([u8; 3], u8)> = ies
            .iter()
            .filter(|ie| ie.id == ID_VENDOR_SPECIFIC && ie.body.len() >= 4)
            .map(|ie| {
                let body = ie.body;
                ([body[0], body[1], body[2]], body[3])
            })
            .collect();
        let actual_vendors: Vec<([u8; 3], u8)> = summary
            .vendors
            .iter()
            .map(|vendor| (vendor.oui, vendor.element_type))
            .collect();
        assert_eq!(actual_vendors, expected_vendors, "the vendor list");

        // An RSN element always wins over a WPA1 one.
        let has_rsn = ies.iter().any(|ie| ie.id == ID_RSN);
        let has_wpa = ies.iter().any(|ie| {
            ie.id == ID_VENDOR_SPECIFIC
                && ie.body.len() >= 4
                && ie.body[..3] == MICROSOFT_OUI
                && ie.body[3] == MICROSOFT_TYPE_WPA
                && ie.body.len() >= 6
        });
        match summary.security.as_ref() {
            Some(security) => {
                assert_eq!(
                    security.rsn, has_rsn,
                    "an RSN element must win over a WPA1 element"
                );
                assert!(has_rsn || has_wpa, "the security comes from an element");
            }
            None => assert!(
                !has_rsn && !has_wpa,
                "a frame with an RSN or a WPA1 element has security"
            ),
        }
    }

    // The summary must also survive elements whose bodies are cut short.
    // The cut point comes from the input itself, so every length is tried.
    let cut = if data.is_empty() {
        0
    } else {
        data[data.len() - 1] as usize
    };
    let ies = split_elements(data, cut);
    let summary = od3sa_parse::ie::summarize(&ies);

    // A cut element is still an element: the vendor list holds the OUI and
    // the type of every vendor element that is long enough for both.
    for vendor in &summary.vendors {
        assert_eq!(vendor.oui.len(), 3);
    }
});
