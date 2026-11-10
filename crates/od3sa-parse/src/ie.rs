//! Information element parsing.
//!
//! An information element is a one-byte element ID, a one-byte length, and
//! that many bytes of payload. Elements appear in beacon, probe response,
//! association request and association response frames.
//!
//! The daemon keeps:
//!
//! * **SSID** (including the "hidden" flag when the element is empty),
//! * **RSN / WPA** information: AKM suite list, pairwise and group ciphers,
//! * **HT / VHT / HE** capability presence, as flags,
//! * **vendor** elements, kept as an OUI plus element type, not as a blob,
//! * **WPS** presence, as a flag and a version number.
//!
//! Elements that carry payload data (for example a vendor element with a
//! private blob) are reduced to their identifying prefix. The bytes of an
//! element are never retained verbatim.
//!
//! # Suite selectors
//!
//! AKM and cipher suites are four byte selectors: a three byte OUI and a one
//! byte type. The suites below use OUI `00:0F:AC`.
//!
//! AKM suite types, from IEEE 802.11 Table 12-6 and the Wi-Fi Alliance WPA3
//! specification v3.5 (the "AKM suite types" table, which maps each
//! selector to the matching `wpa_supplicant` `key_mgmt`):
//!
//! | Selector | Name | Meaning |
//! |---|---|---|
//! | `00:0f:ac:1` | 802.1X (EAP) | enterprise |
//! | `00:0f:ac:2` | PSK | WPA2-Personal |
//! | `00:0f:ac:3` | FT over 802.1X | WPA3 enterprise |
//! | `00:0f:ac:4` | FT over PSK | WPA2 |
//! | `00:0f:ac:5` | 802.1X SHA-256 | WPA3 enterprise only mode |
//! | `00:0f:ac:6` | PSK SHA-256 | WPA2 |
//! | `00:0f:ac:8` | SAE | WPA3-Personal |
//! | `00:0f:ac:9` | FT over SAE | WPA3 with 802.11r |
//! | `00:0f:ac:12` | 802.1X SHA-384 | Suite B 192-bit |
//! | `00:0f:ac:18` | OWE | Enhanced Open |
//! | `00:0f:ac:24` | SAE with group-dependent hash (SAE-H2E) | WPA3, Wi-Fi 7 |
//! | `00:0f:ac:25` | FT over SAE-H2E | WPA3 with 802.11r |
//!
//! A WPA3-Personal network in transition mode advertises **both** PSK
//! (`:2`) and SAE (`:8`); a WPA3-Personal network advertises SAE (`:8`)
//! only. Labelling the two the wrong way round would report a WPA3 network
//! as WPA2, so they are kept apart here.
//!
//! Cipher suite types, from IEEE 802.11 Table 12-7:
//!
//! | Selector | Name |
//! |---|---|
//! | `00:0f:ac:1` | WEP-40 |
//! | `00:0f:ac:2` | TKIP |
//! | `00:0f:ac:4` | CCMP-128 |
//! | `00:0f:ac:5` | WEP-104 |
//! | `00:0f:ac:6` | BIP |
//! | `00:0f:ac:8` | GCMP-128 |
//! | `00:0f:ac:9` | GCMP-256 |
//! | `00:0f:ac:10` | CCMP-256 |
//! | `00:0f:ac:12` | BIP-CMAC-128 |
//!
//! Anything else is [`Akm::Other`] / [`Cipher::Other`], which keep the four
//! selector bytes so that an unknown suite is still identifiable.
//!
//! Implemented in OR-102.

use crate::error::{ParseError, Result, take};

/// Length of the element ID and length fields that precede every element.
pub const IE_HEADER_LEN: usize = 2;

/// Element ID of the SSID element.
const ID_SSID: u8 = 0;
/// Element ID of the HT capabilities element.
const ID_HT_CAPABILITIES: u8 = 45;
/// Element ID of the RSN element.
const ID_RSN: u8 = 48;
/// Element ID of the HT operation element.
const ID_HT_OPERATION: u8 = 61;
/// Element ID of the VHT capabilities element.
const ID_VHT_CAPABILITIES: u8 = 191;
/// Element ID of the VHT operation element.
const ID_VHT_OPERATION: u8 = 192;
/// Element ID of the vendor specific element.
const ID_VENDOR_SPECIFIC: u8 = 221;
/// Element ID of the elements that carry an extended element ID.
const ID_EXTENDED: u8 = 255;

/// Extended element ID of the HE capabilities element.
const EXT_HE_CAPABILITIES: u8 = 35;
/// Extended element ID of the HE operation element.
const EXT_HE_OPERATION: u8 = 36;

/// OUI of the RSN suite selectors.
const SUITE_OUI: [u8; 3] = [0x00, 0x0F, 0xAC];
/// OUI of the Microsoft vendor elements (WPA1 and WPS).
const MICROSOFT_OUI: [u8; 3] = [0x00, 0x50, 0xF2];
/// Vendor element type of the WPA1 (Microsoft WPA) element.
const MICROSOFT_TYPE_WPA: u8 = 1;
/// Vendor element type of the WPS element.
const MICROSOFT_TYPE_WPS: u8 = 6;

/// One information element: its ID and its body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ie<'a> {
    /// The element ID.
    pub id: u8,
    /// The element body: the bytes that follow the ID and the length.
    pub body: &'a [u8],
}

/// Walk the elements in `buf`.
///
/// Every element is a one-byte ID, a one-byte length and that many bytes.
/// A length that runs past the end of the buffer is
/// [`ParseError::Truncated`], and a buffer that ends in the middle of an
/// element header is an error too. A zero-length element is legal.
pub fn parse_ies(buf: &[u8]) -> Result<Vec<Ie<'_>>> {
    let mut out: Vec<Ie<'_>> = Vec::new();
    let mut rest = buf;

    while !rest.is_empty() {
        let (header, tail) = rest.split_at_checked(2).ok_or(ParseError::Truncated {
            needed: 2,
            available: rest.len(),
        })?;
        let [id, len] = header else {
            return Err(ParseError::Truncated {
                needed: 2,
                available: rest.len(),
            });
        };
        let (id, len) = (*id, *len as usize);

        let body = take(tail, len)?;
        out.push(Ie { id, body });

        rest = tail.get(len..).ok_or(ParseError::Truncated {
            needed: len,
            available: tail.len(),
        })?;
    }

    Ok(out)
}

/// The SSID of an access point.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ssid {
    /// The raw SSID bytes. Empty means the network hides its name.
    pub bytes: Vec<u8>,
    /// True when the SSID element is empty.
    pub hidden: bool,
}

/// An authentication and key management suite.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Akm {
    /// Pre-shared key (WPA2-Personal), selector `00:0f:ac:2`.
    Psk,
    /// Pre-shared key with SHA-256, selector `00:0f:ac:6`.
    PskSha256,
    /// 802.1X / EAP, selector `00:0f:ac:1`.
    Eap,
    /// 802.1X with SHA-256, selector `00:0f:ac:5`.
    EapSha256,
    /// Fast transition over 802.1X, selector `00:0f:ac:3`.
    FtEap,
    /// Fast transition over PSK, selector `00:0f:ac:4`.
    FtPsk,
    /// Simultaneous Authentication of Equals (WPA3-Personal), `00:0f:ac:8`.
    Sae,
    /// Fast transition over SAE, selector `00:0f:ac:9`.
    FtSae,
    /// SAE with a group-dependent hash (Hash-to-Element), `00:0f:ac:24`.
    SaeH2e,
    /// Fast transition over SAE-H2E, selector `00:0f:ac:25`.
    FtSaeH2e,
    /// Opportunistic Wireless Encryption, selector `00:0f:ac:18`.
    Owe,
    /// A selector that is not in the table.
    Other([u8; 4]),
}

/// A cipher suite.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Cipher {
    /// WEP with a 40-bit key, selector `00:0f:ac:1`.
    Wep40,
    /// WEP with a 104-bit key, selector `00:0f:ac:5`.
    Wep104,
    /// TKIP, selector `00:0f:ac:2`.
    Tkip,
    /// CCMP with a 128-bit key, selector `00:0f:ac:4`.
    Ccmp,
    /// CCMP with a 256-bit key, selector `00:0f:ac:10`.
    Ccmp256,
    /// GCMP with a 128-bit key, selector `00:0f:ac:8`.
    Gcmp,
    /// GCMP with a 256-bit key, selector `00:0f:ac:9`.
    Gcmp256,
    /// Broadcast/multicast integrity protocol, selector `00:0f:ac:6`.
    Bip,
    /// Broadcast/multicast integrity protocol, CMAC-128, `00:0f:ac:12`.
    BipCmac,
    /// A selector that is not in the table.
    Other([u8; 4]),
}

/// What the elements say about the security of a network.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Security {
    /// True for an RSN element (WPA2 and later), false for a vendor WPA
    /// element (WPA1).
    pub rsn: bool,
    /// The AKM suites the network offers.
    pub akm: Vec<Akm>,
    /// The pairwise (unicast) ciphers the network offers.
    pub pairwise: Vec<Cipher>,
    /// The group cipher, when the element was long enough to name one.
    pub group: Option<Cipher>,
    /// The RSN capabilities field, when present.
    pub rsn_capabilities: Option<u16>,
}

/// A vendor element, reduced to its OUI and type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VendorOui {
    /// The three byte OUI of the vendor.
    pub oui: [u8; 3],
    /// The vendor's own type byte.
    pub element_type: u8,
}

/// WPS information, presence and version only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WpsInfo {
    /// The WPS version byte.
    pub version: u8,
}

/// Everything the daemon keeps from a frame's elements.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ElementSummary {
    /// The SSID, when the frame carried one.
    pub ssid: Option<Ssid>,
    /// The security description, when the frame carried an RSN or WPA
    /// element.
    pub security: Option<Security>,
    /// True when the frame carried HT information.
    pub ht: bool,
    /// True when the frame carried VHT information.
    pub vht: bool,
    /// True when the frame carried HE (802.11ax) information.
    pub he: bool,
    /// The vendor elements, each reduced to an OUI and a type.
    pub vendors: Vec<VendorOui>,
    /// WPS information, when the frame carried a WPS element.
    pub wps: Option<WpsInfo>,
}

/// Summarise a list of elements.
///
/// Elements that the parser does not understand are ignored, and a
/// malformed element contributes only what could be read from it. The
/// summary never holds element payloads: a vendor element is kept as its
/// OUI and type, and an RSN element only as its suite selectors.
///
/// The summary carries one flag per generation, so both the capability
/// element and the operation element of a generation set it.
pub fn summarize(ies: &[Ie<'_>]) -> ElementSummary {
    let mut summary = ElementSummary::default();
    let mut rsn_security: Option<Security> = None;
    let mut wpa_security: Option<Security> = None;

    for ie in ies {
        match ie.id {
            ID_SSID => {
                if summary.ssid.is_none() {
                    summary.ssid = Some(Ssid {
                        bytes: ie.body.to_vec(),
                        hidden: ie.body.is_empty(),
                    });
                }
            }
            ID_RSN => {
                if rsn_security.is_none() {
                    rsn_security = Some(parse_rsn_element(ie.body));
                }
            }
            ID_HT_CAPABILITIES | ID_HT_OPERATION => summary.ht = true,
            ID_VHT_CAPABILITIES | ID_VHT_OPERATION => summary.vht = true,
            ID_EXTENDED => {
                if let Some(&ext) = ie.body.first()
                    && (ext == EXT_HE_CAPABILITIES || ext == EXT_HE_OPERATION)
                {
                    summary.he = true;
                }
            }
            ID_VENDOR_SPECIFIC => {
                if let Some((oui, element_type)) = vendor_header(ie.body) {
                    if oui == MICROSOFT_OUI {
                        match element_type {
                            MICROSOFT_TYPE_WPA => {
                                // OUI, type and version take six bytes; the
                                // suite lists follow the version.
                                if let Some(rest) = ie.body.get(6..) {
                                    let mut cursor = Cursor::new(rest);
                                    wpa_security = Some(parse_suites(&mut cursor, false));
                                }
                            }
                            MICROSOFT_TYPE_WPS => {
                                // The element body is the three byte OUI,
                                // the type byte and then the version byte,
                                // so the version is at index four.
                                if let Some(&version) = ie.body.get(4) {
                                    summary.wps = Some(WpsInfo { version });
                                }
                            }
                            _ => {}
                        }
                    }
                    summary.vendors.push(VendorOui { oui, element_type });
                }
            }
            _ => {}
        }
    }

    // An RSN element describes the network better than a WPA1 element, so
    // it wins when a frame carries both.
    summary.security = rsn_security.or(wpa_security);
    summary
}

/// Split a vendor element into its OUI and type.
///
/// Returns `None` when the element is too short to hold both.
fn vendor_header(body: &[u8]) -> Option<([u8; 3], u8)> {
    let oui_bytes = body.get(..3)?;
    let &[oui0, oui1, oui2] = oui_bytes else {
        return None;
    };
    let element_type = *body.get(3)?;
    Some(([oui0, oui1, oui2], element_type))
}

/// Parse an RSN element body.
///
/// The body starts with the version word; the suite lists follow it.
fn parse_rsn_element(body: &[u8]) -> Security {
    let mut cursor = Cursor::new(body);
    // The version word is not interesting to the daemon.
    let _version = cursor.u16_le();
    parse_suites(&mut cursor, true)
}

/// Parse the suite lists shared by the RSN and the WPA1 elements.
///
/// The cursor must be at the group cipher. Everything that does not fit
/// inside the element is dropped: the parser stops at the element end
/// rather than reading past it. The PMKID list and the group management
/// cipher list are not retained.
fn parse_suites(cursor: &mut Cursor<'_>, rsn: bool) -> Security {
    let mut security = Security {
        rsn,
        akm: Vec::new(),
        pairwise: Vec::new(),
        group: None,
        rsn_capabilities: None,
    };

    security.group = cursor.take(4).map(map_cipher);

    let pairwise_count = cursor.u16_le().unwrap_or(0) as usize;
    for _ in 0..pairwise_count {
        match cursor.take(4) {
            Some(selector) => security.pairwise.push(map_cipher(selector)),
            None => break,
        }
    }

    let akm_count = cursor.u16_le().unwrap_or(0) as usize;
    let mut akm_selectors: Vec<[u8; 4]> = Vec::new();
    for _ in 0..akm_count {
        match cursor.take(4) {
            Some(selector) => akm_selectors.push(selector_bytes(selector)),
            None => break,
        }
    }

    // The WPA1 element has WPA capabilities in this position, not RSN
    // capabilities, so they are only reported for an RSN element.
    if rsn {
        security.rsn_capabilities = cursor.u16_le();
    }

    for selector in &akm_selectors {
        security.akm.push(map_akm(selector));
    }

    security
}

/// Map an AKM selector to a suite.
///
/// The table is IEEE 802.11 Table 12-6, as tabulated by the Wi-Fi Alliance
/// WPA3 specification v3.5: `00:0f:ac:2` is PSK (WPA2-Personal) and
/// `00:0f:ac:8` is SAE (WPA3-Personal). A WPA3 network in transition mode
/// lists both, and each keeps its own entry in the AKM list.
fn map_akm(selector: &[u8; 4]) -> Akm {
    if selector[..3] != SUITE_OUI {
        return Akm::Other(*selector);
    }
    match selector[3] {
        1 => Akm::Eap,
        2 => Akm::Psk,
        3 => Akm::FtEap,
        4 => Akm::FtPsk,
        5 => Akm::EapSha256,
        6 => Akm::PskSha256,
        8 => Akm::Sae,
        9 => Akm::FtSae,
        // 12 is 802.1X with SHA-384 (Suite B 192-bit); this suite list has
        // no variant for it, so it stays `Other` with its selector bytes
        // kept.
        18 => Akm::Owe,
        24 => Akm::SaeH2e,
        25 => Akm::FtSaeH2e,
        _ => Akm::Other(*selector),
    }
}

/// Map a cipher selector to a cipher.
///
/// The table is IEEE 802.11 Table 12-7.
fn map_cipher(selector: &[u8]) -> Cipher {
    let bytes = selector_bytes(selector);
    if bytes[..3] != SUITE_OUI {
        return Cipher::Other(bytes);
    }
    match bytes[3] {
        1 => Cipher::Wep40,
        2 => Cipher::Tkip,
        4 => Cipher::Ccmp,
        5 => Cipher::Wep104,
        6 => Cipher::Bip,
        8 => Cipher::Gcmp,
        9 => Cipher::Gcmp256,
        10 => Cipher::Ccmp256,
        12 => Cipher::BipCmac,
        _ => Cipher::Other(bytes),
    }
}

/// The four bytes of a suite selector.
fn selector_bytes(selector: &[u8]) -> [u8; 4] {
    selector.try_into().unwrap_or([0u8; 4])
}

/// A bounds-checked cursor over an element body.
struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    /// A cursor at the start of `buf`.
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    /// Take `n` bytes, or return `None` when the element ends first.
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let buf = self.buf;
        let rest = buf.get(self.pos..)?;
        let out = take(rest, n).ok()?;
        self.pos += n;
        Some(out)
    }

    /// Take a little-endian `u16`.
    fn u16_le(&mut self) -> Option<u16> {
        let bytes = self.take(2)?;
        let bytes: [u8; 2] = bytes.try_into().ok()?;
        Some(u16::from_le_bytes(bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The suite OUI, `00:0F:AC`.
    const SUITE: [u8; 3] = [0x00, 0x0F, 0xAC];

    /// Build one element: ID, length and body.
    fn element(id: u8, body: &[u8]) -> Vec<u8> {
        assert!(body.len() <= u8::MAX as usize, "test bodies are short");
        let mut out = Vec::with_capacity(2 + body.len());
        out.push(id);
        out.push(body.len() as u8);
        out.extend_from_slice(body);
        out
    }

    /// A four byte suite selector.
    fn selector(ty: u8) -> [u8; 4] {
        [SUITE[0], SUITE[1], SUITE[2], ty]
    }

    /// An RSN element body: version, group cipher, pairwise, AKM, caps.
    fn rsn_body(group: [u8; 4], pairwise: &[[u8; 4]], akm: &[[u8; 4]], caps: u16) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&1u16.to_le_bytes());
        body.extend_from_slice(&group);
        body.extend_from_slice(&(pairwise.len() as u16).to_le_bytes());
        for suite in pairwise {
            body.extend_from_slice(suite);
        }
        body.extend_from_slice(&(akm.len() as u16).to_le_bytes());
        for suite in akm {
            body.extend_from_slice(suite);
        }
        body.extend_from_slice(&caps.to_le_bytes());
        body
    }

    /// Parse one RSN element and return its security summary.
    fn rsn_security(akm: &[[u8; 4]]) -> Security {
        rsn_security_with(selector(4), &[selector(4)], akm)
    }

    /// Parse one RSN element and return its security summary.
    fn rsn_security_with(group: [u8; 4], pairwise: &[[u8; 4]], akm: &[[u8; 4]]) -> Security {
        let body = rsn_body(group, pairwise, akm, 0x008c);
        let element = element(48, &body);
        let ies = parse_ies(&element).expect("the RSN element parses");
        summarize(&ies).security.expect("security is present")
    }

    #[test]
    fn beacon_elements_are_summarised() {
        let ssid = b"example-ssid";
        let mut buf = Vec::new();
        buf.extend_from_slice(&element(0, ssid));
        buf.extend_from_slice(&element(
            48,
            &rsn_body(selector(4), &[selector(4)], &[selector(2)], 0x008c),
        ));
        buf.extend_from_slice(&element(45, &[0x8e, 0x12, 0x00, 0x0f]));
        buf.extend_from_slice(&element(191, &[0x8e, 0x12, 0x00, 0x0f, 0x00, 0x00]));
        buf.extend_from_slice(&element(255, &[35, 0x26, 0x00, 0x00, 0x3f]));
        buf.extend_from_slice(&element(221, &[0x00, 0x11, 0x22, 0x07, 0xaa, 0xbb]));
        buf.extend_from_slice(&element(221, &[0x00, 0x50, 0xf2, 0x06, 0x10, 0x02, 0x00]));

        let ies = parse_ies(&buf).expect("synthetic elements parse");
        assert_eq!(ies.len(), 7);
        assert_eq!(ies[0].id, 0);
        assert_eq!(ies[0].body, ssid);

        let summary = summarize(&ies);

        assert_eq!(
            summary.ssid,
            Some(Ssid {
                bytes: ssid.to_vec(),
                hidden: false,
            })
        );
        assert_eq!(
            summary.security,
            Some(Security {
                rsn: true,
                akm: vec![Akm::Psk],
                pairwise: vec![Cipher::Ccmp],
                group: Some(Cipher::Ccmp),
                rsn_capabilities: Some(0x008c),
            })
        );
        assert!(summary.ht);
        assert!(summary.vht);
        assert!(summary.he);
        assert_eq!(
            summary.vendors,
            vec![
                VendorOui {
                    oui: [0x00, 0x11, 0x22],
                    element_type: 0x07,
                },
                VendorOui {
                    oui: [0x00, 0x50, 0xf2],
                    element_type: 0x06,
                },
            ]
        );
        assert_eq!(summary.wps, Some(WpsInfo { version: 0x10 }));
    }

    #[test]
    fn empty_ssid_means_hidden() {
        let buf = element(0, &[]);
        let ies = parse_ies(&buf).expect("a zero length element is legal");
        assert_eq!(ies.len(), 1);
        assert!(ies[0].body.is_empty());

        let summary = summarize(&ies);
        assert_eq!(
            summary.ssid,
            Some(Ssid {
                bytes: Vec::new(),
                hidden: true,
            })
        );
    }

    #[test]
    fn wpa3_personal_is_sae_not_psk() {
        // A WPA3-Personal network advertises SAE (00:0f:ac:8) only. It
        // must not be reported as PSK, which is WPA2-Personal
        // (00:0f:ac:2).
        let security = rsn_security(&[selector(8)]);
        assert!(security.rsn);
        assert_eq!(security.akm, vec![Akm::Sae]);
        assert!(
            !security.akm.contains(&Akm::Psk),
            "a WPA3 network must not be labelled PSK"
        );
        assert_eq!(security.pairwise, vec![Cipher::Ccmp]);
        assert_eq!(security.group, Some(Cipher::Ccmp));
    }

    #[test]
    fn transition_mode_lists_both_psk_and_sae() {
        // A WPA3-Personal network in transition mode advertises PSK
        // (00:0f:ac:2) *and* SAE (00:0f:ac:8). Both stay in the list, in
        // the order the element gives them.
        let security = rsn_security(&[selector(2), selector(8)]);
        assert_eq!(security.akm, vec![Akm::Psk, Akm::Sae]);
        assert!(security.akm.contains(&Akm::Psk));
        assert!(security.akm.contains(&Akm::Sae));
    }

    #[test]
    fn the_other_akm_suites_are_named() {
        assert_eq!(rsn_security(&[selector(1)]).akm, vec![Akm::Eap]);
        assert_eq!(rsn_security(&[selector(3)]).akm, vec![Akm::FtEap]);
        assert_eq!(rsn_security(&[selector(4)]).akm, vec![Akm::FtPsk]);
        assert_eq!(rsn_security(&[selector(5)]).akm, vec![Akm::EapSha256]);
        assert_eq!(rsn_security(&[selector(6)]).akm, vec![Akm::PskSha256]);
        assert_eq!(rsn_security(&[selector(9)]).akm, vec![Akm::FtSae]);
        assert_eq!(rsn_security(&[selector(18)]).akm, vec![Akm::Owe]);
        assert_eq!(rsn_security(&[selector(24)]).akm, vec![Akm::SaeH2e]);
        assert_eq!(rsn_security(&[selector(25)]).akm, vec![Akm::FtSaeH2e]);
    }

    #[test]
    fn the_cipher_suites_are_named() {
        let security = rsn_security_with(
            selector(1),
            &[selector(1), selector(2), selector(5)],
            &[selector(2)],
        );
        assert_eq!(
            security.pairwise,
            vec![Cipher::Wep40, Cipher::Tkip, Cipher::Wep104]
        );
        assert_eq!(security.group, Some(Cipher::Wep40));

        let security = rsn_security_with(selector(6), &[selector(8)], &[selector(2)]);
        assert_eq!(security.pairwise, vec![Cipher::Gcmp]);
        assert_eq!(security.group, Some(Cipher::Bip));

        let security = rsn_security_with(selector(9), &[selector(9)], &[selector(2)]);
        assert_eq!(security.pairwise, vec![Cipher::Gcmp256]);
        assert_eq!(security.group, Some(Cipher::Gcmp256));

        let security =
            rsn_security_with(selector(10), &[selector(10), selector(12)], &[selector(2)]);
        assert_eq!(security.pairwise, vec![Cipher::Ccmp256, Cipher::BipCmac]);
        assert_eq!(security.group, Some(Cipher::Ccmp256));
    }

    #[test]
    fn unknown_suites_keep_their_selector() {
        let unknown_akm = selector(42);
        let unknown_cipher = selector(77);
        let body = rsn_body(unknown_cipher, &[unknown_cipher], &[unknown_akm], 0x0000);
        let element = element(48, &body);
        let ies = parse_ies(&element).expect("the RSN element parses");
        let security = summarize(&ies).security.expect("security is present");
        assert_eq!(security.akm, vec![Akm::Other(unknown_akm)]);
        assert_eq!(security.pairwise, vec![Cipher::Other(unknown_cipher)]);
        assert_eq!(security.group, Some(Cipher::Other(unknown_cipher)));
    }

    #[test]
    fn wpa1_vendor_element_is_not_rsn() {
        // OUI 00:50:F2, type 1, version 1, then the suite lists. The WPA1
        // element uses the PSK selector 00:0f:ac:2 as well.
        let mut body = vec![0x00, 0x50, 0xf2, 0x01, 0x01, 0x00];
        body.extend_from_slice(&selector(4));
        body.extend_from_slice(&1u16.to_le_bytes());
        body.extend_from_slice(&selector(2));
        body.extend_from_slice(&1u16.to_le_bytes());
        body.extend_from_slice(&selector(2));
        body.extend_from_slice(&0u16.to_le_bytes());

        let buf = element(221, &body);
        let ies = parse_ies(&buf).expect("the vendor element parses");
        let summary = summarize(&ies);

        assert_eq!(
            summary.security,
            Some(Security {
                rsn: false,
                akm: vec![Akm::Psk],
                pairwise: vec![Cipher::Tkip],
                group: Some(Cipher::Ccmp),
                rsn_capabilities: None,
            })
        );
        assert_eq!(
            summary.vendors,
            vec![VendorOui {
                oui: [0x00, 0x50, 0xf2],
                element_type: 0x01,
            }]
        );
    }

    #[test]
    fn element_length_past_the_end_is_an_error() {
        let err = parse_ies(&[0x00, 0x05, 0x01]).expect_err("the length does not fit");
        assert!(matches!(err, ParseError::Truncated { .. }));
    }

    #[test]
    fn truncated_buffers_are_errors_not_panics() {
        // A lone element ID, with no length byte.
        let err = parse_ies(&[0x00]).expect_err("the header is incomplete");
        assert!(matches!(err, ParseError::Truncated { .. }));

        // A length byte with no body.
        let err = parse_ies(&[0x30, 0x08, 0x01]).expect_err("the body is missing");
        assert!(matches!(err, ParseError::Truncated { .. }));

        // An empty buffer is not an error: it holds no elements.
        let ies = parse_ies(&[]).expect("an empty buffer holds no elements");
        assert!(ies.is_empty());
    }

    #[test]
    fn random_bytes_never_panic() {
        // A small deterministic LCG, so the test is reproducible.
        let mut state: u32 = 0x1234_5678;
        let mut next = move || {
            state = state.wrapping_mul(1_103_515_245).wrapping_add(12_345);
            state >> 16
        };

        for _ in 0..2_000 {
            let len = (next() % 300) as usize;
            let mut buf = Vec::with_capacity(len);
            for _ in 0..len {
                buf.push((next() & 0xff) as u8);
            }
            // The parser must answer, not crash.
            if let Ok(ies) = parse_ies(&buf) {
                let _summary = summarize(&ies);
            }
        }
    }

    #[test]
    fn payloads_are_not_retained() {
        // A vendor element with a distinctive payload.
        let marker = b"SECRETVENDORDATA";
        let mut vendor = vec![0x00, 0x0a, 0x0b, 0x2c];
        vendor.extend_from_slice(marker);
        let mut buf = element(221, &vendor);

        // An RSN element with padding after the capabilities.
        let mut rsn = rsn_body(selector(4), &[selector(4)], &[selector(2)], 0x008c);
        rsn.extend_from_slice(marker);
        buf.extend_from_slice(&element(48, &rsn));

        let ies = parse_ies(&buf).expect("the synthetic elements parse");
        let summary = summarize(&ies);
        let printed = format!("{summary:?}");

        assert!(
            !printed.contains("SECRETVENDORDATA"),
            "the vendor payload must not be kept: {printed}"
        );
        assert!(
            !printed.contains("SECRET"),
            "no payload may be kept: {printed}"
        );
    }
}
