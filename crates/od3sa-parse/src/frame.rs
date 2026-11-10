//! Top-level frame dispatch.
//!
//! Given a captured frame (radiotap header plus 802.11 frame), this module
//! decides what kind of frame it is and hands it to the right sub-parser:
//!
//! * **management** frames: beacon, probe request and response, association
//!   request and response, authentication, deauthentication and disassociation.
//!   These are *observed* only; the daemon never reacts to them by
//!   transmitting anything.
//! * **control** frames: counted, not detailed. They are parsed with
//!   [`ControlHeader`], because a control frame is shorter than a MAC
//!   header: an ACK or a CTS is ten bytes, an RTS sixteen.
//! * **data** frames: the header is read to map a client to a BSSID. The
//!   payload is never kept. EAPOL frames are counted as `eapol_seen` and
//!   dropped.
//!
//! # Metadata only
//!
//! The daemon keeps *metadata*, never content. This module therefore never
//! copies a frame body into anything it returns: the body is looked at for
//! at most eight bytes, to read the LLC/SNAP EtherType, and the answer is
//! reduced to a [`BodyKind`]. An EAPOL frame is counted and forgotten; its
//! bytes are not kept, not hashed, not logged.
//!
//! # No transmission
//!
//! This module is a pure function library over byte slices. It cannot and
//! does not touch a radio, a pcap handle or the network. Nothing here
//! transmits, and nothing here can.
//!
//! Implemented in OR-103.

use crate::error::{ParseError, Result, take};
use crate::ieee80211::{ControlHeader, FrameType, MacHeader, management_ie_offset};

/// Length of a MAC header without the address-4 field.
const MAC_HEADER_LEN: usize = 24;

/// Length of a MAC header with the address-4 field.
const MAC_HEADER_LEN_ADDR4: usize = 30;

/// The first three bytes of an LLC/SNAP header: the LLC `AA AA 03`.
const LLC_SNAP_PREFIX: [u8; 3] = [0xAA, 0xAA, 0x03];

/// The EtherType of an EAPOL frame (IEEE 802.1X).
const ETHER_TYPE_EAPOL: u16 = 0x888E;

/// How a data frame is addressed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DataMapping {
    /// The station that sent or received the frame.
    ///
    /// This is `None` when the frame does not identify a single station:
    /// when the address that would name the station is a broadcast or
    /// multicast address, and when the frame is a four-address frame with no
    /// fourth address, so that the station cannot be named at all.
    pub client: Option<[u8; 6]>,
    /// The access point the frame belongs to.
    ///
    /// This is `None` for a four-address frame: such a frame carries the
    /// addresses of the bridge that relayed it, not the BSSID of the network
    /// the station is on.
    pub bssid: Option<[u8; 6]>,
    /// The `To DS` bit of the frame control word.
    pub to_ds: bool,
    /// The `From DS` bit of the frame control word.
    pub from_ds: bool,
}

/// What the body of a data frame is, without keeping any of it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyKind {
    /// Ordinary data.
    Data,
    /// An EAPOL frame: counted, never stored.
    Eapol,
    /// A frame the daemon does not classify.
    Other,
}

/// What kind of frame a captured frame turned out to be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameClass {
    /// A management frame: beacon, probe, association, authentication, ...
    Management {
        /// The MAC header of the frame.
        header: MacHeader,
        /// The management subtype of the frame.
        subtype: u8,
        /// Where the information elements start in the frame body, when the
        /// subtype has any.
        ie_offset: Option<usize>,
    },
    /// A control frame: ACK, RTS, CTS, ...
    Control {
        /// The header of the control frame.
        header: ControlHeader,
        /// The control subtype of the frame.
        subtype: u8,
    },
    /// A data frame.
    Data {
        /// The MAC header of the frame.
        header: MacHeader,
        /// How the frame is addressed.
        mapping: DataMapping,
        /// What the body of the frame is. The body itself is not kept.
        body: BodyKind,
    },
    /// An extension frame: mesh traffic, control extensions, ...
    Extension {
        /// The MAC header of the frame.
        header: MacHeader,
    },
    /// A frame whose type field is not one of the four defined ones.
    Unknown {
        /// The MAC header of the frame.
        header: MacHeader,
        /// The raw type value from the frame control word.
        frame_type: u8,
    },
}

/// Map a data frame's addresses to a client and a BSSID.
///
/// The rules are the ones fixed by the parser API contract
/// (`docs/PARSER-API.md`), which follow IEEE 802.11-2020, Table 9-30 (the
/// same table the Linux kernel documents in `include/linux/ieee80211.h`):
///
/// | To DS | From DS | addr1 | addr2 | addr3 | addr4 |
/// |---|---|---|---|---|---|
/// | 0 | 0 | DA/RA | SA/TA | **BSSID** | absent |
/// | 0 | 1 | DA/RA | **BSSID**/TA | SA | absent |
/// | 1 | 0 | **BSSID**/RA | SA/TA | DA | absent |
/// | 1 | 1 | RA | TA | DA | **SA** |
///
/// So the client (the station) and the BSSID are:
///
/// * `To DS = 0, From DS = 0`: the client is addr2, the source address; the
///   BSSID is addr3.
/// * `To DS = 1, From DS = 0`: the client is addr2, the source address; the
///   BSSID is addr1.
/// * `To DS = 0, From DS = 1`: the client is addr1, the destination address,
///   that is the station the frame is addressed to; the BSSID is addr2.
/// * `To DS = 1, From DS = 1`: the client is addr4, the source address of the
///   original station. The BSSID is *not* in the frame: addr3 is the
///   destination address and addr2 is the transmitting bridge, so the BSSID is
///   left `None` rather than guessed.
///
/// The client is `None` in the cases where the station cannot be named with
/// confidence:
///
/// * the address that would name the station is a broadcast or multicast
///   address, which does not name one station, and
/// * the frame is a four-address frame with no fourth address, so there is no
///   source address to read.
///
/// The BSSID is known in the three-address forms and is `None` only for the
/// four-address form, where the frame does not carry it.
pub fn map_data_addresses(header: &MacHeader) -> DataMapping {
    let to_ds = header.to_ds();
    let from_ds = header.from_ds();

    let (client, bssid) = match (to_ds, from_ds) {
        // addr1 = DA/RA, addr2 = SA/TA, addr3 = BSSID.
        (false, false) => (Some(header.addr2), Some(header.addr3)),
        // addr1 = DA/RA, addr2 = BSSID/TA, addr3 = SA.
        (false, true) => (Some(header.addr1), Some(header.addr2)),
        // addr1 = BSSID/RA, addr2 = SA/TA, addr3 = DA.
        (true, false) => (Some(header.addr2), Some(header.addr1)),
        // addr1 = RA, addr2 = TA (the bridge), addr3 = DA, addr4 = SA (the
        // original station). The BSSID is not in the frame.
        (true, true) => (header.addr4, None),
    };

    let client = client.filter(|addr| !is_group_address(*addr));

    DataMapping {
        client,
        bssid,
        to_ds,
        from_ds,
    }
}

/// Classify the body of a data frame by looking at its first bytes only.
///
/// A data body starts with an LLC/SNAP header: `AA AA 03 00 00 00` followed
/// by a two byte big-endian EtherType. EtherType `0x888E` is EAPOL.
///
/// A body that is too short to hold the LLC/SNAP header, or that does not
/// start with `AA AA 03`, is [`BodyKind::Other`]. A body that starts with
/// `AA AA 03` but carries some other EtherType is [`BodyKind::Data`].
///
/// Only the first eight bytes are ever read, and none of them is kept: the
/// result is a single tag. A protected (encrypted) body does not start with
/// an LLC/SNAP header, so it classifies as [`BodyKind::Other`].
pub fn classify_body(body: &[u8]) -> BodyKind {
    let header = match take(body, 8) {
        Ok(header) => header,
        Err(_) => return BodyKind::Other,
    };

    if header[..3] != LLC_SNAP_PREFIX {
        return BodyKind::Other;
    }

    let ether_type = u16::from_be_bytes([header[6], header[7]]);
    if ether_type == ETHER_TYPE_EAPOL {
        BodyKind::Eapol
    } else {
        BodyKind::Data
    }
}

/// Dispatch a captured 802.11 frame.
///
/// The frame is the bytes that follow the radiotap header; the radiotap
/// header itself is parsed by [`crate::radiotap`] and is not part of the
/// frame.
///
/// The result carries the header and, for data frames, the address mapping
/// and the body kind. The frame body is never copied into the result: it is
/// looked at for at most eight bytes, to tell EAPOL from ordinary data, and
/// then dropped.
pub fn dispatch(frame: &[u8]) -> Result<FrameClass> {
    // The frame type has to be known before the header is parsed: a control
    // frame is ten bytes long, so it cannot go through `MacHeader::parse`.
    // `ControlHeader::parse` reads the frame control word and needs no more
    // than the ten bytes every control frame has, so it serves as the peek
    // that tells the two apart.
    let peek = ControlHeader::parse(frame)?;

    Ok(match peek.frame_type() {
        FrameType::Control => FrameClass::Control {
            header: peek,
            subtype: peek.subtype(),
        },
        FrameType::Management => {
            let header = MacHeader::parse(frame)?;
            let subtype = header.subtype();
            FrameClass::Management {
                header,
                subtype,
                ie_offset: management_ie_offset(subtype),
            }
        }
        FrameType::Data => {
            let header = MacHeader::parse(frame)?;
            let body = frame.get(mac_header_len(&header)..).unwrap_or(&[]);
            FrameClass::Data {
                header,
                mapping: map_data_addresses(&header),
                body: classify_body(data_payload(body, header.subtype())),
            }
        }
        FrameType::Extension => {
            let header = MacHeader::parse(frame)?;
            FrameClass::Extension { header }
        }
        FrameType::Unknown(frame_type) => {
            let header = MacHeader::parse(frame)?;
            FrameClass::Unknown { header, frame_type }
        }
    })
}

/// Dispatch a captured frame: a radiotap header followed by the 802.11 frame.
///
/// The radiotap header is parsed by [`crate::radiotap`], which owns that
/// format; this function only needs to know where the 802.11 frame starts,
/// which is the header's total length.
///
/// The radiotap metadata itself is not part of the result: it belongs to the
/// capture layer, which records the signal level and the channel.
pub fn dispatch_capture(capture: &[u8]) -> Result<FrameClass> {
    let radiotap = crate::radiotap::parse(capture)?;
    let frame = capture
        .get(radiotap.len as usize..)
        .ok_or(ParseError::Truncated {
            needed: radiotap.len as usize,
            available: capture.len(),
        })?;
    dispatch(frame)
}

/// The length of the MAC header of a frame, in bytes.
///
/// A frame that carries the address-4 field has a six bytes longer header.
/// The field is present only in a data frame with both distribution system
/// bits set, so this follows the parsed header.
fn mac_header_len(header: &MacHeader) -> usize {
    if header.addr4.is_some() {
        MAC_HEADER_LEN_ADDR4
    } else {
        MAC_HEADER_LEN
    }
}

/// The payload of a data frame, with the QoS control field removed.
///
/// A QoS data frame (subtypes 8 to 15) carries a two byte QoS control field
/// between the MAC header and the payload. The field is not encrypted, so it
/// has to be skipped before the LLC/SNAP header can be found.
fn data_payload(body: &[u8], subtype: u8) -> &[u8] {
    const QOS_BIT: u8 = 0x08;
    const QOS_CONTROL_LEN: usize = 2;

    if subtype & QOS_BIT != 0 {
        body.get(QOS_CONTROL_LEN..).unwrap_or(&[])
    } else {
        body
    }
}

/// True when the address is a broadcast or multicast address.
///
/// The low bit of the first octet of a MAC address is the individual or
/// group bit: a set bit means the address names a group of stations rather
/// than one station.
fn is_group_address(addr: [u8; 6]) -> bool {
    addr[0] & 0x01 != 0
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A synthetic MAC address. Only the last byte varies, so every address
    /// in the tests is obviously fake.
    fn mac(last: u8) -> [u8; 6] {
        [0x00, 0x11, 0x22, 0x33, 0x44, last]
    }

    /// A synthetic group (multicast) address.
    fn group_mac(last: u8) -> [u8; 6] {
        [0x01, 0x00, 0x5e, 0x00, 0x00, last]
    }

    /// The `To DS` bit of the frame control word.
    const TO_DS: u16 = 0x0100;

    /// The `From DS` bit of the frame control word.
    const FROM_DS: u16 = 0x0200;

    /// The type field of the frame control word, for data frames.
    const FRAME_TYPE_DATA: u16 = 0x0008;

    /// The frame control word of a data frame.
    fn data_control(subtype: u8, to_ds: bool, from_ds: bool) -> u16 {
        let mut fc = FRAME_TYPE_DATA | (u16::from(subtype) << 4);
        if to_ds {
            fc |= TO_DS;
        }
        if from_ds {
            fc |= FROM_DS;
        }
        fc
    }

    /// A data frame with the given frame control word and body.
    ///
    /// The address-4 field is present exactly when the frame is a data frame
    /// with both distribution system bits set, which is how the header
    /// parser decides it.
    fn data_frame(fc: u16, body: &[u8]) -> Vec<u8> {
        let mut frame = Vec::new();
        frame.extend_from_slice(&fc.to_le_bytes());
        frame.extend_from_slice(&0x0027u16.to_le_bytes());
        frame.extend_from_slice(&mac(0x01));
        frame.extend_from_slice(&mac(0x02));
        frame.extend_from_slice(&mac(0x03));
        frame.extend_from_slice(&0x1234u16.to_le_bytes());
        if fc & 0x000c == FRAME_TYPE_DATA && fc & TO_DS != 0 && fc & FROM_DS != 0 {
            frame.extend_from_slice(&mac(0x04));
        }
        frame.extend_from_slice(body);
        frame
    }

    /// An LLC/SNAP header followed by the given EtherType.
    fn snap(ether_type: u16) -> Vec<u8> {
        let mut body = vec![0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00];
        body.extend_from_slice(&ether_type.to_be_bytes());
        body
    }

    #[test]
    fn to_ds_data_frame_maps_client_to_addr2() {
        let frame = data_frame(data_control(0, true, false), &snap(0x0800));
        let header = MacHeader::parse(&frame).expect("the header parses");
        let mapping = map_data_addresses(&header);

        assert_eq!(mapping.client, Some(mac(0x02)));
        assert_eq!(mapping.bssid, Some(mac(0x01)));
        assert!(mapping.to_ds);
        assert!(!mapping.from_ds);
    }

    #[test]
    fn from_ds_data_frame_maps_client_to_addr1() {
        let frame = data_frame(data_control(0, false, true), &snap(0x0800));
        let header = MacHeader::parse(&frame).expect("the header parses");
        let mapping = map_data_addresses(&header);

        assert_eq!(mapping.client, Some(mac(0x01)));
        assert_eq!(mapping.bssid, Some(mac(0x02)));
        assert!(!mapping.to_ds);
        assert!(mapping.from_ds);
    }

    #[test]
    fn neither_ds_data_frame_maps_client_to_addr2_and_bssid_to_addr3() {
        // The IBSS and DLS form: addr1 is the destination, addr2 the source
        // and addr3 the BSSID.
        let frame = data_frame(data_control(0, false, false), &snap(0x0800));
        let header = MacHeader::parse(&frame).expect("the header parses");
        let mapping = map_data_addresses(&header);

        assert_eq!(mapping.client, Some(mac(0x02)));
        assert_eq!(mapping.bssid, Some(mac(0x03)));
        assert!(!mapping.to_ds);
        assert!(!mapping.from_ds);
    }

    #[test]
    fn four_address_data_frame_maps_client_to_addr4() {
        // The WDS form: addr4 is the source address of the original station,
        // and the BSSID is not in the frame at all.
        let frame = data_frame(data_control(0, true, true), &snap(0x0800));
        let header = MacHeader::parse(&frame).expect("the header parses");
        assert_eq!(header.addr4, Some(mac(0x04)));

        let mapping = map_data_addresses(&header);

        assert_eq!(mapping.client, Some(mac(0x04)));
        assert_eq!(mapping.bssid, None);
        assert!(mapping.to_ds);
        assert!(mapping.from_ds);
    }

    #[test]
    fn a_four_address_frame_without_addr4_has_no_client() {
        // The header cannot name the station when the fourth address is
        // missing.
        let header = MacHeader {
            frame_control: data_control(0, true, true),
            duration: 0x0027,
            addr1: mac(0x01),
            addr2: mac(0x02),
            addr3: mac(0x03),
            addr4: None,
            sequence_control: 0x1234,
        };
        let mapping = map_data_addresses(&header);

        assert_eq!(mapping.client, None);
        assert_eq!(mapping.bssid, None);
    }

    #[test]
    fn a_group_address_is_not_a_client() {
        // A broadcast destination does not name a single station.
        let mut frame = data_frame(data_control(0, false, true), &snap(0x0800));
        // Replace addr1 with a multicast address.
        frame[4..10].copy_from_slice(&group_mac(0x09));
        let header = MacHeader::parse(&frame).expect("the header parses");
        let mapping = map_data_addresses(&header);

        assert_eq!(mapping.client, None);
        assert_eq!(mapping.bssid, Some(mac(0x02)));
    }

    #[test]
    fn classify_body_finds_eapol() {
        let body = snap(ETHER_TYPE_EAPOL);
        assert_eq!(classify_body(&body), BodyKind::Eapol);
    }

    #[test]
    fn classify_body_finds_ordinary_data() {
        // 0x0800 is IPv4, 0x86DD is IPv6.
        assert_eq!(classify_body(&snap(0x0800)), BodyKind::Data);
        assert_eq!(classify_body(&snap(0x86DD)), BodyKind::Data);
    }

    #[test]
    fn classify_body_rejects_a_short_body() {
        // Nothing at all, and every prefix of a valid LLC/SNAP header.
        assert_eq!(classify_body(&[]), BodyKind::Other);
        for len in 0..8 {
            let body = snap(ETHER_TYPE_EAPOL);
            assert_eq!(classify_body(&body[..len]), BodyKind::Other);
        }
    }

    #[test]
    fn classify_body_rejects_a_body_without_llc_snap() {
        assert_eq!(
            classify_body(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00]),
            BodyKind::Other
        );
        assert_eq!(classify_body(b"\xaa\xaa\x03"), BodyKind::Other);
    }

    #[test]
    fn no_payload_is_retained() {
        // A data frame whose payload carries a distinctive marker. Neither the
        // dispatch result nor the body classification may keep it.
        let marker = "SECRETPORTPAYLOAD";
        let mut body = snap(0x0800);
        body.extend_from_slice(marker.as_bytes());
        let frame = data_frame(data_control(0, true, false), &body);

        let result = dispatch(&frame).expect("the frame dispatches");
        let rendered = format!("{result:?}");
        assert!(!rendered.contains(marker), "the payload leaked: {rendered}");

        let kind = classify_body(&body);
        assert_eq!(kind, BodyKind::Data);
        assert!(!format!("{kind:?}").contains(marker));
    }

    #[test]
    fn no_eapol_body_is_retained() {
        // An EAPOL frame is counted, and its body is dropped.
        let marker = "SECRETPORTPAYLOAD";
        let mut body = snap(ETHER_TYPE_EAPOL);
        body.extend_from_slice(marker.as_bytes());
        let frame = data_frame(data_control(0, true, false), &body);

        let result = dispatch(&frame).expect("the frame dispatches");
        let rendered = format!("{result:?}");
        assert!(
            !rendered.contains(marker),
            "the EAPOL body leaked: {rendered}"
        );

        match result {
            FrameClass::Data { body: kind, .. } => assert_eq!(kind, BodyKind::Eapol),
            other => panic!("expected a data frame, got {other:?}"),
        }
    }

    #[test]
    fn dispatch_classifies_a_data_frame() {
        let frame = data_frame(data_control(0, true, false), &snap(0x0800));
        let result = dispatch(&frame).expect("the frame dispatches");

        match result {
            FrameClass::Data {
                header,
                mapping,
                body,
            } => {
                assert_eq!(header.addr1, mac(0x01));
                assert_eq!(header.addr2, mac(0x02));
                assert_eq!(header.addr3, mac(0x03));
                assert_eq!(mapping.client, Some(mac(0x02)));
                assert_eq!(mapping.bssid, Some(mac(0x01)));
                assert_eq!(body, BodyKind::Data);
            }
            other => panic!("expected a data frame, got {other:?}"),
        }
    }

    #[test]
    fn dispatch_skips_the_qos_control_field() {
        // A QoS data frame carries a two byte QoS control field before the
        // LLC/SNAP header.
        let mut body = vec![0x00, 0x00];
        body.extend_from_slice(&snap(ETHER_TYPE_EAPOL));
        let frame = data_frame(data_control(8, true, false), &body);

        match dispatch(&frame).expect("the frame dispatches") {
            FrameClass::Data { body, .. } => assert_eq!(body, BodyKind::Eapol),
            other => panic!("expected a data frame, got {other:?}"),
        }
    }

    #[test]
    fn dispatch_classifies_a_four_address_data_frame() {
        let frame = data_frame(data_control(0, true, true), &snap(0x0800));

        match dispatch(&frame).expect("the frame dispatches") {
            FrameClass::Data {
                header, mapping, ..
            } => {
                assert_eq!(header.addr4, Some(mac(0x04)));
                assert_eq!(mapping.client, Some(mac(0x04)));
                assert_eq!(mapping.bssid, None);
            }
            other => panic!("expected a data frame, got {other:?}"),
        }
    }

    #[test]
    fn dispatch_classifies_management_and_control_frames() {
        // A beacon: type 0, subtype 8.
        let mut beacon = Vec::new();
        beacon.extend_from_slice(&(8u16 << 4).to_le_bytes());
        beacon.extend_from_slice(&0x0027u16.to_le_bytes());
        beacon.extend_from_slice(&mac(0x01));
        beacon.extend_from_slice(&mac(0x02));
        beacon.extend_from_slice(&mac(0x03));
        beacon.extend_from_slice(&0x1234u16.to_le_bytes());
        beacon.extend_from_slice(&[0u8; 12]);

        match dispatch(&beacon).expect("the beacon dispatches") {
            FrameClass::Management {
                subtype, ie_offset, ..
            } => {
                assert_eq!(subtype, 8);
                // A beacon carries twelve bytes of fixed fields before its
                // information elements.
                assert_eq!(ie_offset, Some(12));
            }
            other => panic!("expected a management frame, got {other:?}"),
        }

        // An ACK: type 1, subtype 13. A control frame is ten bytes, so it
        // never reaches the MAC header parser.
        let mut ack = Vec::new();
        ack.extend_from_slice(&(0x0004u16 | (13u16 << 4)).to_le_bytes());
        ack.extend_from_slice(&0x0027u16.to_le_bytes());
        ack.extend_from_slice(&mac(0x01));

        match dispatch(&ack).expect("the ack dispatches") {
            FrameClass::Control { header, subtype } => {
                assert_eq!(subtype, 13);
                assert_eq!(header.addr1, mac(0x01));
            }
            other => panic!("expected a control frame, got {other:?}"),
        }
    }

    #[test]
    fn dispatch_rejects_a_truncated_frame() {
        assert!(dispatch(&[]).is_err());
        assert!(dispatch(&[0x08, 0x00]).is_err());
    }

    #[test]
    fn dispatch_capture_skips_the_radiotap_header() {
        // A radiotap header with no fields: version, padding, length and an
        // empty present mask.
        let mut capture = vec![0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00];
        capture.extend_from_slice(&data_frame(data_control(0, true, false), &snap(0x0800)));

        let result = dispatch_capture(&capture).expect("the capture dispatches");
        assert!(matches!(result, FrameClass::Data { .. }));

        // A capture whose radiotap header claims more bytes than the buffer
        // holds is an error, not a panic.
        let mut short = capture.clone();
        short[2] = 0xff;
        assert!(dispatch_capture(&short).is_err());
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
        let mut rng = Lcg::new(0x0d3a_5eed_1234_5678);
        for _ in 0..4000 {
            let len = (rng.next_u64() % 96) as usize;
            let mut buf: Vec<u8> = Vec::with_capacity(len);
            for _ in 0..len {
                buf.push(rng.next_u8());
            }

            // The dispatcher either parses the frame or reports an error. It
            // never panics, whatever the bytes are.
            let outcome = dispatch(&buf);
            assert!(outcome.is_ok() || outcome.is_err());

            // The same for a capture with a random radiotap header in front.
            let mut capture = vec![0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00];
            capture.extend_from_slice(&buf);
            let outcome = dispatch_capture(&capture);
            assert!(outcome.is_ok() || outcome.is_err());

            // And for the body classifier.
            let _ = classify_body(&buf);

            // A data frame with a random body, so that the data path runs on
            // random input too.
            let mut frame = Vec::new();
            frame.extend_from_slice(&data_control(0, true, false).to_le_bytes());
            frame.extend_from_slice(&0x0027u16.to_le_bytes());
            frame.extend_from_slice(&mac(0x01));
            frame.extend_from_slice(&mac(0x02));
            frame.extend_from_slice(&mac(0x03));
            frame.extend_from_slice(&0x1234u16.to_le_bytes());
            frame.extend_from_slice(&buf);
            let outcome = dispatch(&frame);
            assert!(outcome.is_ok() || outcome.is_err());
        }
    }
}
