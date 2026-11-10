//! Frame counters for the `--dry-run` mode.
//!
//! The counters answer one question: *what is on the air?* They keep
//! counts, channel numbers and signal levels, and nothing else.
//!
//! # No libpcap
//!
//! This module depends on `od3sa-parse` and on nothing else. It never opens
//! a capture handle, never names an interface and never touches a radio: it
//! takes the bytes of one captured frame and updates the counts. That is
//! what makes it testable on the build machine, with synthetic frames, and
//! it keeps the capture side a pure source of bytes.
//!
//! # Metadata only
//!
//! Nothing that comes out of a frame body is kept. The frame is classified,
//! counted and dropped. An EAPOL frame is counted once, in
//! [`Counters::eapol_frames`], and nowhere else: it is not part of the class
//! counts, not part of the channel counts and not part of the byte total,
//! and its body is never read beyond the eight bytes the LLC/SNAP header
//! needs.
//!
//! The counters hold no payload, no address and no SSID. A test checks that
//! a frame whose payload carries a distinctive marker leaves no trace of it
//! in the counters.

use std::collections::BTreeMap;

use od3sa_parse::frame::{BodyKind, FrameClass, dispatch};
use od3sa_parse::radiotap;

/// What kind of link layer the captured frames have.
///
/// A monitor interface normally delivers a radiotap header in front of
/// every frame: that is where the channel and the signal level come from.
/// Some interfaces deliver the bare 802.11 frame instead; the frames are
/// then still counted, but no channel and no signal level can be named.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LinkLayer {
    /// 802.11 frames with a radiotap header in front of them.
    #[default]
    Radiotap,
    /// 802.11 frames with no radiotap header.
    Ieee80211,
}

/// The counts of the management frame subtypes.
///
/// The buckets are the ones the capture contract names. The association
/// bucket holds the association request and response (subtypes 0 and 1) and
/// the reassociation request and response (subtypes 2 and 3): all four are
/// the station joining or leaving a network.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ManagementCounts {
    /// Beacon frames (subtype 8).
    pub beacon: u64,
    /// Probe request frames (subtype 4).
    pub probe_request: u64,
    /// Probe response frames (subtype 5).
    pub probe_response: u64,
    /// Association and reassociation frames (subtypes 0 to 3).
    pub association: u64,
    /// Authentication frames (subtype 11).
    pub authentication: u64,
    /// Deauthentication frames (subtype 12).
    pub deauthentication: u64,
    /// Disassociation frames (subtype 10).
    pub disassociation: u64,
    /// Every other management subtype: ATIM, action frames, and the reserved
    /// values.
    pub other: u64,
}

impl ManagementCounts {
    /// Count one management frame of the given subtype.
    fn add(&mut self, subtype: u8) {
        match subtype {
            8 => self.beacon += 1,
            4 => self.probe_request += 1,
            5 => self.probe_response += 1,
            0..=3 => self.association += 1,
            11 => self.authentication += 1,
            12 => self.deauthentication += 1,
            10 => self.disassociation += 1,
            _ => self.other += 1,
        }
    }

    /// The total of every management bucket.
    pub fn total(&self) -> u64 {
        self.beacon
            + self.probe_request
            + self.probe_response
            + self.association
            + self.authentication
            + self.deauthentication
            + self.disassociation
            + self.other
    }
}

/// What was seen on one channel.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ChannelStats {
    /// How many frames were seen on the channel.
    pub frames: u64,
    /// The strongest signal seen on the channel, in dBm.
    ///
    /// This is `None` when no frame on the channel carried a signal level.
    /// The strongest signal is the one closest to zero: -40 dBm is stronger
    /// than -80 dBm.
    pub strongest_dbm: Option<i8>,
}

/// The counters of a `--dry-run`.
///
/// The counters keep counts, channel numbers and signal levels, and nothing
/// else. See the module documentation for what "metadata only" means here.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Counters {
    /// Management frames.
    management: u64,
    /// Control frames.
    control: u64,
    /// Data frames that are not EAPOL.
    data: u64,
    /// Frames that are neither management, control nor data, and frames that
    /// could not be classified at all.
    other: u64,
    /// The management frames, by subtype.
    management_subtypes: ManagementCounts,
    /// What was seen on each channel.
    channels: BTreeMap<u16, ChannelStats>,
    /// Frames whose radiotap header carried no channel, and frames that
    /// arrived on a link layer with no radiotap header at all.
    frames_without_channel: u64,
    /// The total size of the frames that were counted, in bytes.
    total_bytes: u64,
    /// EAPOL frames. Counted separately, and never stored.
    eapol_frames: u64,
    /// What kind of link layer the captured frames have.
    link_layer: LinkLayer,
}

impl Counters {
    /// New, empty counters for an interface that delivers the given kind
    /// of link layer.
    pub fn with_link_layer(link_layer: LinkLayer) -> Counters {
        Counters {
            link_layer,
            ..Counters::default()
        }
    }

    /// Count one captured frame.
    ///
    /// The frame is the bytes of a captured packet: on a radiotap link
    /// layer, a radiotap header followed by the 802.11 frame; on a plain
    /// 802.11 link layer, the 802.11 frame alone. A frame that cannot be
    /// parsed is counted as an "other" frame: it was seen, and its size is
    /// counted, but nothing can be said about it.
    ///
    /// An EAPOL frame is counted once, in [`Counters::eapol_frames`], and
    /// nowhere else. It is never kept.
    pub fn add(&mut self, frame: &[u8]) {
        // The radiotap header, when there is one. It carries the channel
        // and the signal level, and it says where the 802.11 frame starts.
        let (payload, header) = match self.link_layer {
            LinkLayer::Radiotap => match radiotap::parse(frame) {
                Ok(header) => {
                    let payload = frame.get(header.len as usize..).unwrap_or(&[]);
                    (payload, Some(header))
                }
                Err(_) => {
                    // The radiotap header is unreadable: the frame cannot be
                    // classified and no channel can be named.
                    self.other += 1;
                    self.total_bytes += frame.len() as u64;
                    self.frames_without_channel += 1;
                    return;
                }
            },
            LinkLayer::Ieee80211 => (frame, None),
        };

        match dispatch(payload) {
            Ok(FrameClass::Management { subtype, .. }) => {
                self.management += 1;
                self.management_subtypes.add(subtype);
            }
            Ok(FrameClass::Control { .. }) => self.control += 1,
            Ok(FrameClass::Data {
                body: BodyKind::Eapol,
                ..
            }) => {
                // Counted separately and dropped: the body is never read
                // beyond the LLC/SNAP header, and the frame is not counted
                // anywhere else.
                self.eapol_frames += 1;
                return;
            }
            Ok(FrameClass::Data { .. }) => self.data += 1,
            Ok(FrameClass::Extension { .. }) | Ok(FrameClass::Unknown { .. }) => self.other += 1,
            Err(_) => self.other += 1,
        }

        self.total_bytes += frame.len() as u64;

        let channel = header.and_then(|header| {
            header
                .channel
                .and_then(|channel| radiotap::channel_number(channel.freq_mhz))
        });
        let signal = header.and_then(|header| header.signal_dbm);

        match channel {
            Some(number) => {
                let stats = self.channels.entry(number).or_default();
                stats.frames += 1;
                if let Some(signal) = signal {
                    stats.strongest_dbm = Some(match stats.strongest_dbm {
                        Some(current) => current.max(signal),
                        None => signal,
                    });
                }
            }
            None => self.frames_without_channel += 1,
        }
    }

    /// The total number of counted frames.
    ///
    /// EAPOL frames are not counted here: they have their own counter.
    pub fn total_frames(&self) -> u64 {
        self.management + self.control + self.data + self.other
    }

    /// The number of management frames.
    pub fn management_frames(&self) -> u64 {
        self.management
    }

    /// The number of control frames.
    pub fn control_frames(&self) -> u64 {
        self.control
    }

    /// The number of data frames that are not EAPOL.
    pub fn data_frames(&self) -> u64 {
        self.data
    }

    /// The number of frames that are neither management, control nor data,
    /// and of the frames that could not be classified.
    pub fn other_frames(&self) -> u64 {
        self.other
    }

    /// The management frames, by subtype.
    pub fn management_counts(&self) -> &ManagementCounts {
        &self.management_subtypes
    }

    /// The number of EAPOL frames.
    ///
    /// EAPOL frames are counted and never stored: no body, no address, no
    /// key material.
    pub fn eapol_frames(&self) -> u64 {
        self.eapol_frames
    }

    /// The total size of the counted frames, in bytes.
    pub fn total_bytes(&self) -> u64 {
        self.total_bytes
    }

    /// The mean size of the counted frames, in bytes.
    ///
    /// This is zero when no frame was counted.
    pub fn mean_frame_size(&self) -> f64 {
        let frames = self.total_frames();
        if frames == 0 {
            0.0
        } else {
            self.total_bytes as f64 / frames as f64
        }
    }

    /// The number of frames seen on a channel.
    pub fn channel_frames(&self, channel: u16) -> u64 {
        self.channels.get(&channel).map_or(0, |stats| stats.frames)
    }

    /// The strongest signal seen on a channel, in dBm.
    pub fn strongest_signal(&self, channel: u16) -> Option<i8> {
        self.channels
            .get(&channel)
            .and_then(|stats| stats.strongest_dbm)
    }

    /// The number of frames whose radiotap header carried no channel.
    pub fn frames_without_channel(&self) -> u64 {
        self.frames_without_channel
    }

    /// Every channel that was seen, with what was seen on it.
    pub fn channels(&self) -> impl Iterator<Item = (u16, &ChannelStats)> {
        self.channels.iter().map(|(number, stats)| (*number, stats))
    }

    /// The `count` busiest channels, the busiest first.
    ///
    /// Channels with the same number of frames are ordered by channel
    /// number, so the result is stable.
    pub fn top_channels(&self, count: usize) -> Vec<(u16, ChannelStats)> {
        let mut channels: Vec<(u16, ChannelStats)> = self
            .channels
            .iter()
            .map(|(number, stats)| (*number, *stats))
            .collect();
        channels.sort_by(|left, right| {
            right
                .1
                .frames
                .cmp(&left.1.frames)
                .then(left.0.cmp(&right.0))
        });
        channels.truncate(count);
        channels
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

    /// A synthetic radiotap header with a channel and a signal level.
    ///
    /// The header carries the channel field (bit 3) and the DBM field
    /// (bit 5), in that order, and `it_len` covers the whole header.
    fn radiotap(signal_dbm: i8, freq_mhz: u16) -> Vec<u8> {
        let mut header = vec![0u8; 8];
        header[4..8].copy_from_slice(&((1u32 << 3) | (1u32 << 5)).to_le_bytes());
        header.extend_from_slice(&freq_mhz.to_le_bytes()); // the channel frequency
        header.extend_from_slice(&0u16.to_le_bytes()); // the channel flags
        header.push(signal_dbm as u8); // the signal level
        let length = u16::try_from(header.len()).unwrap_or(u16::MAX);
        header[2..4].copy_from_slice(&length.to_le_bytes());
        header
    }

    /// A synthetic beacon frame, with a radiotap header in front of it.
    fn beacon_frame(signal_dbm: i8, freq_mhz: u16) -> Vec<u8> {
        let mut frame = radiotap(signal_dbm, freq_mhz);
        frame.extend_from_slice(&(8u16 << 4).to_le_bytes()); // management, subtype 8
        frame.extend_from_slice(&0x0027u16.to_le_bytes()); // duration
        frame.extend_from_slice(&mac(0x01)); // addr1
        frame.extend_from_slice(&mac(0x02)); // addr2
        frame.extend_from_slice(&mac(0x02)); // addr3, the BSSID
        frame.extend_from_slice(&0x1234u16.to_le_bytes()); // sequence control
        frame.extend_from_slice(&[0u8; 8]); // the beacon timestamp
        frame.extend_from_slice(&100u16.to_le_bytes()); // the beacon interval
        frame.extend_from_slice(&0x0001u16.to_le_bytes()); // the capability info
        frame.extend_from_slice(&[0, 4, b'e', b'x', b'a', b'm']); // an SSID element
        frame
    }

    /// The LLC/SNAP header of an EAPOL frame, with EtherType `0x888E`.
    const LLC_SNAP_EAPOL: [u8; 8] = [0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8e];

    /// A synthetic data frame, with a radiotap header in front of it.
    fn data_frame(signal_dbm: i8, freq_mhz: u16, body: &[u8]) -> Vec<u8> {
        let mut frame = radiotap(signal_dbm, freq_mhz);
        // Data, subtype 0, To DS set: the address-4 field is not present.
        frame.extend_from_slice(&0x0108u16.to_le_bytes());
        frame.extend_from_slice(&0x0027u16.to_le_bytes()); // duration
        frame.extend_from_slice(&mac(0x02)); // addr1, the BSSID
        frame.extend_from_slice(&mac(0x03)); // addr2, the source
        frame.extend_from_slice(&mac(0x04)); // addr3, the destination
        frame.extend_from_slice(&0x1234u16.to_le_bytes()); // sequence control
        frame.extend_from_slice(body);
        frame
    }

    /// A synthetic EAPOL data frame.
    fn eapol_frame(signal_dbm: i8, freq_mhz: u16) -> Vec<u8> {
        let mut body = LLC_SNAP_EAPOL.to_vec();
        body.extend_from_slice(&[0x01, 0x00, 0x00, 0x04]); // EAPOL version, type, length
        body.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // a placeholder body
        data_frame(signal_dbm, freq_mhz, &body)
    }

    #[test]
    fn a_beacon_frame_is_counted_as_a_management_beacon_on_its_channel() {
        let mut counters = Counters::with_link_layer(LinkLayer::Radiotap);
        counters.add(&beacon_frame(-42, 2412));

        assert_eq!(counters.total_frames(), 1);
        assert_eq!(counters.management_frames(), 1);
        assert_eq!(counters.control_frames(), 0);
        assert_eq!(counters.data_frames(), 0);
        assert_eq!(counters.other_frames(), 0);
        assert_eq!(counters.eapol_frames(), 0);

        assert_eq!(counters.management_counts().beacon, 1);
        assert_eq!(counters.management_counts().probe_request, 0);
        assert_eq!(counters.management_counts().total(), 1);

        // 2412 MHz is channel 1.
        assert_eq!(counters.channel_frames(1), 1);
        assert_eq!(counters.channel_frames(6), 0);
        assert_eq!(counters.strongest_signal(1), Some(-42));
    }

    #[test]
    fn a_beacon_on_a_five_ghertz_channel_is_counted_on_that_channel() {
        let mut counters = Counters::with_link_layer(LinkLayer::Radiotap);
        counters.add(&beacon_frame(-67, 5180));

        // 5180 MHz is channel 36.
        assert_eq!(counters.channel_frames(36), 1);
        assert_eq!(counters.strongest_signal(36), Some(-67));
    }

    #[test]
    fn an_eapol_frame_is_counted_only_as_an_eapol_frame() {
        let mut counters = Counters::with_link_layer(LinkLayer::Radiotap);
        counters.add(&eapol_frame(-50, 2412));

        assert_eq!(counters.eapol_frames(), 1);

        // An EAPOL frame is counted separately: it is in no other counter.
        assert_eq!(counters.total_frames(), 0);
        assert_eq!(counters.management_frames(), 0);
        assert_eq!(counters.control_frames(), 0);
        assert_eq!(counters.data_frames(), 0);
        assert_eq!(counters.other_frames(), 0);
        assert_eq!(counters.management_counts().total(), 0);
        assert_eq!(counters.channel_frames(1), 0);
        assert_eq!(counters.total_bytes(), 0);
        assert_eq!(counters.mean_frame_size(), 0.0);
    }

    #[test]
    fn a_data_frame_is_counted_as_data_and_not_as_eapol() {
        let mut counters = Counters::with_link_layer(LinkLayer::Radiotap);
        let mut body = vec![0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x08, 0x00];
        body.extend_from_slice(b"example-payload");
        counters.add(&data_frame(-50, 2412, &body));

        assert_eq!(counters.data_frames(), 1);
        assert_eq!(counters.eapol_frames(), 0);
        assert_eq!(counters.channel_frames(1), 1);
        assert!(counters.total_bytes() > 0);
    }

    #[test]
    fn the_strongest_signal_per_channel_is_kept_and_not_the_last_one() {
        let mut counters = Counters::with_link_layer(LinkLayer::Radiotap);
        counters.add(&beacon_frame(-80, 2412));
        counters.add(&beacon_frame(-45, 2412));
        counters.add(&beacon_frame(-70, 2412));

        // The strongest of the three is -45 dBm, and it is kept even though
        // a weaker frame came after it.
        assert_eq!(counters.strongest_signal(1), Some(-45));
        assert_eq!(counters.channel_frames(1), 3);
    }

    #[test]
    fn the_signal_is_kept_per_channel() {
        let mut counters = Counters::with_link_layer(LinkLayer::Radiotap);
        counters.add(&beacon_frame(-80, 2412)); // channel 1
        counters.add(&beacon_frame(-30, 5180)); // channel 36

        assert_eq!(counters.strongest_signal(1), Some(-80));
        assert_eq!(counters.strongest_signal(36), Some(-30));
    }

    #[test]
    fn the_busiest_channels_come_first() {
        let mut counters = Counters::with_link_layer(LinkLayer::Radiotap);
        counters.add(&beacon_frame(-50, 2412)); // channel 1
        counters.add(&beacon_frame(-50, 5180)); // channel 36
        counters.add(&beacon_frame(-50, 5180)); // channel 36
        counters.add(&beacon_frame(-50, 5180)); // channel 36

        let top = counters.top_channels(2);
        assert_eq!(top.len(), 2);
        assert_eq!(top[0].0, 36);
        assert_eq!(top[0].1.frames, 3);
        assert_eq!(top[1].0, 1);
        assert_eq!(top[1].1.frames, 1);
    }

    #[test]
    fn the_mean_frame_size_is_the_mean_of_the_counted_frames() {
        let mut counters = Counters::with_link_layer(LinkLayer::Radiotap);
        let frame = beacon_frame(-42, 2412);
        counters.add(&frame);
        counters.add(&frame);

        assert_eq!(counters.total_bytes(), (frame.len() * 2) as u64);
        assert_eq!(counters.mean_frame_size(), frame.len() as f64);
    }

    #[test]
    fn a_plain_80211_frame_is_counted_but_has_no_channel() {
        // On a link layer without a radiotap header the frame is the 802.11
        // frame itself: it is counted, but no channel and no signal level
        // can be named.
        let mut counters = Counters::with_link_layer(LinkLayer::Ieee80211);
        let radiotapped = beacon_frame(-42, 2412);
        let header_len = u16::from_le_bytes([radiotapped[2], radiotapped[3]]) as usize;
        counters.add(&radiotapped[header_len..]);

        assert_eq!(counters.total_frames(), 1);
        assert_eq!(counters.management_frames(), 1);
        assert_eq!(counters.management_counts().beacon, 1);
        assert_eq!(counters.channel_frames(1), 0);
        assert_eq!(counters.frames_without_channel(), 1);
        assert_eq!(counters.strongest_signal(1), None);
    }

    #[test]
    fn a_frame_with_a_broken_radiotap_header_is_counted_as_other() {
        let mut counters = Counters::with_link_layer(LinkLayer::Radiotap);
        counters.add(&[0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00]);

        assert_eq!(counters.other_frames(), 1);
        assert_eq!(counters.total_frames(), 1);
        assert_eq!(counters.frames_without_channel(), 1);
    }

    #[test]
    fn the_counters_keep_no_payload() {
        // The guardrail: a frame whose payload carries a distinctive marker
        // must leave no trace of it in the counters.
        let marker = "SECRETPORTPAYLOAD";
        let mut body = vec![0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x08, 0x00];
        body.extend_from_slice(marker.as_bytes());
        let frame = data_frame(-50, 2412, &body);

        let mut counters = Counters::with_link_layer(LinkLayer::Radiotap);
        counters.add(&frame);

        let rendered = format!("{counters:?}");
        assert!(
            !rendered.contains(marker),
            "the payload leaked into the counters: {rendered}"
        );
    }

    #[test]
    fn the_counters_keep_no_eapol_body() {
        // The same guardrail for the EAPOL path: the body of a handshake
        // frame is never kept.
        let marker = "SECRETPORTPAYLOAD";
        let mut body = LLC_SNAP_EAPOL.to_vec();
        body.extend_from_slice(marker.as_bytes());
        let frame = data_frame(-50, 2412, &body);

        let mut counters = Counters::with_link_layer(LinkLayer::Radiotap);
        counters.add(&frame);

        let rendered = format!("{counters:?}");
        assert!(
            !rendered.contains(marker),
            "the EAPOL body leaked into the counters: {rendered}"
        );
    }
}
