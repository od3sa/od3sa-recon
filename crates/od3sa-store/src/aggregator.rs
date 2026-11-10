//! The aggregator: one captured frame in, the rows it implies out.
//!
//! The daemon sees frames. The database holds devices, access points,
//! clients, probes and sightings. This module is the thing in between: it
//! turns one frame into the rows that frame implies, and it keeps a bounded
//! in-memory table of the devices it has seen, so that the same device does
//! not become a new row every time it is seen.
//!
//! # The frame is parsed elsewhere
//!
//! Nothing here parses a frame. The parsing lives in `od3sa-parse`, and this
//! module drives it: [`od3sa_parse::frame::dispatch`] says what kind of frame
//! it is, and for a management frame
//! [`od3sa_parse::ieee80211::management_ie_offset`] says where the
//! information elements start, which [`od3sa_parse::ie::parse_ies`] and
//! [`od3sa_parse::ie::summarize`] then read.
//!
//! # A malformed frame is not an error
//!
//! The daemon must not stop because one frame is odd. A frame that cannot be
//! parsed yields an empty [`Observation`] and no error, so the caller can
//! keep going.
//!
//! # Metadata only
//!
//! The aggregator keeps the MAC address, the SSID, the security and the
//! signal level. It never keeps a frame body and never keeps an EAPOL body:
//! there is no field for one, and the frame body is never copied out of the
//! buffer it came in.

use std::collections::VecDeque;
use std::sync::{Mutex, OnceLock};

use od3sa_parse::frame::{FrameClass, dispatch};
use od3sa_parse::ie::{Akm, Cipher, ElementSummary, Security, parse_ies, summarize};
use od3sa_parse::ieee80211::{MAC_HEADER_LEN, management_ie_offset};
use od3sa_parse::radiotap;

use crate::StoreError;

/// The management subtype of a beacon.
const SUBTYPE_BEACON: u8 = 8;
/// The management subtype of a probe response.
const SUBTYPE_PROBE_RESPONSE: u8 = 5;
/// The management subtype of a probe request.
const SUBTYPE_PROBE_REQUEST: u8 = 4;
/// The management subtype of an association request.
const SUBTYPE_ASSOC_REQUEST: u8 = 0;
/// The management subtype of an association response.
const SUBTYPE_ASSOC_RESPONSE: u8 = 1;
/// The disassociation frame subtype.
const SUBTYPE_DISASSOC: u8 = 10;
/// The deauthentication frame subtype.
const SUBTYPE_DEAUTH: u8 = 12;

/// The offset of the beacon interval inside a beacon's fixed fields.
///
/// A beacon carries a timestamp (eight bytes) and then the beacon interval
/// (two bytes) before its information elements.
const BEACON_INTERVAL_OFFSET: usize = 8;

/// The length of the beacon interval field.
const BEACON_INTERVAL_LEN: usize = 2;

/// The RSN capabilities bit that says management frame protection is
/// required.
///
/// IEEE 802.11 Table 12-5: bit 6 of the two byte RSN capabilities field is
/// `MFPR`, "management frame protection required".
const RSN_CAP_MFPR: u16 = 0x0040;

/// The name given to a source when there are more distinct sources than the
/// aggregator is willing to remember.
const SOURCE_FALLBACK: &str = "unknown";

/// How many distinct source names are interned.
///
/// The names are interned once each, so this bounds the memory the process
/// ever takes for them.
const MAX_SOURCES: usize = 64;

/// The interned source names of the process.
///
/// A [`Sighting`] holds its source as a `&'static str`, so the name has to
/// live for as long as the sighting does. The names are interned here, once
/// each, rather than leaked per frame: the table is bounded and the process
/// has a handful of sources.
fn source_table() -> &'static Mutex<Vec<&'static str>> {
    static TABLE: OnceLock<Mutex<Vec<&'static str>>> = OnceLock::new();
    TABLE.get_or_init(|| Mutex::new(Vec::new()))
}

/// Intern a source name, so that it can be held in a `&'static str`.
///
/// A name that is already interned is returned as it is. A name beyond the
/// table's capacity is reported as [`SOURCE_FALLBACK`], so the table can
/// never grow without bound.
fn intern_source(source: &str) -> &'static str {
    let Ok(mut table) = source_table().lock() else {
        // A poisoned lock means another thread panicked while holding it.
        // The name is not important enough to panic over.
        return SOURCE_FALLBACK;
    };

    for name in table.iter() {
        if *name == source {
            return name;
        }
    }

    if table.len() >= MAX_SOURCES {
        return SOURCE_FALLBACK;
    }

    let name: &'static str = Box::leak(source.to_string().into_boxed_str());
    table.push(name);
    name
}

/// What kind of link layer a captured frame has.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LinkLayer {
    /// 802.11 frames with a radiotap header in front of them.
    #[default]
    Radiotap,
    /// 802.11 frames with no radiotap header.
    Ieee80211,
}

/// A device the aggregator has seen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Device {
    /// The six byte MAC address.
    pub mac: [u8; 6],
    /// The first three bytes of the address.
    pub oui: [u8; 3],
    /// "ap", "client", "ble" or "unknown".
    pub kind: &'static str,
    /// True when the address is a locally administered one: the top two bits
    /// of the first octet are set.
    pub randomized: bool,
    /// True when this is the first time the aggregator has seen this
    /// device.
    ///
    /// The aggregator is the thing that remembers the devices it has seen,
    /// so it is the thing that can say whether one is new. The collector
    /// publishes `device.new` from this flag, so that the event is published
    /// once rather than on every frame.
    pub new: bool,
}

/// An access point, as far as a frame reveals one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessPoint {
    /// The BSSID.
    pub bssid: [u8; 6],
    /// The SSID bytes, if the frame carried one.
    pub ssid: Option<Vec<u8>>,
    /// True when the SSID element was empty.
    pub ssid_hidden: bool,
    /// The channel, from the radiotap header.
    pub channel: Option<u16>,
    /// The centre frequency in MHz.
    pub freq_mhz: Option<u16>,
    /// "2.4", "5" or "6".
    pub band: Option<&'static str>,
    /// A short security label: "WPA2-PSK", "WPA3-SAE", "WEP", "open".
    pub security: Option<String>,
    /// The AKM suite names, comma separated.
    pub akm: Option<String>,
    /// The pairwise cipher names, comma separated.
    pub pairwise: Option<String>,
    /// The group cipher name.
    pub group_cipher: Option<String>,
    /// True when the RSN capabilities say PMF is required.
    pub pmf_required: bool,
    /// True when the frame carried WPS information.
    pub wps: bool,
    /// True when the frame carried HT information.
    pub ht: bool,
    /// True when the frame carried VHT information.
    pub vht: bool,
    /// True when the frame carried HE information.
    pub he: bool,
    /// The beacon interval, in TU.
    pub beacon_interval: Option<u16>,
}

/// A sighting of a device.
#[derive(Debug, Clone, PartialEq)]
pub struct Sighting {
    /// The device that was seen.
    pub mac: [u8; 6],
    /// When it was seen, in unix epoch milliseconds.
    pub ts_ms: i64,
    /// The signal level in dBm, if the frame carried one.
    pub rssi: Option<i8>,
    /// The channel it was seen on.
    pub channel: Option<u16>,
    /// The source that saw it. The writer maps this to a `sources` row.
    pub source: &'static str,
    /// The latitude, when there was a position to tag it with.
    ///
    /// The aggregator does not know where the collector is, so these are
    /// empty here; the collector fills them in from gpsd before the
    /// sighting is written.
    pub lat: Option<f64>,
    /// The longitude, when there was a position.
    pub lon: Option<f64>,
    /// The altitude in metres, when there was a position.
    pub alt: Option<f64>,
    /// The fix mode: 1 none, 2 two-dimensional, 3 three-dimensional.
    pub fix: Option<u8>,
}

/// A probe request: a station looking for a network.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Probe {
    /// The station that probed.
    pub mac: [u8; 6],
    /// The SSID it asked for.
    pub ssid: Vec<u8>,
    /// When it probed, in unix epoch milliseconds.
    pub ts_ms: i64,
    /// The signal level in dBm, if the frame carried one.
    pub rssi: Option<i8>,
}

/// A client seen associated with an access point.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientLink {
    /// The station.
    pub mac: [u8; 6],
    /// The access point.
    pub bssid: [u8; 6],
    /// When the link was seen, in unix epoch milliseconds.
    pub ts_ms: i64,
    /// The signal level in dBm, if the frame carried one.
    pub rssi: Option<i8>,
}

/// A deauthentication or disassociation frame.
///
/// The station that was deauthenticated or disassociated is the frame's
/// address 1 — the frame is addressed to it — and the sender, normally the
/// access point, is address 2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Deauth {
    /// The station that was deauthenticated or disassociated.
    pub mac: [u8; 6],
    /// The access point that sent the frame.
    pub bssid: [u8; 6],
    /// The reason code, when the frame carried one.
    pub reason: Option<u8>,
}

/// What one frame turned into.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Observation {
    /// The device the frame was about, if any.
    pub device: Option<Device>,
    /// The access point the frame was about, if any.
    pub access_point: Option<AccessPoint>,
    /// The sighting of the device.
    pub sighting: Option<Sighting>,
    /// The probe, for a probe request.
    pub probe: Option<Probe>,
    /// The client-to-AP link, for a data frame or an association.
    pub client: Option<ClientLink>,
    /// The deauthentication, for a deauthentication or disassociation frame.
    pub deauth: Option<Deauth>,
    /// Whether the frame could be parsed at all.
    ///
    /// A frame that could not be parsed is not an error — one odd frame in a
    /// million is normal, and the daemon must not stop for it. But it is
    /// worth counting, so that a collector can tell a busy channel from a
    /// broken one.
    pub parsed: bool,
}

/// What the capture layer knows about one frame, besides its bytes.
///
/// The radiotap header carries the signal level and the channel; the caller
/// carries the time and the source.
#[derive(Debug, Clone, Copy)]
struct FrameContext {
    /// When the frame was seen, in unix epoch milliseconds.
    ts_ms: i64,
    /// The source that saw it.
    source: &'static str,
    /// The signal level in dBm.
    rssi: Option<i8>,
    /// The channel the frame was seen on.
    channel: Option<u16>,
    /// The centre frequency in MHz.
    freq_mhz: Option<u16>,
    /// The band the centre frequency belongs to.
    band: Option<&'static str>,
}

/// A bounded table of the devices seen recently.
///
/// The table is the working set, not the memory of everything: a long run on
/// a busy channel sees a lot of random MAC addresses, so the table is capped
/// and the oldest entries are dropped. The database is where everything is
/// kept.
#[derive(Debug)]
pub struct Aggregator {
    /// The devices, oldest first.
    devices: VecDeque<Device>,
    /// How many devices the table holds at most.
    capacity: usize,
}

impl Aggregator {
    /// A new aggregator whose device table holds at most `capacity` devices.
    /// The oldest device is dropped when the table is full.
    pub fn new(capacity: usize) -> Aggregator {
        Aggregator {
            devices: VecDeque::new(),
            capacity,
        }
    }

    /// How many devices the table currently holds.
    pub fn len(&self) -> usize {
        self.devices.len()
    }

    /// True when the table holds no devices.
    pub fn is_empty(&self) -> bool {
        self.devices.is_empty()
    }

    /// True when the table holds the given device.
    ///
    /// The table has no other way to be looked at: the aggregator keeps the
    /// working set to itself and hands out one device per observation.
    pub fn contains(&self, mac: [u8; 6]) -> bool {
        self.devices.iter().any(|device| device.mac == mac)
    }

    /// Turn one captured frame into what it says.
    ///
    /// # Errors
    ///
    /// There is no error to report: a frame that cannot be parsed yields an
    /// empty observation. The result type is kept because the caller is the
    /// daemon, which treats every frame the same way.
    pub fn observe(
        &mut self,
        frame: &[u8],
        link: LinkLayer,
        ts_ms: i64,
        source: &str,
    ) -> Result<Observation, StoreError> {
        let source = intern_source(source);

        // The radiotap header carries the signal level and the channel. A
        // header that does not parse means the frame is malformed, and a
        // malformed frame is not an error.
        let (frame, rssi, freq_mhz) = match link {
            LinkLayer::Radiotap => match radiotap::parse(frame) {
                Ok(header) => {
                    let start = header.len as usize;
                    let body = frame.get(start..).unwrap_or(&[]);
                    (
                        body,
                        header.signal_dbm,
                        header.channel.map(|channel| channel.freq_mhz),
                    )
                }
                Err(_) => return Ok(Observation::default()),
            },
            LinkLayer::Ieee80211 => (frame, None, None),
        };

        let channel = freq_mhz.and_then(radiotap::channel_number);
        let band = freq_mhz.and_then(band_of);

        let context = FrameContext {
            ts_ms,
            source,
            rssi,
            channel,
            freq_mhz,
            band,
        };

        let class = match dispatch(frame) {
            Ok(class) => class,
            // The frame could not be parsed. That is not an error, but it is
            // counted: the observation says so.
            Err(_) => {
                let mut observation = Observation {
                    parsed: true,
                    ..Observation::default()
                };
                observation.parsed = false;
                return Ok(observation);
            }
        };

        match class {
            FrameClass::Management {
                header, subtype, ..
            } => self.observe_management(&header, subtype, frame, &context),
            FrameClass::Data { mapping, .. } => {
                let mut observation = Observation {
                    parsed: true,
                    ..Observation::default()
                };

                if let Some(client) = mapping.client {
                    let new = self.remember(client, "client");
                    let device = device_of(client, "client", new);
                    observation.device = Some(device);
                    observation.sighting = Some(Sighting {
                        lat: None,
                        lon: None,
                        alt: None,
                        fix: None,
                        mac: client,
                        ts_ms: context.ts_ms,
                        rssi: context.rssi,
                        channel: context.channel,
                        source: context.source,
                    });
                }

                if let Some(bssid) = mapping.bssid {
                    // The access point of the network is a device of its own.
                    self.remember(bssid, "ap");
                    if let Some(client) = mapping.client {
                        observation.client = Some(ClientLink {
                            mac: client,
                            bssid,
                            ts_ms: context.ts_ms,
                            rssi: context.rssi,
                        });
                    }
                }

                Ok(observation)
            }
            FrameClass::Control { .. }
            | FrameClass::Extension { .. }
            | FrameClass::Unknown { .. } => Ok(Observation {
                parsed: true,
                ..Observation::default()
            }),
        }
    }

    /// Handle a management frame.
    fn observe_management(
        &mut self,
        header: &od3sa_parse::ieee80211::MacHeader,
        subtype: u8,
        frame: &[u8],
        context: &FrameContext,
    ) -> Result<Observation, StoreError> {
        let mut observation = Observation {
            parsed: true,
            ..Observation::default()
        };

        match subtype {
            SUBTYPE_BEACON | SUBTYPE_PROBE_RESPONSE => {
                let bssid = header.addr3;
                let summary = elements_of(frame, subtype);

                let new = self.remember(bssid, "ap");
                observation.device = Some(device_of(bssid, "ap", new));
                observation.access_point = Some(access_point_of(
                    bssid,
                    &summary,
                    context.channel,
                    context.freq_mhz,
                    context.band,
                    frame,
                ));
                observation.sighting = Some(Sighting {
                    lat: None,
                    lon: None,
                    alt: None,
                    fix: None,
                    mac: bssid,
                    ts_ms: context.ts_ms,
                    rssi: context.rssi,
                    channel: context.channel,
                    source: context.source,
                });
            }
            SUBTYPE_PROBE_REQUEST => {
                let station = header.addr2;
                let summary = elements_of(frame, subtype);

                let new = self.remember(station, "client");
                observation.device = Some(device_of(station, "client", new));

                if let Some(ssid) = summary.ssid {
                    observation.probe = Some(Probe {
                        mac: station,
                        ssid: ssid.bytes,
                        ts_ms: context.ts_ms,
                        rssi: context.rssi,
                    });
                }
                observation.sighting = Some(Sighting {
                    lat: None,
                    lon: None,
                    alt: None,
                    fix: None,
                    mac: station,
                    ts_ms: context.ts_ms,
                    rssi: context.rssi,
                    channel: context.channel,
                    source: context.source,
                });
            }
            SUBTYPE_ASSOC_REQUEST | SUBTYPE_ASSOC_RESPONSE => {
                let station = header.addr2;
                let bssid = header.addr3;

                let new = self.remember(station, "client");
                self.remember(bssid, "ap");
                observation.device = Some(device_of(station, "client", new));
                observation.client = Some(ClientLink {
                    mac: station,
                    bssid,
                    ts_ms: context.ts_ms,
                    rssi: context.rssi,
                });
                observation.sighting = Some(Sighting {
                    lat: None,
                    lon: None,
                    alt: None,
                    fix: None,
                    mac: station,
                    ts_ms: context.ts_ms,
                    rssi: context.rssi,
                    channel: context.channel,
                    source: context.source,
                });
            }
            SUBTYPE_DEAUTH | SUBTYPE_DISASSOC => {
                // The frame is addressed to the station that is being
                // deauthenticated, and comes from the access point.
                let station = header.addr1;
                let bssid = header.addr2;

                let new = self.remember(station, "client");
                observation.device = Some(device_of(station, "client", new));
                observation.deauth = Some(Deauth {
                    mac: station,
                    bssid,
                    reason: reason_code(frame, subtype),
                });
                observation.sighting = Some(Sighting {
                    lat: None,
                    lon: None,
                    alt: None,
                    fix: None,
                    mac: station,
                    ts_ms: context.ts_ms,
                    rssi: context.rssi,
                    channel: context.channel,
                    source: context.source,
                });
            }
            _ => {}
        }

        Ok(observation)
    }

    /// Put a device into the table, dropping the oldest one when the table is
    /// full.
    /// Remember a device, and say whether it was new.
    fn remember(&mut self, mac: [u8; 6], kind: &'static str) -> bool {
        if let Some(existing) = self.devices.iter_mut().find(|device| device.mac == mac) {
            // The more specific kind wins: a device first seen as a client
            // and later seen as an access point is an access point.
            if kind_rank(kind) > kind_rank(existing.kind) {
                existing.kind = kind;
            }
            return false;
        }

        if self.capacity == 0 {
            return false;
        }

        self.devices.push_back(device_of(mac, kind, true));
        while self.devices.len() > self.capacity {
            self.devices.pop_front();
        }
        true
    }
}

/// How specific a device kind is: the higher the number, the more the kind
/// says about the device.
fn kind_rank(kind: &str) -> u8 {
    match kind {
        "ap" => 3,
        "ble" => 2,
        "client" => 1,
        _ => 0,
    }
}

/// The device a MAC address names.
fn device_of(mac: [u8; 6], kind: &'static str, new: bool) -> Device {
    Device {
        mac,
        oui: [mac[0], mac[1], mac[2]],
        kind,
        randomized: mac[0] & 0b1100_0000 == 0b1100_0000,
        new,
    }
}

/// The band a centre frequency belongs to.
fn band_of(freq_mhz: u16) -> Option<&'static str> {
    match freq_mhz {
        2400..=2500 => Some("2.4"),
        4900..=5899 => Some("5"),
        5900..=7125 => Some("6"),
        _ => None,
    }
}

/// The elements of a management frame, summarised.
///
/// A frame whose elements do not parse has no elements as far as the
/// aggregator is concerned: the frame is still worth a sighting.
/// The reason code of a deauthentication or disassociation frame.
///
/// It is the first two bytes of the frame body, after the MAC header.
fn reason_code(frame: &[u8], subtype: u8) -> Option<u8> {
    if subtype != SUBTYPE_DEAUTH && subtype != SUBTYPE_DISASSOC {
        return None;
    }
    let body = frame.get(MAC_HEADER_LEN..)?;
    let bytes = body.get(..2)?;
    Some(u16::from_le_bytes([bytes[0], bytes[1]]) as u8)
}

fn elements_of(frame: &[u8], subtype: u8) -> ElementSummary {
    let Some(offset) = management_ie_offset(subtype) else {
        return ElementSummary::default();
    };
    let Some(body) = frame.get(MAC_HEADER_LEN + offset..) else {
        return ElementSummary::default();
    };
    match parse_ies(body) {
        Ok(ies) => summarize(&ies),
        Err(_) => ElementSummary::default(),
    }
}

/// The beacon interval of a beacon frame, in TU.
fn beacon_interval_of(frame: &[u8]) -> Option<u16> {
    let body = frame.get(MAC_HEADER_LEN..)?;
    let bytes = body.get(BEACON_INTERVAL_OFFSET..BEACON_INTERVAL_OFFSET + BEACON_INTERVAL_LEN)?;
    Some(u16::from_le_bytes([bytes[0], bytes[1]]))
}

/// The access point a beacon or a probe response describes.
fn access_point_of(
    bssid: [u8; 6],
    summary: &ElementSummary,
    channel: Option<u16>,
    freq_mhz: Option<u16>,
    band: Option<&'static str>,
    frame: &[u8],
) -> AccessPoint {
    let security = summary.security.as_ref();
    let pmf_required = security
        .and_then(|security| security.rsn_capabilities)
        .map(|capabilities| capabilities & RSN_CAP_MFPR != 0)
        .unwrap_or(false);

    AccessPoint {
        bssid,
        ssid: summary.ssid.as_ref().map(|ssid| ssid.bytes.clone()),
        ssid_hidden: summary
            .ssid
            .as_ref()
            .map(|ssid| ssid.hidden)
            .unwrap_or(false),
        channel,
        freq_mhz,
        band,
        security: Some(security_label(security)),
        akm: security.map(|security| {
            security
                .akm
                .iter()
                .map(akm_name)
                .collect::<Vec<String>>()
                .join(",")
        }),
        pairwise: security.map(|security| {
            security
                .pairwise
                .iter()
                .map(cipher_name)
                .collect::<Vec<String>>()
                .join(",")
        }),
        group_cipher: security
            .and_then(|security| security.group.as_ref())
            .map(cipher_name),
        pmf_required,
        wps: summary.wps.is_some(),
        ht: summary.ht,
        vht: summary.vht,
        he: summary.he,
        beacon_interval: beacon_interval_of(frame),
    }
}

/// The short security label of a network.
///
/// The contract names four labels: "WPA2-PSK", "WPA3-SAE", "WEP" and
/// "open". Two more are used where the four would be wrong: an enterprise
/// network is "WPA2-ENTERPRISE" rather than a personal one, and a network
/// in transition mode, which offers both PSK and SAE, says so rather than
/// being called a WPA2 network.
fn security_label(security: Option<&Security>) -> String {
    let Some(security) = security else {
        return "open".to_string();
    };

    let has_akm = |want: fn(&Akm) -> bool| security.akm.iter().any(want);
    let psk = has_akm(|akm| matches!(akm, Akm::Psk | Akm::PskSha256 | Akm::FtPsk));
    let sae = has_akm(|akm| matches!(akm, Akm::Sae | Akm::FtSae | Akm::SaeH2e | Akm::FtSaeH2e));
    let eap = has_akm(|akm| matches!(akm, Akm::Eap | Akm::FtEap | Akm::EapSha256));

    let wep = security
        .pairwise
        .iter()
        .chain(security.group.iter())
        .any(|cipher| matches!(cipher, Cipher::Wep40 | Cipher::Wep104));

    if wep {
        return "WEP".to_string();
    }

    // A WPA1 network is described by a vendor element, not by an RSN one.
    if !security.rsn {
        return match (psk, eap) {
            (true, _) => "WPA-PSK".to_string(),
            (false, true) => "WPA-ENTERPRISE".to_string(),
            _ => "WPA".to_string(),
        };
    }

    match (psk, sae, eap) {
        (true, true, _) => "WPA2-PSK+WPA3-SAE".to_string(),
        (false, true, _) => "WPA3-SAE".to_string(),
        (true, false, _) => "WPA2-PSK".to_string(),
        (false, false, true) => "WPA2-ENTERPRISE".to_string(),
        (false, false, false) => "UNKNOWN".to_string(),
    }
}

/// The name of an AKM suite.
fn akm_name(akm: &Akm) -> String {
    match akm {
        Akm::Psk => "PSK".to_string(),
        Akm::PskSha256 => "PSK-SHA256".to_string(),
        Akm::Eap => "EAP".to_string(),
        Akm::EapSha256 => "EAP-SHA256".to_string(),
        Akm::FtEap => "FT-EAP".to_string(),
        Akm::FtPsk => "FT-PSK".to_string(),
        Akm::Sae => "SAE".to_string(),
        Akm::FtSae => "FT-SAE".to_string(),
        Akm::SaeH2e => "SAE-H2E".to_string(),
        Akm::FtSaeH2e => "FT-SAE-H2E".to_string(),
        Akm::Owe => "OWE".to_string(),
        Akm::Other(selector) => selector_name(selector),
    }
}

/// The name of a cipher suite.
fn cipher_name(cipher: &Cipher) -> String {
    match cipher {
        Cipher::Wep40 => "WEP-40".to_string(),
        Cipher::Wep104 => "WEP-104".to_string(),
        Cipher::Tkip => "TKIP".to_string(),
        Cipher::Ccmp => "CCMP".to_string(),
        Cipher::Ccmp256 => "CCMP-256".to_string(),
        Cipher::Gcmp => "GCMP".to_string(),
        Cipher::Gcmp256 => "GCMP-256".to_string(),
        Cipher::Bip => "BIP".to_string(),
        Cipher::BipCmac => "BIP-CMAC-128".to_string(),
        Cipher::Other(selector) => selector_name(selector),
    }
}

/// The name of a suite selector that is not in the table.
fn selector_name(selector: &[u8; 4]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}",
        selector[0], selector[1], selector[2], selector[3]
    )
}
