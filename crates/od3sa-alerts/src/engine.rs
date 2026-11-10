//! The engine: what the aggregator produced, and the alerts that follow.

use std::collections::{HashMap, VecDeque};

use od3sa_store::{AccessPoint as SeenAccessPoint, Deauth, Observation};
use serde_json::{Value as Json, json};

use crate::rules::{Rules, Severity, format_mac, format_oui};

/// How many devices the engine remembers by default.
///
/// The table is a working set, not a memory of everything: a busy channel
/// sees a lot of random addresses, so the table is capped and the oldest
/// entry is dropped when it is full.
pub const MAX_DEVICES: usize = 1024;

/// How many access points, one per SSID, the engine remembers by default.
pub const MAX_ACCESS_POINTS: usize = 256;

/// How many (BSSID, security) pairs the engine remembers for one SSID.
///
/// The pairs are what the rogue access point rule compares against, so their
/// number is capped as well.
pub const MAX_PAIRS_PER_SSID: usize = 8;

/// One alert.
#[derive(Debug, Clone, PartialEq)]
pub struct Alert {
    /// Which rule raised it.
    pub rule: String,
    /// How serious it is.
    pub severity: Severity,
    /// The device it is about, when it is about one.
    pub mac: Option<[u8; 6]>,
    /// A short line for a human.
    pub summary: String,
    /// Anything else worth keeping, as JSON.
    pub details: Json,
}

/// What the engine remembers about one device.
#[derive(Debug, Clone)]
struct Device {
    /// When it was first seen, in unix epoch milliseconds.
    first_seen_ms: i64,
    /// When it was last seen, in unix epoch milliseconds.
    last_seen_ms: i64,
    /// True when the watchlist has already been raised for this device's
    /// MAC or OUI.
    watchlist_alerted: bool,
    /// True when the watchlist has already been raised for the SSID this
    /// access point broadcasts.
    ssid_watchlist_alerted: bool,
    /// True when the strong signal rule has already fired for this device.
    strong_alerted: bool,
    /// The times, in unix epoch milliseconds, at which the recent events
    /// about this device were seen.
    events: VecDeque<i64>,
}

/// What the engine remembers about one SSID.
#[derive(Debug, Clone)]
struct SsidEntry {
    /// The access points seen with this name, and the security each was seen
    /// with.
    pairs: VecDeque<([u8; 6], Option<String>)>,
}

/// The engine: it watches what the aggregator produces and raises alerts.
///
/// The engine keeps the state the rules need: the devices it has seen, the
/// access points it has seen and their SSID, BSSID and security, and the
/// recent event counts per device. The state is bounded, so a long run on a
/// busy channel cannot grow without limit.
///
/// The engine does not write to the database. It returns the alerts; the
/// caller writes them to the `alerts` table and publishes them as
/// `alert.raised` events.
#[derive(Debug)]
pub struct AlertEngine {
    /// The rules.
    rules: Rules,
    /// How many devices the table holds.
    max_devices: usize,
    /// How many access points the table holds.
    max_access_points: usize,
    /// The devices seen.
    devices: HashMap<[u8; 6], Device>,
    /// The devices seen, oldest first. The order is what the cap drops from.
    device_order: VecDeque<[u8; 6]>,
    /// The access points seen, by SSID.
    access_points: HashMap<Vec<u8>, SsidEntry>,
    /// The SSIDs seen, oldest first.
    access_point_order: VecDeque<Vec<u8>>,
}

impl AlertEngine {
    /// An engine with the given rules.
    pub fn new(rules: Rules) -> AlertEngine {
        AlertEngine::with_limits(rules, MAX_DEVICES, MAX_ACCESS_POINTS)
    }

    /// An engine with the given rules and table sizes.
    ///
    /// The tables are capped so that a long run on a busy channel cannot grow
    /// without limit; the oldest entries are dropped. The sizes are a
    /// parameter so that a caller with a small memory budget can lower them.
    pub fn with_limits(rules: Rules, max_devices: usize, max_access_points: usize) -> AlertEngine {
        AlertEngine {
            rules,
            max_devices,
            max_access_points,
            devices: HashMap::new(),
            device_order: VecDeque::new(),
            access_points: HashMap::new(),
            access_point_order: VecDeque::new(),
        }
    }

    /// The rules the engine was built with.
    pub fn rules(&self) -> &Rules {
        &self.rules
    }

    /// How many devices the engine currently remembers.
    pub fn device_count(&self) -> usize {
        self.devices.len()
    }

    /// How many access points the engine currently remembers.
    pub fn access_point_count(&self) -> usize {
        self.access_points.len()
    }

    /// Feed one observation in, and get the alerts it raised.
    ///
    /// The engine keeps the state the rules need — which devices it has seen,
    /// which SSIDs it has seen on which access points, and how many events it
    /// has seen about each device recently.
    ///
    /// # What the deauthentication rule counts
    ///
    /// The rule is about *deauthentication or disassociation frames about the
    /// same device*, and it counts exactly those: the aggregator reports
    /// them in the observation's `deauth` field, with the station that was
    /// deauthenticated and the reason code.
    pub fn observe(&mut self, observation: &Observation, now_ms: i64) -> Vec<Alert> {
        let mut alerts = Vec::new();
        if !self.rules.enabled {
            return alerts;
        }

        if let Some(device) = observation.device.as_ref() {
            alerts.extend(self.observe_device(device.mac, device.kind, observation, now_ms));
        }

        if let Some(access_point) = observation.access_point.as_ref() {
            alerts.extend(self.observe_access_point(access_point, now_ms));
        }

        if let Some(deauth) = observation.deauth.as_ref() {
            alerts.extend(self.observe_deauth(deauth, now_ms));
        }

        alerts
    }

    /// The rules that are about one device.
    fn observe_device(
        &mut self,
        mac: [u8; 6],
        kind: &str,
        observation: &Observation,
        now_ms: i64,
    ) -> Vec<Alert> {
        let mut alerts = Vec::new();
        let known = self.devices.contains_key(&mac);

        // A device the engine has not seen before.
        if !known {
            if let Some(rule) = self.rules.new_device.as_ref()
                && rule.enabled
            {
                alerts.push(Alert {
                    rule: "new_device".to_string(),
                    severity: rule.severity,
                    mac: Some(mac),
                    summary: format!("new device {}", format_mac(mac)),
                    details: json!({
                        "kind": kind,
                        "oui": format_oui(mac),
                        "first_seen_ms": now_ms,
                    }),
                });
            }
            self.remember_device(mac, now_ms);
        }

        // A device that was seen before, after an absence.
        if known {
            let last_seen = self.devices[&mac].last_seen_ms;
            let gap_ms = now_ms - last_seen;
            if let Some(rule) = self.rules.seen_again.as_ref()
                && rule.enabled
            {
                let after_ms = rule.after_seconds.saturating_mul(1000) as i64;
                if gap_ms >= after_ms {
                    alerts.push(Alert {
                        rule: "seen_again".to_string(),
                        severity: rule.severity,
                        mac: Some(mac),
                        summary: format!(
                            "{} seen again after {} s",
                            format_mac(mac),
                            gap_ms / 1000
                        ),
                        details: json!({
                            "kind": kind,
                            "gap_seconds": gap_ms / 1000,
                            "first_seen_ms": self.devices[&mac].first_seen_ms,
                            "last_seen_ms": last_seen,
                        }),
                    });
                }
            }
        }

        if let Some(device) = self.devices.get_mut(&mac) {
            device.last_seen_ms = now_ms;
        }

        // A device that is on the watchlist.
        let watchlist = self
            .rules
            .watchlist
            .as_ref()
            .map(|rule| (rule.enabled, rule.severity, rule.matches_mac(mac)));
        if let Some((true, severity, true)) = watchlist {
            let alerted = self
                .devices
                .get(&mac)
                .map(|device| device.watchlist_alerted)
                .unwrap_or(false);
            if !alerted {
                if let Some(device) = self.devices.get_mut(&mac) {
                    device.watchlist_alerted = true;
                }
                alerts.push(Alert {
                    rule: "watchlist".to_string(),
                    severity,
                    mac: Some(mac),
                    summary: format!("{} is on the watchlist", format_mac(mac)),
                    details: json!({ "kind": kind, "match": "mac" }),
                });
            }
        }

        // A signal stronger than the threshold.
        let strong = self
            .rules
            .strong_signal
            .as_ref()
            .map(|rule| (rule.enabled, rule.severity, rule.rssi_above));
        if let Some((true, severity, rssi_above)) = strong {
            let already = self
                .devices
                .get(&mac)
                .map(|device| device.strong_alerted)
                .unwrap_or(false);
            if !already {
                let rssi = observation
                    .sighting
                    .as_ref()
                    .and_then(|sighting| sighting.rssi)
                    .or_else(|| observation.client.as_ref().and_then(|client| client.rssi));
                if let Some(rssi) = rssi
                    && rssi > rssi_above
                {
                    if let Some(device) = self.devices.get_mut(&mac) {
                        device.strong_alerted = true;
                    }
                    alerts.push(Alert {
                        rule: "strong_signal".to_string(),
                        severity,
                        mac: Some(mac),
                        summary: format!("{} at {} dBm", format_mac(mac), rssi),
                        details: json!({ "kind": kind, "rssi": rssi }),
                    });
                }
            }
        }

        alerts
    }

    /// The rules that are about one access point.
    fn observe_access_point(&mut self, access_point: &SeenAccessPoint, now_ms: i64) -> Vec<Alert> {
        let mut alerts = Vec::new();
        let Some(ssid) = access_point.ssid.as_ref() else {
            return alerts;
        };

        // The same SSID on another access point, or with other security.
        let rogue = self
            .rules
            .rogue_ap
            .as_ref()
            .map(|rule| (rule.enabled, rule.severity));
        if let Some((true, severity)) = rogue {
            alerts.extend(self.check_rogue_ap(access_point, ssid, severity));
        }

        // An access point whose SSID is on the watchlist.
        let watchlist = self
            .rules
            .watchlist
            .as_ref()
            .map(|rule| (rule.enabled, rule.severity, rule.matches_ssid(ssid)));
        if let Some((true, severity, true)) = watchlist {
            let bssid = access_point.bssid;
            self.remember_device(bssid, now_ms);
            let alerted = self
                .devices
                .get(&bssid)
                .map(|device| device.ssid_watchlist_alerted)
                .unwrap_or(false);
            if !alerted {
                if let Some(device) = self.devices.get_mut(&bssid) {
                    device.ssid_watchlist_alerted = true;
                }
                alerts.push(Alert {
                    rule: "watchlist".to_string(),
                    severity,
                    mac: Some(bssid),
                    summary: format!(
                        "access point {} broadcasts the watched SSID",
                        format_mac(bssid)
                    ),
                    details: json!({
                        "match": "ssid",
                        "ssid": String::from_utf8_lossy(ssid),
                    }),
                });
            }
        }

        alerts
    }

    /// The deauthentication rule: a burst of deauthentication or
    /// disassociation frames about the same device.
    fn observe_deauth(&mut self, deauth: &Deauth, now_ms: i64) -> Vec<Alert> {
        let mac = deauth.mac;
        let mut alerts: Vec<Alert> = Vec::new();
        let deauth = self
            .rules
            .deauth_burst
            .as_ref()
            .map(|rule| (rule.enabled, rule.severity, rule.count, rule.within_seconds));
        let Some((true, severity, count, within_seconds)) = deauth else {
            return alerts;
        };

        self.remember_device(mac, now_ms);
        let window_ms = within_seconds.saturating_mul(1000) as i64;

        let Some(device) = self.devices.get_mut(&mac) else {
            return alerts;
        };

        // The old ones are forgotten.
        while let Some(front) = device.events.front() {
            if now_ms - *front > window_ms {
                device.events.pop_front();
            } else {
                break;
            }
        }
        device.events.push_back(now_ms);

        if device.events.len() as u32 >= count {
            // The burst is announced once, not once per frame.
            device.events.clear();
            alerts.push(Alert {
                rule: "deauth_burst".to_string(),
                severity,
                mac: Some(mac),
                summary: format!(
                    "{} deauthentication frames about {} in {} s",
                    count,
                    format_mac(mac),
                    within_seconds
                ),
                details: json!({
                    "count": count,
                    "within_seconds": within_seconds,
                    "measured": "deauthentication_frames",
                }),
            });
        }

        alerts
    }

    /// Put a device into the table, dropping the oldest one when the table
    /// is full.
    ///
    /// A device that is already in the table is only marked as seen again:
    /// its last sighting moves forward, so that the "seen again" rule
    /// measures the gap from the last sighting and not from the first one.
    fn remember_device(&mut self, mac: [u8; 6], now_ms: i64) {
        if let Some(device) = self.devices.get_mut(&mac) {
            device.last_seen_ms = now_ms;
            return;
        }
        self.devices.insert(
            mac,
            Device {
                first_seen_ms: now_ms,
                last_seen_ms: now_ms,
                watchlist_alerted: false,
                ssid_watchlist_alerted: false,
                strong_alerted: false,
                events: VecDeque::new(),
            },
        );
        self.device_order.push_back(mac);
        while self.devices.len() > self.max_devices {
            let Some(oldest) = self.device_order.pop_front() else {
                break;
            };
            self.devices.remove(&oldest);
        }
    }

    /// The rogue access point rule: the same SSID on a different access
    /// point, or with different security.
    fn check_rogue_ap(
        &mut self,
        access_point: &SeenAccessPoint,
        ssid: &[u8],
        severity: Severity,
    ) -> Vec<Alert> {
        let bssid = access_point.bssid;
        let security = access_point.security.clone();

        let known_pairs = match self.access_points.get(ssid) {
            Some(entry) => entry.pairs.clone(),
            None => {
                // The name has not been seen before: there is nothing to
                // compare it with, so this is not an alert.
                self.access_points.insert(
                    ssid.to_vec(),
                    SsidEntry {
                        pairs: VecDeque::from([(bssid, security)]),
                    },
                );
                self.access_point_order.push_back(ssid.to_vec());
                while self.access_points.len() > self.max_access_points {
                    let Some(oldest) = self.access_point_order.pop_front() else {
                        break;
                    };
                    self.access_points.remove(&oldest);
                }
                return Vec::new();
            }
        };

        if known_pairs
            .iter()
            .any(|(seen_bssid, seen_security)| *seen_bssid == bssid && seen_security == &security)
        {
            // The same access point, with the same security, seen again.
            return Vec::new();
        }

        // The name has been seen before, but not on this access point with
        // this security: something else is claiming the name.
        let previous = known_pairs
            .iter()
            .find(|(seen_bssid, _)| *seen_bssid == bssid)
            .cloned()
            .or_else(|| known_pairs.front().cloned())
            .unwrap_or((bssid, security.clone()));

        let details = json!({
            "ssid": String::from_utf8_lossy(ssid),
            "bssid": format_mac(bssid),
            "security": security,
            "known_bssid": format_mac(previous.0),
            "known_security": previous.1,
        });

        let summary = if previous.0 == bssid {
            format!(
                "the SSID {} changed security on {}",
                String::from_utf8_lossy(ssid),
                format_mac(bssid)
            )
        } else {
            format!(
                "the SSID {} is also broadcast by {}",
                String::from_utf8_lossy(ssid),
                format_mac(previous.0)
            )
        };

        if let Some(entry) = self.access_points.get_mut(ssid) {
            entry.pairs.push_back((bssid, security));
            while entry.pairs.len() > MAX_PAIRS_PER_SSID {
                entry.pairs.pop_front();
            }
        }

        vec![Alert {
            rule: "rogue_ap".to_string(),
            severity,
            mac: Some(bssid),
            summary,
            details,
        }]
    }
}
