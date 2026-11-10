//! The events the collector publishes.
//!
//! The topics and their shapes are in `docs/api/events.md`. The rules here
//! are:
//!
//! - **`device.new` and `ap.new` are published when the device or the access
//!   point is new**, not every time it is seen. The aggregator is the thing
//!   that remembers what it has seen, so it is the thing that says.
//! - **`client.assoc` and `probe.seen` are published when the link or the
//!   probe is seen.** They are already rare: a probe request is a station
//!   looking for a network.
//! - **`alert.raised` is published for every alert.**

use od3sa_alerts::Alert;
use od3sa_events::Event;
use od3sa_store::Observation;
use serde_json::json;

/// The API version the events carry.
pub const API_VERSION: u32 = 0;

/// The events an observation and its alerts call for.
pub fn events_for(observation: &Observation, alerts: &[Alert], ts_ms: i64) -> Vec<Event> {
    let mut events = Vec::new();

    if let Some(device) = &observation.device
        && device.new
    {
        events.push(event(
            "device.new",
            ts_ms,
            json!({
                "mac": format_mac(device.mac),
                "kind": device.kind,
                "oui": format_oui(device.oui),
                "randomized": device.randomized,
                "rssi": observation.sighting.as_ref().and_then(|s| s.rssi),
                "channel": observation.sighting.as_ref().and_then(|s| s.channel),
                "source": observation.sighting.as_ref().map(|s| s.source),
            }),
        ));
    }

    if let Some(access_point) = &observation.access_point {
        let is_new = observation
            .device
            .as_ref()
            .map(|device| device.new)
            .unwrap_or(false);
        if is_new {
            events.push(event(
                "ap.new",
                ts_ms,
                json!({
                    "bssid": format_mac(access_point.bssid),
                    "ssid": access_point
                        .ssid
                        .as_ref()
                        .map(|ssid| String::from_utf8_lossy(ssid).into_owned()),
                    "channel": access_point.channel,
                    "freq_mhz": access_point.freq_mhz,
                    "security": access_point.security,
                    "wps": access_point.wps,
                    "rssi": observation.sighting.as_ref().and_then(|s| s.rssi),
                }),
            ));
        }
    }

    if let Some(client) = &observation.client {
        events.push(event(
            "client.assoc",
            ts_ms,
            json!({
                "client": format_mac(client.mac),
                "bssid": format_mac(client.bssid),
                "rssi": client.rssi,
            }),
        ));
    }

    if let Some(probe) = &observation.probe {
        events.push(event(
            "probe.seen",
            ts_ms,
            json!({
                "client": format_mac(probe.mac),
                "ssid": String::from_utf8_lossy(&probe.ssid),
                "rssi": probe.rssi,
            }),
        ));
    }

    for alert in alerts {
        events.push(event(
            "alert.raised",
            ts_ms,
            json!({
                "id": serde_json::Value::Null,
                "rule": alert.rule,
                "severity": alert.severity.as_str(),
                "mac": alert.mac.map(format_mac),
                "summary": alert.summary,
            }),
        ));
    }

    events
}

/// One event.
fn event(topic: &str, ts_ms: i64, data: serde_json::Value) -> Event {
    Event {
        version: API_VERSION,
        topic: topic.to_string(),
        ts_ms,
        seq: 0,
        data,
    }
}

/// A MAC address, as the schema and the query API write it.
fn format_mac(mac: [u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

/// The first three bytes of a MAC address.
fn format_oui(oui: [u8; 3]) -> String {
    format!("{:02x}:{:02x}:{:02x}", oui[0], oui[1], oui[2])
}
