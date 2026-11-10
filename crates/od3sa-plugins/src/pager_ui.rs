//! The `pager-ui` payload: what the daemon has seen, in a form the Pager's
//! screen can show.
//!
//! The payload is a **binary**, not a shell script, and that is not a
//! preference. The daemon's query socket is a Unix socket, and the Pager's
//! busybox has no `nc -U` and no way to speak JSON-RPC: a shell script on
//! the device simply cannot reach the socket. So the plugin is a Rust
//! binary, and the shell script in the plugin's directory is the thin
//! wrapper the Pager's payload menu runs — it calls the binary and hands
//! its output to `logger`, which is how the Pager shows a line on its
//! screen.
//!
//! What it prints is a summary, not a dump: a device owner wants to know
//! how many devices and access points are about, how strong the signal
//! is, and whether anything was flagged.

use crate::client::{PluginError, QueryClient};
use serde_json::{Value, json};

/// The lines the payload shows.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Summary {
    /// The daemon's version.
    pub version: String,
    /// How long the daemon has been running, in seconds.
    pub uptime_s: u64,
    /// How many devices are known.
    pub devices: u64,
    /// How many access points are known.
    pub aps: u64,
    /// How many client links are known.
    pub clients: u64,
    /// How many Bluetooth devices are known.
    pub ble: u64,
    /// The size of the database, in bytes.
    pub db_bytes: u64,
    /// The daemon's resident set, in kilobytes.
    pub rss_kb: u64,
    /// The frames the capture has seen.
    pub frames: u64,
    /// The busiest channels, with their frame counts.
    pub channels: Vec<(u16, u64)>,
    /// How many alerts there are, and the rule of the most recent one.
    pub alerts: u64,
    /// The rule of the most recent alert, if there was one.
    pub last_alert: Option<String>,
}

impl Summary {
    /// The summary, as the lines the payload shows.
    pub fn lines(&self) -> Vec<String> {
        let mut lines = Vec::new();

        lines.push(format!(
            "od3sa-recon {} - up {}s",
            self.version, self.uptime_s
        ));
        lines.push(format!(
            "devices {}  aps {}  clients {}  ble {}",
            self.devices, self.aps, self.clients, self.ble
        ));
        lines.push(format!(
            "frames {}  db {}  rss {}k",
            self.frames, self.db_bytes, self.rss_kb
        ));

        if !self.channels.is_empty() {
            let channels: Vec<String> = self
                .channels
                .iter()
                .take(5)
                .map(|(number, frames)| format!("{number}={frames}"))
                .collect();
            lines.push(format!("channels: {}", channels.join(" ")));
        }

        if self.alerts > 0 {
            let last = self
                .last_alert
                .as_deref()
                .map(|alert| format!(" ({alert})"))
                .unwrap_or_default();
            lines.push(format!("alerts: {}{last}", self.alerts));
        }

        lines
    }

    /// The summary, as one block of text.
    pub fn text(&self) -> String {
        self.lines().join("\n")
    }
}

/// Ask the daemon for the summary.
pub fn summarise(client: &QueryClient) -> Result<Summary, PluginError> {
    let status = client.call("status", json!({}))?;

    let mut summary = Summary {
        version: status
            .get("version")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
            .to_string(),
        uptime_s: status.get("uptime_s").and_then(Value::as_u64).unwrap_or(0),
        db_bytes: status.get("db_bytes").and_then(Value::as_u64).unwrap_or(0),
        rss_kb: status.get("rss_kb").and_then(Value::as_u64).unwrap_or(0),
        ..Summary::default()
    };

    if let Some(counts) = status.get("counts") {
        summary.devices = counts.get("devices").and_then(Value::as_u64).unwrap_or(0);
        summary.aps = counts.get("aps").and_then(Value::as_u64).unwrap_or(0);
        summary.clients = counts.get("clients").and_then(Value::as_u64).unwrap_or(0);
        summary.ble = counts.get("ble").and_then(Value::as_u64).unwrap_or(0);
    }

    // The frames the capture has seen come from the sources.
    if let Some(sources) = status.get("sources").and_then(Value::as_array) {
        summary.frames = sources
            .iter()
            .filter_map(|source| source.get("frames").and_then(Value::as_u64))
            .sum();
    }

    // The busiest channels, from the access points and their sightings.
    let mut channels: Vec<(u16, u64)> = Vec::new();
    for access_point in client.call_all("aps.list", json!({}))? {
        let Some(channel) = access_point.get("channel").and_then(Value::as_u64) else {
            continue;
        };
        let channel = channel as u16;
        match channels.iter_mut().find(|(number, _)| *number == channel) {
            Some((_, frames)) => *frames += 1,
            None => channels.push((channel, 1)),
        }
    }
    channels.sort_by(|left, right| right.1.cmp(&left.1).then(left.0.cmp(&right.0)));
    summary.channels = channels;

    // The alerts, and the rule of the most recent one.
    let alerts = client.call_all("alerts.list", json!({}))?;
    summary.alerts = alerts.len() as u64;
    if let Some(latest) = alerts
        .iter()
        .filter_map(|alert| alert.get("ts_ms").and_then(Value::as_u64))
        .max()
    {
        summary.last_alert = alerts
            .iter()
            .find(|alert| alert.get("ts_ms").and_then(Value::as_u64) == Some(latest))
            .and_then(|alert| alert.get("rule").and_then(Value::as_str))
            .map(str::to_string);
    }

    Ok(summary)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// A summary with some numbers in it.
    fn summary() -> Summary {
        Summary {
            version: "0.1.0".to_string(),
            uptime_s: 3600,
            devices: 42,
            aps: 7,
            clients: 30,
            ble: 0,
            db_bytes: 1_048_576,
            rss_kb: 4096,
            frames: 123_456,
            channels: vec![(36, 30), (1, 12)],
            alerts: 2,
            last_alert: Some("new_device".to_string()),
        }
    }

    #[test]
    fn the_lines_hold_the_numbers() {
        let lines = summary().lines();
        assert_eq!(lines.len(), 5);
        assert!(lines[0].contains("0.1.0"));
        assert!(lines[0].contains("3600"));
        assert!(lines[1].contains("42"));
        assert!(lines[1].contains("7"));
        assert!(lines[2].contains("123456"));
        assert!(lines[3].contains("36=30"));
        assert!(lines[4].contains("2"));
        assert!(lines[4].contains("new_device"));
    }

    #[test]
    fn a_summary_with_nothing_in_it_still_makes_lines() {
        let lines = Summary::default().lines();
        assert!(!lines.is_empty());
        // No channels and no alerts: those lines are left out rather than
        // printed empty.
        assert!(!lines.iter().any(|line| line.starts_with("channels:")));
        assert!(!lines.iter().any(|line| line.starts_with("alerts:")));
    }

    #[test]
    fn the_text_is_the_lines_joined() {
        let summary = summary();
        assert_eq!(summary.text(), summary.lines().join("\n"));
    }

    #[test]
    fn the_summary_comes_from_the_daemon() {
        let status = json!({
            "version": "0.1.0",
            "uptime_s": 60,
            "counts": {"devices": 2, "aps": 1, "clients": 3, "ble": 0},
            "db_bytes": 100,
            "rss_kb": 200,
            "sources": [{"frames": 10}, {"frames": 5}],
        });
        let aps = json!({"items": [{"channel": 36}, {"channel": 1}, {"channel": 36}]});
        let alerts = json!({"items": [{"ts_ms": 5, "rule": "new_device"}]});

        let client = crate::client::QueryClient::scripted(vec![
            ("status", status),
            ("aps.list", aps),
            ("alerts.list", alerts),
        ]);
        let summary = summarise(&client).expect("the summary should come");

        assert_eq!(summary.devices, 2);
        assert_eq!(summary.aps, 1);
        assert_eq!(summary.frames, 15);
        // The channels are counted, busiest first.
        assert_eq!(summary.channels, vec![(36, 2), (1, 1)]);
        assert_eq!(summary.alerts, 1);
        assert_eq!(summary.last_alert.as_deref(), Some("new_device"));
    }
}
