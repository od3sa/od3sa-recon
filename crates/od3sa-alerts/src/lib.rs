//! The awareness alert rules for `od3sa-recon`.
//!
//! This crate turns what the aggregator saw into **alerts**: a device that
//! was not seen before, a device that is on the watchlist, an access point
//! that is claiming a name it does not own, a burst of frames about one
//! device, and so on.
//!
//! # These rules are awareness rules
//!
//! An alert here describes **what was seen**. Nothing in this crate acts on
//! an alert: there is no code path that deauthenticates a client, that
//! changes an access point's configuration, that sends a probe or that
//! transmits anything of any kind. There is no radio handle, no pcap handle
//! and no socket in this crate. The alerts are text, and the caller decides
//! what to do with them — which, in this project, is to write them to the
//! `alerts` table and publish them as `alert.raised` events.
//!
//! # The engine does not write to the database
//!
//! [`AlertEngine::observe`] returns the alerts it raised. It never touches
//! SQLite. The caller writes them to the `alerts` table and publishes them
//! as `alert.raised` events.
//!
//! # An alert is raised once, not on every frame
//!
//! The engine keeps the state it needs to know whether it has already said
//! it: the devices it has seen, the access points it has seen and their
//! SSID, BSSID and security, and the recent event counts per device. A
//! device that is seen ten times a second raises its `new_device` alert
//! once, not ten times a second.
//!
//! # The state is bounded
//!
//! The device table and the access point table are both capped, so a long
//! run on a busy channel cannot grow without limit. The oldest entries are
//! dropped.
//!
//! # What it reads
//!
//! The engine reads the [`od3sa_store::Observation`] the aggregator
//! produces, so it depends on that crate for the types, on `toml` for the
//! configuration and on `serde_json` for the details of an alert.
//!
//! # Example
//!
//! ```
//! use od3sa_alerts::{AlertEngine, Rules};
//!
//! let rules = Rules::parse("new_device = { enabled = true, severity = \"info\" }")
//!     .expect("the configuration parses");
//! let mut engine = AlertEngine::new(rules);
//!
//! let observation = od3sa_store::Observation::default();
//! let alerts = engine.observe(&observation, 1_700_000_000_000);
//! assert!(alerts.is_empty());
//! ```

#![forbid(unsafe_code)]

mod engine;
mod rules;

#[cfg(test)]
mod tests;

pub use engine::{Alert, AlertEngine, MAX_ACCESS_POINTS, MAX_DEVICES, MAX_PAIRS_PER_SSID};
pub use rules::{
    AlertError, DeauthBurst, Rule, Rules, SeenAgain, Severity, StrongSignal, Watchlist, format_mac,
    format_oui,
};
