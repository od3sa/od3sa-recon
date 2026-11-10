//! The collector's tests.
//!
//! The frames come from `od3sa-fixtures`, so every address is out of the
//! synthetic family and every SSID is `example-*`.

use std::path::PathBuf;

use crate::{Collector, CollectorConfig};
use od3sa_alerts::Rules;
use od3sa_events::EventBus;
use od3sa_store::{LinkLayer, Store, Value, ValueExt};

/// A temporary directory for a database or a socket.
fn temp_path(name: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "od3sa-collector-test-{}-{name}",
        std::process::id()
    ));
    path
}

/// A collector over a fresh database, with the given rules.
fn collector_with(rules: &str, database: PathBuf) -> Collector {
    let config = CollectorConfig {
        database,
        alerts: Some(rules.to_string()),
        events_socket: None,
        gpsd_address: None,
        ..CollectorConfig::default()
    };
    Collector::new(config)
}

/// Open a database the test can look into.
fn open_database(path: &std::path::Path) -> Store {
    Store::open(path).expect("the database should open")
}

/// A beacon frame with a radiotap header in front of it.
fn beacon() -> Vec<u8> {
    od3sa_fixtures::beacon(od3sa_fixtures::mac(1), "example-ssid", 5180, -42, true)
}

/// A probe request frame.
fn probe() -> Vec<u8> {
    od3sa_fixtures::probe_request(od3sa_fixtures::mac(2), "example-probe", -55, 5180)
}

/// A frame that cannot be parsed at all.
fn broken() -> Vec<u8> {
    vec![0xff; 12]
}

#[test]
fn a_frame_becomes_rows() {
    let path = temp_path("rows.sqlite");
    let mut collector = collector_with("", path.clone());
    collector.open_database().expect("the database should open");

    let frame = beacon();
    collector
        .process(&frame, LinkLayer::Radiotap, 1_762_300_000_000, None)
        .expect("the frame should be processed");
    collector.flush_for_test();

    let store = open_database(&path);
    let devices = store
        .query("SELECT mac, kind FROM devices")
        .expect("the query should work");
    assert_eq!(devices.len(), 1, "the device should be in the database");
    assert_eq!(
        devices.get(0, "mac").and_then(|value| value.as_str()),
        Some("00:11:22:33:44:01")
    );

    let access_points = store
        .query("SELECT device_id, channel FROM access_points")
        .expect("the query should work");
    assert_eq!(access_points.len(), 1, "the access point should be there");
    assert_eq!(
        access_points
            .get(0, "channel")
            .and_then(|value| value.as_integer()),
        Some(36)
    );

    let sightings = store
        .query("SELECT device_id, source_id, n FROM sightings")
        .expect("the query should work");
    assert_eq!(sightings.len(), 1, "the sighting should be there");
    assert_eq!(
        sightings.get(0, "n").and_then(|value| value.as_integer()),
        Some(1)
    );

    let _ = std::fs::remove_file(&path);
}

#[test]
fn a_frame_becomes_an_event() {
    let path = temp_path("event.sqlite");
    let socket = temp_path("events.sock");
    let _ = std::fs::remove_file(&socket);

    let bus = EventBus::bind(&socket).expect("the bus should bind");
    let config = CollectorConfig {
        database: path.clone(),
        events_socket: None,
        gpsd_address: None,
        ..CollectorConfig::default()
    };
    let mut collector = Collector::new(config).with_bus(bus.clone());
    collector.open_database().expect("the database should open");

    let frame = beacon();
    collector
        .process(&frame, LinkLayer::Radiotap, 1_762_300_000_000, None)
        .expect("the frame should be processed");

    let stats = collector.stats();
    assert!(
        stats.events >= 2,
        "a new device and a new access point should be published: {stats:?}"
    );

    bus.stop();
    let _ = std::fs::remove_file(&socket);
    let _ = std::fs::remove_file(&path);
}

#[test]
fn an_alert_becomes_a_row_and_an_event() {
    let path = temp_path("alert.sqlite");
    let rules =
        "watchlist = { enabled = true, severity = \"warning\", ssids = [\"example-ssid\"] }";
    let mut collector = collector_with(rules, path.clone());
    collector.open_database().expect("the database should open");

    let frame = beacon();
    collector
        .process(&frame, LinkLayer::Radiotap, 1_762_300_000_000, None)
        .expect("the frame should be processed");
    collector.flush_for_test();

    let store = open_database(&path);
    let alerts = store
        .query("SELECT rule, severity, summary FROM alerts")
        .expect("the query should work");
    assert_eq!(alerts.len(), 1, "the alert should be in the database");
    assert_eq!(
        alerts.get(0, "rule").and_then(|value| value.as_str()),
        Some("watchlist")
    );
    assert_eq!(
        alerts.get(0, "severity").and_then(|value| value.as_str()),
        Some("warning")
    );

    let stats = collector.stats();
    assert_eq!(stats.alerts, 1, "the alert should be counted");

    let _ = std::fs::remove_file(&path);
}

#[test]
fn the_batch_is_flushed_at_the_end() {
    let path = temp_path("flush.sqlite");
    let mut collector = collector_with("", path.clone());
    collector.open_database().expect("the database should open");

    let frame = beacon();
    collector
        .process(&frame, LinkLayer::Radiotap, 1_762_300_000_000, None)
        .expect("the frame should be processed");
    collector.flush_for_test();

    let store = open_database(&path);
    let sightings = store
        .query("SELECT n FROM sightings")
        .expect("the query should work");
    assert_eq!(sightings.len(), 1, "the sighting should be there");

    let _ = std::fs::remove_file(&path);
}

#[test]
fn a_frame_that_cannot_be_parsed_is_counted_and_does_not_stop_the_collector() {
    let path = temp_path("broken.sqlite");
    let mut collector = collector_with("", path.clone());
    collector.open_database().expect("the database should open");

    collector
        .process(&broken(), LinkLayer::Radiotap, 1_762_300_000_000, None)
        .expect("a broken frame must not be an error");
    collector
        .process(&broken(), LinkLayer::Radiotap, 1_762_300_001_000, None)
        .expect("a broken frame must not be an error");

    let stats = collector.stats();
    assert_eq!(stats.unparsed, 2, "both broken frames should be counted");
    assert_eq!(stats.observations, 0, "nothing should have been written");

    // The collector carries on: a good frame after the broken ones is still
    // processed.
    let frame = beacon();
    collector
        .process(&frame, LinkLayer::Radiotap, 1_762_300_002_000, None)
        .expect("the frame should be processed");
    assert_eq!(collector.stats().observations, 1);

    let _ = std::fs::remove_file(&path);
}

#[test]
fn nothing_stores_a_payload() {
    let path = temp_path("payload.sqlite");
    let mut collector = collector_with("", path.clone());
    collector.open_database().expect("the database should open");

    // A data frame whose payload carries a marker.
    let mut frame = od3sa_fixtures::data_frame(
        od3sa_fixtures::mac(2),
        od3sa_fixtures::mac(3),
        od3sa_fixtures::mac(1),
        true,
        false,
        b"SECRETPORTPAYLOAD",
    );
    frame.extend_from_slice(b"SECRETPORTPAYLOAD");
    collector
        .process(&frame, LinkLayer::Radiotap, 1_762_300_000_000, None)
        .expect("the frame should be processed");
    collector.flush_for_test();

    let store = open_database(&path);
    for table in [
        "devices",
        "ssids",
        "access_points",
        "clients",
        "probes",
        "sightings",
        "ble_devices",
        "alerts",
    ] {
        let rows = store
            .query(&format!("SELECT * FROM {table}"))
            .expect("the query should work");
        let rendered = format!("{rows:?}");
        assert!(
            !rendered.contains("SECRETPORTPAYLOAD"),
            "the payload leaked into {table}"
        );
    }

    let _ = std::fs::remove_file(&path);
}

#[test]
fn the_collector_works_without_gpsd_and_without_the_bus() {
    let path = temp_path("bare.sqlite");
    let mut collector = collector_with("", path.clone());
    collector.open_database().expect("the database should open");

    // No bus, no gpsd: the rows are still there.
    let frame = beacon();
    collector
        .process(&frame, LinkLayer::Radiotap, 1_762_300_000_000, None)
        .expect("the frame should be processed");
    collector.flush_for_test();

    let store = open_database(&path);
    let sightings = store
        .query("SELECT lat, lon, alt, fix FROM sightings")
        .expect("the query should work");
    assert_eq!(sightings.len(), 1);
    for column in ["lat", "lon", "alt", "fix"] {
        assert!(
            matches!(sightings.get(0, column), Some(Value::Null)),
            "the {column} should be null without a position"
        );
    }

    let _ = std::fs::remove_file(&path);
}

#[test]
fn a_probe_becomes_a_probe() {
    let path = temp_path("probe.sqlite");
    let mut collector = collector_with("", path.clone());
    collector.open_database().expect("the database should open");

    let frame = probe();
    collector
        .process(&frame, LinkLayer::Radiotap, 1_762_300_000_000, None)
        .expect("the frame should be processed");
    collector.flush_for_test();

    let store = open_database(&path);
    let probes = store
        .query("SELECT count FROM probes")
        .expect("the query should work");
    assert_eq!(probes.len(), 1, "the probe should be in the database");
    assert_eq!(
        probes.get(0, "count").and_then(|value| value.as_integer()),
        Some(1)
    );

    let _ = std::fs::remove_file(&path);
}

#[test]
fn the_rules_come_from_the_configuration() {
    let rules = "new_device = { enabled = true, severity = \"info\" }";
    let config = CollectorConfig {
        alerts: Some(rules.to_string()),
        ..CollectorConfig::default()
    };
    assert_eq!(
        config.alerts_rules(),
        Rules::parse(rules).expect("the rules parse")
    );

    // A configuration with no rules means every rule is off.
    let config = CollectorConfig::default();
    assert_eq!(config.alerts_rules(), Rules::default());
}
