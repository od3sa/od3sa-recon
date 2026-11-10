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

/// The retention settings come from the configuration file.
#[test]
fn the_retention_settings_come_from_the_configuration() {
    let config = CollectorConfig::from_toml("retention_days = 7\nmax_db_mb = 64\n")
        .expect("the configuration should parse");

    assert_eq!(config.retention_days, 7);
    assert_eq!(config.max_db_mb, 64);
}

/// A configuration that says nothing about retention keeps the defaults.
#[test]
fn the_retention_settings_have_defaults() {
    let config = CollectorConfig::default();

    assert_eq!(config.retention_days, 30);
    assert_eq!(config.max_db_mb, 512);

    // And a file that does not mention them keeps them too.
    let config = CollectorConfig::from_toml("interface = \"wlan1mon\"\n")
        .expect("the configuration should parse");
    assert_eq!(config.retention_days, 30);
    assert_eq!(config.max_db_mb, 512);
}

/// A retention setting that is not a number is an error, not a default.
#[test]
fn a_retention_setting_that_is_not_a_number_is_an_error() {
    let error = CollectorConfig::from_toml("retention_days = \"a week\"\n")
        .expect_err("a string is not a number");
    assert!(
        error.to_string().contains("retention_days"),
        "unexpected message: {error}"
    );

    let error =
        CollectorConfig::from_toml("max_db_mb = \"lots\"\n").expect_err("a string is not a number");
    assert!(
        error.to_string().contains("max_db_mb"),
        "unexpected message: {error}"
    );
}

/// The retention pass keeps the database from growing for ever.
///
/// The pass is what stops the SD card from filling up, so it has to delete
/// the data that has aged out. This checks the whole path: the collector
/// runs the pass, and the rows that are too old are gone afterwards.
#[test]
fn the_retention_pass_deletes_the_data_that_has_aged_out() {
    let path = temp_path("retention.sqlite");
    let mut collector = collector_with("", path.clone());
    collector.open_database().expect("the database should open");

    // A sighting from before the retention window, and one from now.
    // The times are the real ones, because the retention pass compares
    // them against the wall clock.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis() as i64)
        .expect("the clock should be after the epoch");
    let old = now - 40 * 86_400_000;

    collector
        .process(&beacon(), LinkLayer::Radiotap, old, None)
        .expect("the frame should be processed");
    collector
        .process(&probe(), LinkLayer::Radiotap, now, None)
        .expect("the frame should be processed");
    collector.flush_for_test();

    {
        let store = open_database(&path);
        assert_eq!(
            store
                .query("SELECT count(*) AS n FROM sightings")
                .expect("the query should work")
                .get(0, "n")
                .and_then(Value::as_integer),
            Some(2),
            "both sightings should be there"
        );
    }

    // The retention pass, with a cutoff that takes the old one and keeps
    // the new one.
    collector
        .retain()
        .expect("the retention pass should succeed");

    {
        let store = open_database(&path);
        assert_eq!(
            store
                .query("SELECT count(*) AS n FROM sightings")
                .expect("the query should work")
                .get(0, "n")
                .and_then(Value::as_integer),
            Some(1),
            "the old sighting is gone"
        );
    }

    let _ = std::fs::remove_file(&path);
}

/// The size cap is the backstop: whatever the age limit says, the
/// database does not stay over the cap.
///
/// A sighting from now is well inside the age limit, so the only thing
/// that can take it out of the live database is the cap.
#[test]
fn the_size_cap_rotates_the_database() {
    // The database goes in a directory of its own, because the rotation
    // writes the rotated file next to it, and the temp directory is
    // shared with every other test.
    let directory = temp_path("cap");
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).expect("the directory should be made");
    let path = directory.join("recon.sqlite");
    let mut collector = collector_with("", path.clone());
    collector.open_database().expect("the database should open");

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis() as i64)
        .expect("the clock should be after the epoch");
    collector
        .process(&beacon(), LinkLayer::Radiotap, now, None)
        .expect("the frame should be processed");
    collector.flush_for_test();

    {
        let store = open_database(&path);
        assert_eq!(
            store
                .query("SELECT count(*) AS n FROM sightings")
                .expect("the query should work")
                .get(0, "n")
                .and_then(Value::as_integer),
            Some(1),
            "the sighting is there to begin with"
        );
    }

    // A cap of zero megabytes is under the size of any database.
    collector.config.max_db_mb = 0;
    collector
        .retain()
        .expect("the retention pass should succeed");

    {
        let store = open_database(&path);
        assert_eq!(
            store
                .query("SELECT count(*) AS n FROM sightings")
                .expect("the query should work")
                .get(0, "n")
                .and_then(Value::as_integer),
            Some(0),
            "the live database was rotated"
        );
    }

    // And the rotated file is next to it, holding what was there.
    let rotated = rotated_file(&directory);
    assert!(
        rotated.exists(),
        "the rotated file should be at {rotated:?}"
    );
    let store = open_database(&rotated);
    assert_eq!(
        store
            .query("SELECT count(*) AS n FROM sightings")
            .expect("the query should work")
            .get(0, "n")
            .and_then(Value::as_integer),
        Some(1),
        "the rotated file holds what the live database had"
    );

    let _ = std::fs::remove_dir_all(&directory);
}

/// The file the database is rotated into.
///
/// The rotation names the file after the day, so the test looks for the
/// only file in the directory that is not the database itself.
fn rotated_file(directory: &std::path::Path) -> std::path::PathBuf {
    let mut found: Vec<std::path::PathBuf> = std::fs::read_dir(directory)
        .expect("the directory should be readable")
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .map(|name| name.starts_with("recon-") && name != "recon.sqlite")
                .unwrap_or(false)
        })
        .collect();
    found.sort();
    found.pop().expect("a rotated file should be there")
}

/// The database does not grow for ever.
///
/// This is the whole point of the retention pass: the SD card is 3.5 GB
/// with 2.3 GB free, and a collector that runs for a month must not fill
/// it. The test writes a hundred days of sightings and runs the pass every
/// hour, as the collector does.
///
/// The window is longer than the retention period on purpose: a test that
/// only spans the retention period cannot tell a pass that works from one
/// that does nothing, because nothing has aged out yet.
#[test]
fn the_database_does_not_grow_for_ever() {
    let directory = temp_path("bounds");
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).expect("the directory should be made");
    let path = directory.join("recon.sqlite");

    let mut collector = collector_with("", path.clone());
    collector.open_database().expect("the database should open");

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis() as i64)
        .expect("the clock should be after the epoch");

    // A hundred days of data, four an hour. The retention period is
    // thirty days, so seventy days of it has to go.
    const DAYS: i64 = 100;
    const PER_DAY: i64 = 4;
    let count = DAYS * PER_DAY;
    // The sightings are spread evenly over the hundred days, so each one
    // is six hours from the next.
    let step_ms = 24 * 3_600_000 / PER_DAY;

    for index in 0..count {
        let ts_ms = now - (count - index) * step_ms;
        // Four devices are seen throughout, so they are never forgotten.
        // Eight more are seen only in the first half, so they age out and
        // the pass has to take them and the rows that point at them.
        let device = if index < count / 2 {
            (index % 4) as u8
        } else if index < count / 2 + 8 {
            4 + (index % 8) as u8
        } else {
            (index % 4) as u8
        };
        let frame =
            od3sa_fixtures::beacon(od3sa_fixtures::mac(device), "example-ssid", 5180, -42, true);
        collector
            .process(&frame, LinkLayer::Radiotap, ts_ms, None)
            .expect("the frame should be processed");
        collector.flush_for_test();

        // The pass runs every hour, as the collector runs it.
        collector
            .retain()
            .expect("the retention pass should succeed");
    }

    let store = open_database(&path);

    // What the pass guarantees is that the *data* stops growing: the
    // rows that have aged out are gone, so a collector that has run for a
    // hundred days holds a month of data and not a hundred days of it.
    let rows = store
        .query("SELECT count(*) AS n FROM sightings")
        .expect("the query should work");
    let sightings = rows.get(0, "n").and_then(Value::as_integer).unwrap_or(0);

    // The retention period is thirty days, and there are four sightings a
    // day. Each one is in a minute of its own, so each is a row.
    let expected = 30 * PER_DAY;
    assert!(
        sightings <= expected,
        "the database should hold about a month of sightings ({expected}), not a hundred days of them: {sightings}"
    );

    // And the devices that have aged out went with them, so the tables
    // that grow with every device seen do not grow for ever either.
    let rows = store
        .query("SELECT count(*) AS n FROM devices")
        .expect("the query should work");
    let devices = rows.get(0, "n").and_then(Value::as_integer).unwrap_or(0);
    // The devices that stopped being seen in the first half have aged
    // out, and the pass has taken them. The store's own tests cover the
    // deletion of a device and of the rows that point at it; what matters
    // here is that the collector runs the pass at all.
    assert!(
        devices <= 4,
        "the devices that have aged out should be gone: {devices}"
    );

    let _ = std::fs::remove_dir_all(&directory);
}
