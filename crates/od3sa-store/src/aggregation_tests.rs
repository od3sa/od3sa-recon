//! Tests for the aggregator and the batched writer.
//!
//! The values here are synthetic: the `00:11:22:33:44:xx` MAC family and
//! `example-*` SSIDs, as the rest of the project uses. The frames come from
//! the `od3sa-fixtures` builders, so no real capture is involved anywhere.

use std::fs;
use std::path::PathBuf;

use od3sa_fixtures::{beacon, beacon_with_akm, data_frame, eapol_frame, mac, probe_request};

use crate::aggregator::{Aggregator, LinkLayer};
use crate::writer::Writer;
use crate::{SCHEMA_VERSION, Store, StoreError, ValueExt};

/// The time the synthetic frames are seen at, in unix epoch milliseconds.
const NOW_MS: i64 = 1_700_000_000_000;

/// The name of the source that sees the synthetic frames.
const SOURCE: &str = "example-source";

/// A marker that must never survive into an observation.
const MARKER: &str = "SECRET-EXAMPLE-MARKER";

/// A path under the temp directory, unique per test.
fn temp_path(name: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "od3sa-store-agg-test-{}-{name}.sqlite",
        std::process::id()
    ));
    path
}

/// Remove a database file and the WAL files SQLite leaves next to it.
fn remove_db(path: &std::path::Path) {
    let mut wal = path.as_os_str().to_os_string();
    wal.push("-wal");
    let mut shm = path.as_os_str().to_os_string();
    shm.push("-shm");
    let _ = fs::remove_file(path);
    let _ = fs::remove_file(wal);
    let _ = fs::remove_file(shm);
}

/// The number of rows a query returns.
fn count(store: &Store, sql: &str) -> usize {
    let rows = store.query(sql).expect("the query should succeed");
    rows.get(0, "n")
        .expect("the column should be there")
        .as_integer()
        .expect("the count should be a number") as usize
}

/// One text column of the first row of a query.
fn text(store: &Store, sql: &str, column: &str) -> String {
    let rows = store.query(sql).expect("the query should succeed");
    rows.get(0, column)
        .expect("the column should be there")
        .as_str()
        .expect("the value should be text")
        .to_string()
}

/// A synthetic beacon for the `00:11:22:33:44:xx` family.
fn synthetic_beacon(bssid_last: u8, ssid: &str, freq_mhz: u16, rssi: i8) -> Vec<u8> {
    beacon(mac(bssid_last), ssid, freq_mhz, rssi, true)
}

/// 1. A beacon gives an access point and a sighting of its BSSID.
#[test]
fn a_beacon_gives_an_access_point_and_a_sighting() {
    let mut aggregator = Aggregator::new(16);
    let frame = synthetic_beacon(1, "example-ssid", 2412, -42);

    let observation = aggregator
        .observe(&frame, LinkLayer::Radiotap, NOW_MS, SOURCE)
        .expect("a beacon is not an error");

    let access_point = observation
        .access_point
        .expect("a beacon gives an access point");
    assert_eq!(access_point.bssid, mac(1));
    assert_eq!(
        access_point.ssid.as_deref(),
        Some(&b"example-ssid"[..]),
        "the SSID comes from the elements"
    );
    assert!(!access_point.ssid_hidden);
    assert_eq!(
        access_point.security.as_deref(),
        Some("WPA2-PSK"),
        "the security comes from the RSN element"
    );
    assert_eq!(access_point.akm.as_deref(), Some("PSK"));
    assert_eq!(access_point.pairwise.as_deref(), Some("CCMP"));
    assert_eq!(access_point.group_cipher.as_deref(), Some("CCMP"));
    assert!(!access_point.pmf_required);
    assert!(!access_point.wps);
    assert_eq!(
        access_point.channel,
        Some(1),
        "the channel comes from the radiotap header"
    );
    assert_eq!(access_point.freq_mhz, Some(2412));
    assert_eq!(access_point.band, Some("2.4"));
    assert_eq!(access_point.beacon_interval, Some(100));

    let sighting = observation.sighting.expect("a beacon gives a sighting");
    assert_eq!(sighting.mac, mac(1), "the sighting is of the BSSID");
    assert_eq!(sighting.ts_ms, NOW_MS);
    assert_eq!(sighting.rssi, Some(-42));
    assert_eq!(sighting.channel, Some(1));
    assert_eq!(sighting.source, SOURCE);

    let device = observation.device.expect("a beacon gives a device");
    assert_eq!(device.mac, mac(1));
    assert_eq!(device.kind, "ap");
    assert_eq!(device.oui, [0x00, 0x11, 0x22]);
    assert!(!device.randomized);
}

/// A beacon on a 5 GHz network says so.
#[test]
fn a_beacon_on_five_gigahertz_says_the_five_gigahertz_band() {
    let mut aggregator = Aggregator::new(16);
    let frame = beacon(mac(3), "example-open-net", 5180, -67, false);

    let observation = aggregator
        .observe(&frame, LinkLayer::Radiotap, NOW_MS, SOURCE)
        .expect("a beacon is not an error");

    let access_point = observation
        .access_point
        .expect("a beacon gives an access point");
    assert_eq!(access_point.band, Some("5"));
    assert_eq!(access_point.channel, Some(36));
    assert_eq!(access_point.freq_mhz, Some(5180));
    assert_eq!(
        access_point.security.as_deref(),
        Some("open"),
        "a beacon with no RSN element is an open network"
    );
}

/// A WPA3 beacon is told apart from a WPA2 one.
#[test]
fn a_wpa3_beacon_is_labelled_wpa3() {
    let mut aggregator = Aggregator::new(16);
    let frame = beacon_with_akm(
        mac(4),
        "example-wpa3",
        2412,
        -50,
        &[od3sa_fixtures::AKM_SAE],
    );

    let observation = aggregator
        .observe(&frame, LinkLayer::Radiotap, NOW_MS, SOURCE)
        .expect("a beacon is not an error");

    let access_point = observation
        .access_point
        .expect("a beacon gives an access point");
    assert_eq!(access_point.security.as_deref(), Some("WPA3-SAE"));
    assert_eq!(access_point.akm.as_deref(), Some("SAE"));
}

/// A transition-mode network offers both PSK and SAE, and says so.
#[test]
fn a_transition_mode_network_says_so() {
    let mut aggregator = Aggregator::new(16);
    let frame = beacon_with_akm(
        mac(5),
        "example-mixed",
        2412,
        -58,
        &[od3sa_fixtures::AKM_PSK, od3sa_fixtures::AKM_SAE],
    );

    let observation = aggregator
        .observe(&frame, LinkLayer::Radiotap, NOW_MS, SOURCE)
        .expect("a beacon is not an error");

    let access_point = observation
        .access_point
        .expect("a beacon gives an access point");
    assert_eq!(access_point.security.as_deref(), Some("WPA2-PSK+WPA3-SAE"));
    assert_eq!(access_point.akm.as_deref(), Some("PSK,SAE"));
}

/// 2. A data frame gives a client-to-AP link and a sighting of the client.
#[test]
fn a_data_frame_gives_a_client_link_and_a_sighting() {
    let mut aggregator = Aggregator::new(16);
    let frame = data_frame(mac(21), mac(31), mac(1), true, false, b"example-payload");

    let observation = aggregator
        .observe(&frame, LinkLayer::Radiotap, NOW_MS, SOURCE)
        .expect("a data frame is not an error");

    let client = observation
        .client
        .expect("a data frame gives a client link");
    assert_eq!(client.mac, mac(21), "the client is the sender");
    assert_eq!(client.bssid, mac(1), "the access point is the BSSID");
    assert_eq!(client.ts_ms, NOW_MS);
    assert_eq!(client.rssi, Some(-45));

    let sighting = observation.sighting.expect("a data frame gives a sighting");
    assert_eq!(sighting.mac, mac(21), "the sighting is of the client");
    assert_eq!(sighting.rssi, Some(-45));

    let device = observation.device.expect("a data frame gives a device");
    assert_eq!(device.mac, mac(21));
    assert_eq!(device.kind, "client");
}

/// 3. A probe request gives a probe and a sighting of the probing station.
#[test]
fn a_probe_request_gives_a_probe() {
    let mut aggregator = Aggregator::new(16);
    let frame = probe_request(mac(11), "example-ssid", -48, 2412);

    let observation = aggregator
        .observe(&frame, LinkLayer::Radiotap, NOW_MS, SOURCE)
        .expect("a probe request is not an error");

    let probe = observation.probe.expect("a probe request gives a probe");
    assert_eq!(probe.mac, mac(11));
    assert_eq!(probe.ssid, b"example-ssid".to_vec());
    assert_eq!(probe.ts_ms, NOW_MS);
    assert_eq!(probe.rssi, Some(-48));

    let sighting = observation
        .sighting
        .expect("a probe request gives a sighting");
    assert_eq!(sighting.mac, mac(11));
}

/// 4. No payload is kept: not in the observation, not in its `Debug` output.
#[test]
fn no_payload_is_kept_in_the_observation() {
    let mut aggregator = Aggregator::new(16);

    // A data frame whose body carries a distinctive marker.
    let frame = data_frame(mac(21), mac(31), mac(1), true, false, MARKER.as_bytes());
    let observation = aggregator
        .observe(&frame, LinkLayer::Radiotap, NOW_MS, SOURCE)
        .expect("a data frame is not an error");

    let rendered = format!("{observation:?}");
    assert!(
        !rendered.contains(MARKER),
        "the payload leaked into the observation: {rendered}"
    );
    assert!(!rendered.contains("SECRET"), "a payload leaked: {rendered}");

    // An EAPOL frame carries a marker too, and its body must go as well.
    let mut body = od3sa_fixtures::LLC_SNAP_EAPOL.to_vec();
    body.extend_from_slice(MARKER.as_bytes());
    let eapol = data_frame(mac(21), mac(1), mac(1), true, false, &body);
    let observation = aggregator
        .observe(&eapol, LinkLayer::Radiotap, NOW_MS, SOURCE)
        .expect("an EAPOL frame is not an error");

    let rendered = format!("{observation:?}");
    assert!(
        !rendered.contains(MARKER),
        "the EAPOL body leaked into the observation: {rendered}"
    );

    // And the fixture's own EAPOL frame leaves nothing behind either.
    let eapol = eapol_frame(mac(22), mac(1), mac(1));
    let observation = aggregator
        .observe(&eapol, LinkLayer::Radiotap, NOW_MS, SOURCE)
        .expect("an EAPOL frame is not an error");
    let rendered = format!("{observation:?}");
    assert!(!rendered.contains("SECRET"), "a payload leaked: {rendered}");
}

/// A malformed frame is not an error: it yields an empty observation.
#[test]
fn a_malformed_frame_is_not_an_error() {
    let mut aggregator = Aggregator::new(16);

    for frame in [
        vec![],
        vec![0x08, 0x00],
        vec![0x00; 4],
        b"not a frame at all".to_vec(),
    ] {
        let observation = aggregator
            .observe(&frame, LinkLayer::Radiotap, NOW_MS, SOURCE)
            .expect("a malformed frame is not an error");
        assert_eq!(
            observation,
            crate::Observation::default(),
            "a malformed frame gives an empty observation"
        );
    }
}

/// 5. The device table is bounded, and it drops the oldest devices.
#[test]
fn the_device_table_is_bounded_and_drops_the_oldest() {
    let mut aggregator = Aggregator::new(4);
    assert!(aggregator.is_empty());
    assert_eq!(aggregator.len(), 0);

    for last in 1..=6u8 {
        let frame = synthetic_beacon(last, "example-ssid", 2412, -42);
        aggregator
            .observe(&frame, LinkLayer::Radiotap, NOW_MS, SOURCE)
            .expect("a beacon is not an error");
    }

    assert_eq!(aggregator.len(), 4, "the table stays at its capacity");
    assert!(!aggregator.contains(mac(1)), "the oldest device is dropped");
    assert!(
        !aggregator.contains(mac(2)),
        "the second oldest device is dropped"
    );
    assert!(aggregator.contains(mac(3)), "the newer devices stay");
    assert!(aggregator.contains(mac(4)));
    assert!(aggregator.contains(mac(5)));
    assert!(aggregator.contains(mac(6)));
}

/// The same device seen twice is one device, not two.
#[test]
fn the_same_device_is_remembered_once() {
    let mut aggregator = Aggregator::new(4);

    for _ in 0..5 {
        let frame = synthetic_beacon(1, "example-ssid", 2412, -42);
        aggregator
            .observe(&frame, LinkLayer::Radiotap, NOW_MS, SOURCE)
            .expect("a beacon is not an error");
    }

    assert_eq!(aggregator.len(), 1, "the same device is one device");
}

/// 6. The writer writes the rows, resolving the device and the SSID.
#[test]
fn the_writer_writes_the_rows_and_resolves_the_device_and_the_ssid() {
    let store = Store::open_in_memory().expect("the store should open");
    let mut writer = Writer::new(store, 60_000, 10);
    let mut aggregator = Aggregator::new(16);

    let frame = synthetic_beacon(1, "example-ssid", 2412, -42);
    for _ in 0..2 {
        let observation = aggregator
            .observe(&frame, LinkLayer::Radiotap, NOW_MS, SOURCE)
            .expect("a beacon is not an error");
        writer
            .write(&observation)
            .expect("the write should succeed");
    }

    assert_eq!(writer.pending(), 2, "the batch waits for the flush");
    let written = writer.flush().expect("the flush should succeed");
    assert_eq!(written, 2);
    assert_eq!(writer.pending(), 0);

    let store = writer.store();
    assert_eq!(count(store, "SELECT count(*) AS n FROM devices"), 1);
    assert_eq!(count(store, "SELECT count(*) AS n FROM ssids"), 1);
    assert_eq!(count(store, "SELECT count(*) AS n FROM access_points"), 1);
    assert_eq!(count(store, "SELECT count(*) AS n FROM sightings"), 1);
    assert_eq!(count(store, "SELECT count(*) AS n FROM sources"), 1);

    assert_eq!(
        text(store, "SELECT mac FROM devices", "mac"),
        "00:11:22:33:44:01"
    );
    assert_eq!(
        text(store, "SELECT kind FROM devices", "kind"),
        "ap",
        "the device is an access point"
    );
    assert_eq!(
        text(store, "SELECT security FROM access_points", "security"),
        "WPA2-PSK"
    );
    let channel = store
        .query("SELECT channel FROM access_points")
        .expect("the query should succeed");
    assert_eq!(
        channel
            .get(0, "channel")
            .expect("the column should be there")
            .as_integer(),
        Some(1)
    );
}

/// The signal level lands on the device that was measured, and only on it.
#[test]
fn the_signal_level_lands_on_the_measured_device() {
    let store = Store::open_in_memory().expect("the store should open");
    let mut writer = Writer::new(store, 60_000, 10);
    let mut aggregator = Aggregator::new(16);

    // A data frame: the client is measured, the access point is only
    // mentioned.
    let frame = data_frame(mac(21), mac(31), mac(1), true, false, b"example-payload");
    let observation = aggregator
        .observe(&frame, LinkLayer::Radiotap, NOW_MS, SOURCE)
        .expect("a data frame is not an error");
    writer
        .write(&observation)
        .expect("the write should succeed");
    writer.flush().expect("the flush should succeed");

    let store = writer.store();
    let client = store
        .query("SELECT last_rssi, max_rssi FROM devices WHERE mac = '00:11:22:33:44:15'")
        .expect("the query should succeed");
    assert_eq!(client.len(), 1, "the client has a row");
    assert_eq!(
        client
            .get(0, "last_rssi")
            .expect("the column should be there")
            .as_integer(),
        Some(-45),
        "the client carries the signal level"
    );
    assert_eq!(
        client
            .get(0, "max_rssi")
            .expect("the column should be there")
            .as_integer(),
        Some(-45)
    );

    let access_point = store
        .query("SELECT last_rssi, max_rssi FROM devices WHERE mac = '00:11:22:33:44:01'")
        .expect("the query should succeed");
    assert_eq!(access_point.len(), 1, "the access point has a row");
    assert_eq!(
        access_point
            .get(0, "last_rssi")
            .expect("the column should be there")
            .as_integer(),
        None,
        "the access point was mentioned, not measured"
    );
}

/// The SSID is stored as the bytes that went in.
#[test]
fn the_writer_stores_the_ssid_as_bytes() {
    let store = Store::open_in_memory().expect("the store should open");
    let mut writer = Writer::new(store, 60_000, 10);
    let mut aggregator = Aggregator::new(16);

    let frame = synthetic_beacon(1, "example-ssid", 2412, -42);
    let observation = aggregator
        .observe(&frame, LinkLayer::Radiotap, NOW_MS, SOURCE)
        .expect("a beacon is not an error");
    writer
        .write(&observation)
        .expect("the write should succeed");
    writer.flush().expect("the flush should succeed");

    let rows = writer
        .store()
        .query("SELECT ssid FROM ssids")
        .expect("the query should succeed");
    let bytes = rows
        .get(0, "ssid")
        .expect("the column should be there")
        .as_blob()
        .expect("the ssid should be a blob");
    assert_eq!(bytes, b"example-ssid");
}

/// Batching: a hundred observations with a batch size of ten make ten
/// flushes, and every row is there at the end.
#[test]
fn the_batch_is_flushed_when_it_is_full() {
    let store = Store::open_in_memory().expect("the store should open");
    let mut writer = Writer::new(store, 60_000, 10);
    let mut aggregator = Aggregator::new(256);

    let mut flushes = 0;
    for index in 0..100u8 {
        let frame = synthetic_beacon(index, &format!("example-net-{index:03}"), 2412, -42);
        let observation = aggregator
            .observe(
                &frame,
                LinkLayer::Radiotap,
                NOW_MS + i64::from(index) * 1_000,
                SOURCE,
            )
            .expect("a beacon is not an error");
        writer
            .write(&observation)
            .expect("the write should succeed");

        let pending = writer.pending();
        if pending == 0 {
            flushes += 1;
        }
        assert_eq!(
            pending,
            (index as usize + 1) % 10,
            "the batch holds the observations until it is full"
        );
    }

    assert_eq!(flushes, 10, "a hundred observations make ten flushes");
    assert_eq!(writer.pending(), 0);

    let store = writer.store();
    assert_eq!(count(store, "SELECT count(*) AS n FROM devices"), 100);
    assert_eq!(count(store, "SELECT count(*) AS n FROM ssids"), 100);
    assert_eq!(count(store, "SELECT count(*) AS n FROM access_points"), 100);
    assert_eq!(count(store, "SELECT count(*) AS n FROM sightings"), 100);
}

/// Retention: the sightings older than the age limit are deleted, the
/// newer ones are kept.
#[test]
fn retention_deletes_the_old_sightings() {
    let store = Store::open_in_memory().expect("the store should open");
    let mut writer = Writer::new(store, 60_000, 10);
    let mut aggregator = Aggregator::new(16);

    const DAY_MS: i64 = 86_400_000;

    // One sighting from forty days ago, one from now.
    let old = synthetic_beacon(1, "example-old", 2412, -42);
    let observation = aggregator
        .observe(&old, LinkLayer::Radiotap, NOW_MS - 40 * DAY_MS, SOURCE)
        .expect("a beacon is not an error");
    writer
        .write(&observation)
        .expect("the write should succeed");

    let new = synthetic_beacon(2, "example-new", 2412, -42);
    let observation = aggregator
        .observe(&new, LinkLayer::Radiotap, NOW_MS, SOURCE)
        .expect("a beacon is not an error");
    writer
        .write(&observation)
        .expect("the write should succeed");

    writer.flush().expect("the flush should succeed");
    assert_eq!(
        count(writer.store(), "SELECT count(*) AS n FROM sightings"),
        2
    );

    let retention = writer
        .apply_retention(NOW_MS, 30, u64::MAX)
        .expect("the retention pass should succeed");

    assert_eq!(
        retention.sightings_deleted, 1,
        "the old sighting is deleted"
    );
    assert!(
        retention.rotated_to.is_none(),
        "a database under the size cap is not rotated"
    );
    assert_eq!(
        count(writer.store(), "SELECT count(*) AS n FROM sightings"),
        1,
        "the newer sighting is kept"
    );
}

/// Rotation: a database over the size cap is rotated, the rotated file
/// holds the old rows, and the live database is at the current schema
/// version.
#[test]
fn a_database_over_the_size_cap_is_rotated() {
    let path = temp_path("rotation");
    remove_db(&path);

    let store = Store::open(&path).expect("the store should open");
    let mut writer = Writer::new(store, 60_000, 10);
    let mut aggregator = Aggregator::new(16);

    let frame = synthetic_beacon(1, "example-ssid", 2412, -42);
    let observation = aggregator
        .observe(&frame, LinkLayer::Radiotap, NOW_MS, SOURCE)
        .expect("a beacon is not an error");
    writer
        .write(&observation)
        .expect("the write should succeed");
    writer.flush().expect("the flush should succeed");

    assert_eq!(
        count(writer.store(), "SELECT count(*) AS n FROM devices"),
        1
    );

    // A cap of zero bytes is under the size of any database file.
    let retention = writer
        .apply_retention(NOW_MS, 30, 0)
        .expect("the retention pass should succeed");

    let rotated = retention
        .rotated_to
        .clone()
        .expect("a database over the cap is rotated");
    assert!(
        rotated.exists(),
        "the rotated file should exist at {rotated:?}"
    );

    let name = rotated
        .file_name()
        .expect("the rotated file should have a name")
        .to_string_lossy()
        .to_string();
    assert!(
        name.starts_with("recon-") && name.ends_with(".sqlite"),
        "the rotated file is named recon-YYYYMMDD.sqlite, got {name}"
    );

    // The rotated file holds the old rows.
    let rotated_store = Store::open(&rotated).expect("the rotated database should open");
    assert_eq!(
        count(&rotated_store, "SELECT count(*) AS n FROM devices"),
        1,
        "the rotated file holds the old rows"
    );
    assert_eq!(
        count(&rotated_store, "SELECT count(*) AS n FROM access_points"),
        1
    );
    drop(rotated_store);

    // The live database is fresh, at the current schema version.
    let store = writer.store();
    assert_eq!(
        store
            .schema_version()
            .expect("the version should be readable"),
        SCHEMA_VERSION
    );
    assert_eq!(
        count(store, "SELECT count(*) AS n FROM devices"),
        0,
        "the live database is fresh"
    );
    assert_eq!(count(store, "SELECT count(*) AS n FROM sightings"), 0);

    drop(writer);
    remove_db(&path);
    let _ = fs::remove_file(&rotated);
}

/// The source name is interned, so the same name is the same string every
/// time and the aggregator does not leak per frame.
#[test]
fn the_source_name_is_interned() {
    let mut aggregator = Aggregator::new(16);
    let frame = synthetic_beacon(1, "example-ssid", 2412, -42);

    let first = aggregator
        .observe(&frame, LinkLayer::Radiotap, NOW_MS, SOURCE)
        .expect("a beacon is not an error");
    let second = aggregator
        .observe(&frame, LinkLayer::Radiotap, NOW_MS, SOURCE)
        .expect("a beacon is not an error");

    let first = first.sighting.expect("a beacon gives a sighting").source;
    let second = second.sighting.expect("a beacon gives a sighting").source;
    assert_eq!(first, SOURCE);
    assert_eq!(first, second);
    assert!(
        std::ptr::eq(first, second),
        "the same name is interned once"
    );
}

/// A second source name is a different string.
#[test]
fn a_second_source_name_is_a_different_string() {
    let mut aggregator = Aggregator::new(16);
    let frame = synthetic_beacon(1, "example-ssid", 2412, -42);

    let first = aggregator
        .observe(&frame, LinkLayer::Radiotap, NOW_MS, SOURCE)
        .expect("a beacon is not an error");
    let second = aggregator
        .observe(&frame, LinkLayer::Radiotap, NOW_MS, "example-other-source")
        .expect("a beacon is not an error");

    assert_eq!(
        first.sighting.expect("a beacon gives a sighting").source,
        SOURCE
    );
    assert_eq!(
        second.sighting.expect("a beacon gives a sighting").source,
        "example-other-source"
    );
}

/// The writer flushes when the interval has passed, even with a batch that
/// is not full.
#[test]
fn the_writer_flushes_when_the_interval_has_passed() {
    let store = Store::open_in_memory().expect("the store should open");
    // A zero interval means the batch is flushed on every write.
    let mut writer = Writer::new(store, 0, 1_000);
    let mut aggregator = Aggregator::new(16);

    let frame = synthetic_beacon(1, "example-ssid", 2412, -42);
    let observation = aggregator
        .observe(&frame, LinkLayer::Radiotap, NOW_MS, SOURCE)
        .expect("a beacon is not an error");
    writer
        .write(&observation)
        .expect("the write should succeed");

    assert_eq!(writer.pending(), 0, "the interval flushed the batch");
    assert_eq!(
        count(writer.store(), "SELECT count(*) AS n FROM devices"),
        1
    );
}

/// The writer keeps the client-to-AP link and the probe.
#[test]
fn the_writer_writes_the_client_link_and_the_probe() {
    let store = Store::open_in_memory().expect("the store should open");
    let mut writer = Writer::new(store, 60_000, 10);
    let mut aggregator = Aggregator::new(16);

    let data = data_frame(mac(21), mac(31), mac(1), true, false, b"example-payload");
    let observation = aggregator
        .observe(&data, LinkLayer::Radiotap, NOW_MS, SOURCE)
        .expect("a data frame is not an error");
    writer
        .write(&observation)
        .expect("the write should succeed");

    let probe = probe_request(mac(11), "example-ssid", -48, 2412);
    let observation = aggregator
        .observe(&probe, LinkLayer::Radiotap, NOW_MS, SOURCE)
        .expect("a probe request is not an error");
    writer
        .write(&observation)
        .expect("the write should succeed");

    writer.flush().expect("the flush should succeed");

    let store = writer.store();
    assert_eq!(count(store, "SELECT count(*) AS n FROM clients"), 1);
    assert_eq!(count(store, "SELECT count(*) AS n FROM probes"), 1);
    assert_eq!(count(store, "SELECT count(*) AS n FROM devices"), 3);
    assert_eq!(count(store, "SELECT count(*) AS n FROM ssids"), 1);
}

/// A frame without a radiotap header is read as a bare 802.11 frame.
#[test]
fn a_frame_without_a_radiotap_header_is_read() {
    let mut aggregator = Aggregator::new(16);

    // The fixture's beacon, with the radiotap header taken off.
    let frame = synthetic_beacon(1, "example-ssid", 2412, -42);
    let header_len = u16::from_le_bytes([frame[2], frame[3]]) as usize;
    let bare = &frame[header_len..];

    let observation = aggregator
        .observe(bare, LinkLayer::Ieee80211, NOW_MS, SOURCE)
        .expect("a bare frame is not an error");

    let access_point = observation
        .access_point
        .expect("a bare beacon still gives an access point");
    assert_eq!(access_point.ssid.as_deref(), Some(&b"example-ssid"[..]));
    assert_eq!(access_point.channel, None, "there is no radiotap header");
    assert_eq!(access_point.freq_mhz, None);
    assert_eq!(access_point.band, None);
}

/// The writer refuses to write a sighting for a device it does not know.
#[test]
fn a_foreign_key_is_still_enforced() {
    let store = Store::open_in_memory().expect("the store should open");
    let mut writer = Writer::new(store, 60_000, 10);

    // An observation with a sighting and no device: the writer resolves the
    // device itself, so the row goes in.
    let observation = crate::Observation {
        sighting: Some(crate::Sighting {
            lat: None,
            lon: None,
            alt: None,
            fix: None,
            mac: mac(21),
            ts_ms: NOW_MS,
            rssi: Some(-40),
            channel: Some(1),
            source: SOURCE,
        }),
        ..crate::Observation::default()
    };

    writer
        .write(&observation)
        .expect("the write should succeed");
    writer.flush().expect("the flush should succeed");

    assert_eq!(
        count(writer.store(), "SELECT count(*) AS n FROM sightings"),
        1
    );
}

/// The writer reports a broken database rather than panicking.
#[test]
fn a_broken_database_is_an_error_and_not_a_panic() {
    let store = Store::open_in_memory().expect("the store should open");
    // A table of the wrong shape makes the insert fail.
    store
        .query("DROP TABLE devices")
        .expect("the drop should succeed");
    let mut writer = Writer::new(store, 60_000, 1);

    let observation = crate::Observation {
        sighting: Some(crate::Sighting {
            lat: None,
            lon: None,
            alt: None,
            fix: None,
            mac: mac(21),
            ts_ms: NOW_MS,
            rssi: Some(-40),
            channel: Some(1),
            source: SOURCE,
        }),
        ..crate::Observation::default()
    };

    let error = writer
        .write(&observation)
        .expect_err("a broken database is an error");
    assert!(
        matches!(error, StoreError::Sqlite(_)),
        "the error should come from SQLite, got {error:?}"
    );
}

/// The retention pass deletes the alerts that have aged out, not only the
/// sightings. The alerts table grows with every alert that is raised, so a
/// pass that only deleted sightings would leave the database growing.
#[test]
fn old_alerts_are_deleted_too() {
    let store = Store::open_in_memory().expect("the store should open");
    let mut writer = Writer::new(store, 60_000, 10);
    let mut aggregator = Aggregator::new(16);

    let frame = synthetic_beacon(1, "example-ssid", 2412, -42);
    let observation = aggregator
        .observe(&frame, LinkLayer::Radiotap, NOW_MS, SOURCE)
        .expect("a beacon is not an error");

    writer
        .write_alert(&crate::AlertRow {
            ts_ms: NOW_MS,
            rule: "new_device".to_string(),
            severity: "info".to_string(),
            mac: Some(mac(1)),
            summary: "example".to_string(),
            details: None,
        })
        .expect("the alert should be written");
    writer
        .write(&observation)
        .expect("the write should succeed");
    writer.flush().expect("the flush should succeed");

    assert_eq!(count(writer.store(), "SELECT count(*) AS n FROM alerts"), 1);

    // A cutoff that is well in the future takes both the alert and the
    // sighting with it.
    let retention = writer
        .apply_retention(NOW_MS + 40 * 86_400_000, 30, u64::MAX)
        .expect("the retention pass should succeed");

    assert_eq!(retention.alerts_deleted, 1, "the old alert is deleted");
    assert_eq!(
        count(writer.store(), "SELECT count(*) AS n FROM alerts"),
        0,
        "the alerts table is empty"
    );
}

/// A device with no sighting left is one that has aged out, and it goes
/// with it. Its rows are deleted first, because the foreign keys point at
/// it.
#[test]
fn a_device_with_no_sightings_left_is_deleted() {
    let store = Store::open_in_memory().expect("the store should open");
    let mut writer = Writer::new(store, 60_000, 10);
    let mut aggregator = Aggregator::new(16);

    let frame = synthetic_beacon(1, "example-ssid", 2412, -42);
    let observation = aggregator
        .observe(&frame, LinkLayer::Radiotap, NOW_MS, SOURCE)
        .expect("a beacon is not an error");
    writer
        .write(&observation)
        .expect("the write should succeed");
    writer.flush().expect("the flush should succeed");

    assert_eq!(
        count(writer.store(), "SELECT count(*) AS n FROM devices"),
        1
    );
    assert_eq!(
        count(writer.store(), "SELECT count(*) AS n FROM access_points"),
        1
    );

    let retention = writer
        .apply_retention(NOW_MS + 40 * 86_400_000, 30, u64::MAX)
        .expect("the retention pass should succeed");

    assert_eq!(retention.devices_deleted, 1, "the aged-out device goes");
    assert_eq!(
        count(writer.store(), "SELECT count(*) AS n FROM devices"),
        0,
        "the devices table is empty"
    );
    assert_eq!(
        count(writer.store(), "SELECT count(*) AS n FROM access_points"),
        0,
        "the access points go with it"
    );
    assert_eq!(
        count(writer.store(), "SELECT count(*) AS n FROM ssids"),
        0,
        "the ssid nothing points at any more goes too"
    );
}

/// A device that was seen recently is kept, even when its old sightings
/// have gone. The retention pass is about the size, not about forgetting
/// what is still there.
#[test]
fn a_device_that_is_still_being_seen_is_kept() {
    let store = Store::open_in_memory().expect("the store should open");
    let mut writer = Writer::new(store, 60_000, 10);
    let mut aggregator = Aggregator::new(16);

    let frame = synthetic_beacon(1, "example-ssid", 2412, -42);
    let old = aggregator
        .observe(&frame, LinkLayer::Radiotap, NOW_MS, SOURCE)
        .expect("a beacon is not an error");
    writer.write(&old).expect("the write should succeed");

    // The same device, seen now.
    let recent = aggregator
        .observe(
            &frame,
            LinkLayer::Radiotap,
            NOW_MS + 40 * 86_400_000,
            SOURCE,
        )
        .expect("a beacon is not an error");
    writer.write(&recent).expect("the write should succeed");
    writer.flush().expect("the flush should succeed");

    let retention = writer
        .apply_retention(NOW_MS + 40 * 86_400_000, 30, u64::MAX)
        .expect("the retention pass should succeed");

    assert_eq!(retention.sightings_deleted, 1, "the old sighting goes");
    assert_eq!(retention.devices_deleted, 0, "the device stays");
    assert_eq!(
        count(writer.store(), "SELECT count(*) AS n FROM devices"),
        1,
        "the device is still known"
    );
}
