//! Tests for the schema and the migrator.
//!
//! The values here are synthetic: the `00:11:22:33:44:xx` MAC family and
//! `example-ssid`, as the rest of the project uses. No real capture, no real
//! device, no real network.

use std::fs;
use std::path::PathBuf;

use rusqlite::Connection;

use crate::migrator::{self, MIGRATIONS, Migration};
use crate::{SCHEMA_VERSION, Store, StoreError, Value, ValueExt};

/// The tables `docs/SCHEMA.md` lists, in the order the doc lists them.
const EXPECTED_TABLES: &[&str] = &[
    "meta",
    "sessions",
    "sources",
    "devices",
    "ssids",
    "access_points",
    "clients",
    "probes",
    "ble_devices",
    "sightings",
    "alerts",
];

/// The indexes `docs/SCHEMA.md` lists.
const EXPECTED_INDEXES: &[&str] = &["sightings_bucket", "devices_last_seen"];

/// A path under the temp directory, unique per test.
fn temp_path(name: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "od3sa-store-test-{}-{name}.sqlite",
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

/// One value of the `meta` table, by key.
fn meta_value(store: &Store, key: &str) -> String {
    let rows = store
        .query(&format!("SELECT value FROM meta WHERE key = '{key}'"))
        .expect("the query should succeed");
    rows.get(0, "value")
        .expect("the column should be there")
        .as_str()
        .expect("the value should be text")
        .to_string()
}

/// The names of the tables in a database, ignoring SQLite's own.
fn table_names(store: &Store) -> Vec<String> {
    let rows = store
        .query(
            "SELECT name FROM sqlite_master WHERE type = 'table' \
             AND name NOT LIKE 'sqlite_%' ORDER BY name",
        )
        .expect("the query should succeed");
    let mut names = Vec::with_capacity(rows.len());
    for index in 0..rows.len() {
        names.push(
            rows.get(index, "name")
                .expect("the column should be there")
                .as_str()
                .expect("the name should be text")
                .to_string(),
        );
    }
    names
}

/// The names of the indexes in a database, ignoring SQLite's own.
///
/// SQLite creates an automatic index for every `UNIQUE` constraint. Those are
/// named `sqlite_autoindex_*` and are not part of the schema this crate
/// promises, so they are left out.
fn index_names(store: &Store) -> Vec<String> {
    let rows = store
        .query(
            "SELECT name FROM sqlite_master WHERE type = 'index' \
             AND name NOT LIKE 'sqlite_%' ORDER BY name",
        )
        .expect("the query should succeed");
    let mut names = Vec::with_capacity(rows.len());
    for index in 0..rows.len() {
        names.push(
            rows.get(index, "name")
                .expect("the column should be there")
                .as_str()
                .expect("the name should be text")
                .to_string(),
        );
    }
    names
}

/// A fresh database is at schema version 1.
#[test]
fn fresh_database_is_at_schema_version_one() {
    let store = Store::open_in_memory().expect("the store should open");
    assert_eq!(
        store
            .schema_version()
            .expect("the version should be readable"),
        1
    );
    assert_eq!(SCHEMA_VERSION, 1);
}

/// Every table and index of `docs/SCHEMA.md` is there.
#[test]
fn fresh_database_has_every_table_and_index_of_the_schema() {
    let store = Store::open_in_memory().expect("the store should open");

    let tables = table_names(&store);
    let mut expected: Vec<String> = EXPECTED_TABLES
        .iter()
        .map(|name| name.to_string())
        .collect();
    expected.sort();
    assert_eq!(tables, expected, "the tables should match the schema");

    let indexes = index_names(&store);
    let mut expected: Vec<String> = EXPECTED_INDEXES
        .iter()
        .map(|name| name.to_string())
        .collect();
    expected.sort();
    assert_eq!(indexes, expected, "the indexes should match the schema");
}

/// The `meta` table holds the version and the creation time.
#[test]
fn meta_table_holds_the_version_and_the_creation_time() {
    let store = Store::open_in_memory().expect("the store should open");

    let rows = store
        .query("SELECT key, value FROM meta ORDER BY key")
        .expect("the query should succeed");
    let keys: Vec<String> = (0..rows.len())
        .map(|index| {
            rows.get(index, "key")
                .expect("the column should be there")
                .as_str()
                .expect("the key should be text")
                .to_string()
        })
        .collect();
    assert_eq!(keys, vec!["created_at", "schema_version"]);

    let version = store
        .query("SELECT value FROM meta WHERE key = 'schema_version'")
        .expect("the query should succeed");
    assert_eq!(
        version
            .get(0, "value")
            .expect("the column should be there")
            .as_str(),
        Some("1")
    );

    let created_at = store
        .query("SELECT value FROM meta WHERE key = 'created_at'")
        .expect("the query should succeed");
    let stamp = created_at
        .get(0, "value")
        .expect("the column should be there")
        .as_str()
        .expect("the stamp should be text")
        .parse::<u128>()
        .expect("the stamp should be a number of milliseconds");
    assert!(stamp > 0, "the creation time should be set");
}

/// Foreign keys are enforced.
#[test]
fn foreign_keys_are_on() {
    let store = Store::open_in_memory().expect("the store should open");
    let rows = store
        .query("PRAGMA foreign_keys")
        .expect("the pragma should be readable");
    assert_eq!(
        rows.get(0, "foreign_keys")
            .expect("the column should be there")
            .as_integer(),
        Some(1),
        "PRAGMA foreign_keys should be on"
    );
}

/// Foreign keys are enforced on a file database too.
#[test]
fn foreign_keys_are_on_for_a_file_database() {
    let path = temp_path("foreign-keys");
    remove_db(&path);

    let store = Store::open(&path).expect("the store should open");
    let rows = store
        .query("PRAGMA foreign_keys")
        .expect("the pragma should be readable");
    assert_eq!(
        rows.get(0, "foreign_keys")
            .expect("the column should be there")
            .as_integer(),
        Some(1),
        "PRAGMA foreign_keys should be on"
    );

    drop(store);
    remove_db(&path);
}

/// A file database is in WAL mode, as `docs/SCHEMA.md` asks.
#[test]
fn a_file_database_is_in_wal_mode() {
    let path = temp_path("wal");
    remove_db(&path);

    let store = Store::open(&path).expect("the store should open");
    let rows = store
        .query("PRAGMA journal_mode")
        .expect("the pragma should be readable");
    assert_eq!(
        rows.get(0, "journal_mode")
            .expect("the column should be there")
            .as_str(),
        Some("wal")
    );

    drop(store);
    remove_db(&path);
}

/// Opening an already migrated database applies nothing.
#[test]
fn reopening_a_migrated_database_applies_nothing() {
    let path = temp_path("reopen");
    remove_db(&path);

    let first = Store::open(&path).expect("the store should open");
    assert_eq!(
        first
            .schema_version()
            .expect("the version should be readable"),
        1
    );
    let created_at = meta_value(&first, "created_at");
    // A row that only survives if the schema was left alone.
    first
        .query("INSERT INTO devices (id, mac, kind) VALUES (1, '00:11:22:33:44:07', 'ap')")
        .expect("the marker should go in");
    drop(first);

    let second = Store::open(&path).expect("the store should open again");
    assert_eq!(
        second
            .schema_version()
            .expect("the version should be readable"),
        1
    );
    let after = meta_value(&second, "created_at");
    assert_eq!(
        after, created_at,
        "the migration should not have run a second time"
    );
    assert_eq!(table_names(&second).len(), EXPECTED_TABLES.len());

    let marker = second
        .query("SELECT mac FROM devices WHERE id = 1")
        .expect("the query should succeed");
    assert_eq!(marker.len(), 1, "the row should still be there");
    assert_eq!(
        marker
            .get(0, "mac")
            .expect("the column should be there")
            .as_str(),
        Some("00:11:22:33:44:07")
    );

    drop(second);
    remove_db(&path);
}

/// A migration that fails leaves the database at the previous version.
///
/// The broken migration creates a table and then fails, so the table must not
/// survive either: the migration ran in a transaction that was rolled back.
#[test]
fn a_failing_migration_leaves_the_previous_version() {
    let broken = Migration {
        version: 2,
        name: "002_broken",
        sql: "CREATE TABLE broken_table (id INTEGER);\nTHIS IS NOT SQL;",
    };
    let mut with_broken = MIGRATIONS.to_vec();
    with_broken.push(broken);

    let conn = Connection::open_in_memory().expect("the connection should open");
    migrator::apply(&conn, MIGRATIONS).expect("the first migration should succeed");
    assert_eq!(
        migrator::current_version(&conn).expect("the version should be readable"),
        1
    );

    let error = migrator::apply(&conn, &with_broken).expect_err("the broken migration should fail");
    assert!(
        matches!(error, StoreError::Migration { version: 2, .. }),
        "the error should name the broken migration, got {error:?}"
    );

    assert_eq!(
        migrator::current_version(&conn).expect("the version should be readable"),
        1,
        "the database should still be at version 1"
    );

    let broken_table: i64 = conn
        .query_row(
            "SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = 'broken_table'",
            [],
            |row| row.get(0),
        )
        .expect("the query should succeed");
    assert_eq!(broken_table, 0, "the broken table should be rolled back");
}

/// The foreign keys hold: a sighting must point at a device that exists.
#[test]
fn a_sighting_for_an_unknown_device_is_refused() {
    let store = Store::open_in_memory().expect("the store should open");

    store
        .query("INSERT INTO sources (id, name, kind) VALUES (1, 'example-source', 'pcap')")
        .expect("the source should go in");

    let error = store
        .query(
            "INSERT INTO sightings (device_id, source_id, bucket_ms, n, rssi_min, rssi_max, rssi_avg, channel) \
             VALUES (999, 1, 1700000000000, 3, -80, -60, -70.0, 6)",
        )
        .expect_err("the sighting should be refused");
    assert!(
        matches!(error, StoreError::Sqlite(_)),
        "the error should come from SQLite, got {error:?}"
    );

    let count = store
        .query("SELECT count(*) AS n FROM sightings")
        .expect("the query should succeed");
    assert_eq!(
        count
            .get(0, "n")
            .expect("the column should be there")
            .as_integer(),
        Some(0)
    );
}

/// A device, an access point, a client and a sighting go in and come back.
#[test]
fn a_device_an_access_point_a_client_and_a_sighting_round_trip() {
    let store = Store::open_in_memory().expect("the store should open");

    store
        .query(
            "INSERT INTO devices (id, mac, oui, kind, randomized, first_seen_ms, last_seen_ms, max_rssi, last_rssi, label) \
             VALUES (1, '00:11:22:33:44:01', '00:11:22', 'ap', 0, 1700000000000, 1700000060000, -40, -55, 'example-ap')",
        )
        .expect("the device should go in");
    store
        .query(
            "INSERT INTO devices (id, mac, oui, kind, randomized, first_seen_ms, last_seen_ms, max_rssi, last_rssi, label) \
             VALUES (2, '00:11:22:33:44:02', '00:11:22', 'client', 1, 1700000010000, 1700000060000, -70, -80, 'example-client')",
        )
        .expect("the client device should go in");
    store
        .query("INSERT INTO ssids (id, ssid, hidden) VALUES (1, X'6578616D706C652D73736964', 0)")
        .expect("the ssid should go in");
    store
        .query(
            "INSERT INTO access_points (device_id, ssid_id, channel, freq_mhz, band, security, akm, pairwise, group_cipher, pmf, wps, ht, vht, he, vendor_ies, beacon_int, last_beacon_ms) \
             VALUES (1, 1, 6, 2437, '2.4', 'WPA2-PSK', 'PSK', 'CCMP', 'CCMP', 'optional', 0, 1, 0, 0, NULL, 100, 1700000060000)",
        )
        .expect("the access point should go in");
    store
        .query(
            "INSERT INTO clients (device_id, bssid_device_id, first_seen_ms, last_seen_ms) \
             VALUES (2, 1, 1700000010000, 1700000060000)",
        )
        .expect("the client should go in");
    store
        .query(
            "INSERT INTO sources (id, name, kind, iface, status, frames, errors) \
             VALUES (1, 'example-source', 'pcap', 'wlan1mon', 'up', 42, 0)",
        )
        .expect("the source should go in");
    store
        .query(
            "INSERT INTO sightings (device_id, source_id, bucket_ms, n, rssi_min, rssi_max, rssi_avg, channel, lat, lon, alt, fix) \
             VALUES (1, 1, 1700000000000, 5, -80, -60, -70.0, 6, 31.780000, 35.210000, 700.0, 1)",
        )
        .expect("the sighting should go in");

    let device = store
        .query("SELECT mac, kind, max_rssi, last_rssi FROM devices WHERE id = 1")
        .expect("the query should succeed");
    assert_eq!(device.len(), 1);
    let columns: Vec<&str> = device.columns().iter().map(String::as_str).collect();
    assert_eq!(columns, ["mac", "kind", "max_rssi", "last_rssi"]);
    assert_eq!(
        device
            .get(0, "mac")
            .expect("the column should be there")
            .as_str(),
        Some("00:11:22:33:44:01")
    );
    assert_eq!(
        device
            .get(0, "kind")
            .expect("the column should be there")
            .as_str(),
        Some("ap")
    );
    assert_eq!(
        device
            .get(0, "max_rssi")
            .expect("the column should be there")
            .as_integer(),
        Some(-40)
    );

    let ap = store
        .query("SELECT channel, freq_mhz, band, security FROM access_points WHERE device_id = 1")
        .expect("the query should succeed");
    assert_eq!(ap.len(), 1);
    assert_eq!(
        ap.get(0, "channel")
            .expect("the column should be there")
            .as_integer(),
        Some(6)
    );
    assert_eq!(
        ap.get(0, "freq_mhz")
            .expect("the column should be there")
            .as_integer(),
        Some(2437)
    );
    assert_eq!(
        ap.get(0, "band")
            .expect("the column should be there")
            .as_str(),
        Some("2.4")
    );
    assert_eq!(
        ap.get(0, "security")
            .expect("the column should be there")
            .as_str(),
        Some("WPA2-PSK")
    );

    let client = store
        .query("SELECT device_id, bssid_device_id FROM clients")
        .expect("the query should succeed");
    assert_eq!(client.len(), 1);
    assert_eq!(
        client
            .get(0, "device_id")
            .expect("the column should be there")
            .as_integer(),
        Some(2)
    );
    assert_eq!(
        client
            .get(0, "bssid_device_id")
            .expect("the column should be there")
            .as_integer(),
        Some(1)
    );

    let sighting = store
        .query(
            "SELECT device_id, source_id, bucket_ms, n, rssi_min, rssi_max, rssi_avg, channel, lat, lon, alt, fix \
             FROM sightings",
        )
        .expect("the query should succeed");
    assert_eq!(sighting.len(), 1);
    assert_eq!(
        sighting
            .get(0, "bucket_ms")
            .expect("the column should be there")
            .as_integer(),
        Some(1_700_000_000_000)
    );
    assert_eq!(
        sighting
            .get(0, "n")
            .expect("the column should be there")
            .as_integer(),
        Some(5)
    );
    assert_eq!(
        sighting
            .get(0, "rssi_avg")
            .expect("the column should be there")
            .as_real(),
        Some(-70.0)
    );
    assert_eq!(
        sighting
            .get(0, "lat")
            .expect("the column should be there")
            .as_real(),
        Some(31.78)
    );
    assert_eq!(
        sighting
            .get(0, "fix")
            .expect("the column should be there")
            .as_integer(),
        Some(1)
    );
}

/// The `ssids` table keeps the SSID bytes as a blob.
#[test]
fn an_ssid_comes_back_as_the_bytes_that_went_in() {
    let store = Store::open_in_memory().expect("the store should open");
    store
        .query("INSERT INTO ssids (id, ssid, hidden) VALUES (1, X'6578616D706C652D73736964', 0)")
        .expect("the ssid should go in");

    let rows = store
        .query("SELECT ssid, hidden FROM ssids WHERE id = 1")
        .expect("the query should succeed");
    assert_eq!(rows.len(), 1);
    let bytes = rows
        .get(0, "ssid")
        .expect("the column should be there")
        .as_blob()
        .expect("the ssid should be a blob");
    assert_eq!(bytes, b"example-ssid");
    assert_eq!(
        rows.get(0, "hidden")
            .expect("the column should be there")
            .as_integer(),
        Some(0)
    );
}

/// A bound parameter is data: a quote in it does not change the statement.
#[test]
fn a_bound_parameter_is_data_and_not_sql() {
    let store = Store::open_in_memory().expect("the store should open");
    store
        .query("INSERT INTO devices (id, mac, kind) VALUES (1, '00:11:22:33:44:01', 'ap')")
        .expect("the device should go in");

    // A value that would match every row if it were written into the
    // statement matches nothing.
    let rows = store
        .query_with(
            "SELECT id FROM devices WHERE mac = ?",
            &[Value::Text("00:11:22:33:44:01' OR '1'='1".to_string())],
        )
        .expect("the query should succeed");
    assert_eq!(rows.len(), 0, "the value should match no row");

    // The value that is really there is still found.
    let rows = store
        .query_with(
            "SELECT id FROM devices WHERE mac = ?",
            &[Value::Text("00:11:22:33:44:01".to_string())],
        )
        .expect("the query should succeed");
    assert_eq!(rows.len(), 1, "the value should match one row");

    // The table is still there, with its row in it.
    let rows = store
        .query("SELECT count(*) AS n FROM devices")
        .expect("the query should succeed");
    assert_eq!(
        rows.get(0, "n")
            .expect("the column should be there")
            .as_integer(),
        Some(1)
    );
}

/// A bound parameter of every kind reaches the statement.
#[test]
fn the_page_cache_is_bounded() {
    // The daemon's RSS budget is 15 MB and it holds at least two
    // connections, so the page cache is not left at SQLite's default.
    let store = Store::open_in_memory().expect("the database should open");
    let cache = store
        .query("PRAGMA cache_size")
        .expect("the query should succeed");
    assert_eq!(
        cache.get(0, "cache_size").and_then(Value::as_integer),
        Some(-1000),
        "the page cache should be bounded to a megabyte"
    );
}

#[test]
fn the_kinds_of_parameter_reach_the_statement() {
    let store = Store::open_in_memory().expect("the store should open");
    store
        .query("INSERT INTO ssids (id, ssid, hidden) VALUES (1, X'6578616D706C652D73736964', 0)")
        .expect("the ssid should go in");

    // A blob parameter matches the blob in the column.
    let rows = store
        .query_with(
            "SELECT id FROM ssids WHERE ssid = ?",
            &[Value::Blob(b"example-ssid".to_vec())],
        )
        .expect("the query should succeed");
    assert_eq!(rows.len(), 1, "the blob should match");

    // An integer parameter reaches the statement too.
    let rows = store
        .query_with("SELECT id FROM ssids WHERE id = ?", &[Value::Integer(1)])
        .expect("the query should succeed");
    assert_eq!(rows.len(), 1, "the number should match");

    let rows = store
        .query_with("SELECT id FROM ssids WHERE id = ?", &[Value::Integer(2)])
        .expect("the query should succeed");
    assert_eq!(rows.len(), 0, "the number should not match");
}

/// A statement with the wrong number of parameters is an error.
#[test]
fn a_statement_with_the_wrong_number_of_parameters_is_an_error() {
    let store = Store::open_in_memory().expect("the store should open");

    let error = store
        .query_with(
            "SELECT id FROM devices WHERE mac = ?",
            &[
                Value::Text("00:11:22:33:44:01".to_string()),
                Value::Integer(1),
            ],
        )
        .expect_err("the statement should be refused");
    assert!(
        matches!(error, StoreError::Sqlite(_)),
        "the error should come from SQLite, got {error:?}"
    );

    let error = store
        .query_with("SELECT id FROM devices WHERE mac = ?", &[])
        .expect_err("the statement should be refused");
    assert!(
        matches!(error, StoreError::Sqlite(_)),
        "the error should come from SQLite, got {error:?}"
    );
}
