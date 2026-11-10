//! Tests for the read-only JSON-RPC query socket.
//!
//! The rows here are synthetic: the `00:11:22:33:44:xx` MAC family and
//! `example-ssid`, as the rest of the project uses. No real capture, no
//! real device, no real network.

use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;

use od3sa_store::{Store, Value};
use serde_json::{Map, Value as Json, json};

use super::*;

/// The token the tests use.
const TOKEN: &str = "test-token-0123456789";

/// A counter that keeps the socket paths of parallel tests apart.
static COUNTER: AtomicUsize = AtomicUsize::new(0);

/// A socket path that no other test uses.
fn temp_socket_path() -> PathBuf {
    let number = COUNTER.fetch_add(1, Ordering::SeqCst);
    let mut path = std::env::temp_dir();
    path.push(format!(
        "od3sa-recond-query-test-{}-{number}.sock",
        std::process::id()
    ));
    path
}

/// A database path that no other test uses.
fn temp_database_path() -> PathBuf {
    let number = COUNTER.fetch_add(1, Ordering::SeqCst);
    let mut path = std::env::temp_dir();
    path.push(format!(
        "od3sa-recond-query-test-{}-{number}.sqlite",
        std::process::id()
    ));
    path
}

/// Remove a database file and the files SQLite leaves next to it.
fn remove_database(path: &std::path::Path) {
    for suffix in ["", "-wal", "-shm"] {
        let mut name = path.as_os_str().to_os_string();
        name.push(suffix);
        let _ = fs::remove_file(name);
    }
}

/// A query server with a database in it.
///
/// The socket file is removed when the server is dropped.
struct TestServer {
    server: QueryServer,
    path: PathBuf,
}

impl TestServer {
    /// A server with the given database behind it.
    fn with_store(store: Store) -> TestServer {
        let path = temp_socket_path();
        let _ = fs::remove_file(&path);
        let server = QueryServer::bind(&path, store, TOKEN).expect("the socket should bind");
        TestServer { server, path }
    }

    /// A server with a populated database behind it.
    fn populated() -> TestServer {
        let store = Store::open_in_memory().expect("the store should open");
        populate(&store);
        TestServer::with_store(store)
    }

    /// Send a request with the token, and return the whole response.
    fn response(&self, method: &str, params: Json) -> Json {
        let mut params = params.as_object().cloned().unwrap_or_default();
        params.insert("token".to_string(), json!(TOKEN));
        self.raw(method, Json::Object(params))
    }

    /// Send a request as it is, and return the whole response.
    fn raw(&self, method: &str, params: Json) -> Json {
        let request = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params,
        });
        let line = serde_json::to_string(&request).expect("the request should serialize");
        self.server
            .handle_line(&line)
            .expect("there should be a response")
    }

    /// Send a request with the token, and return the result.
    fn result(&self, method: &str, params: Json) -> Json {
        let response = self.response(method, params);
        assert!(
            response.get("result").is_some(),
            "the method should have answered: {response}"
        );
        response["result"].clone()
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.server.stop();
        let _ = fs::remove_file(&self.path);
    }
}

/// Fill a database with synthetic rows.
fn populate(store: &Store) {
    store
        .query(
            "INSERT INTO sources (id, name, kind, iface, status, last_seen_ms, frames, errors) \
             VALUES (1, 'pcap:wlan1mon', 'pcap', 'wlan1mon', 'running', 1762300060000, 12345, 0)",
        )
        .expect("the source should go in");

    // 'example-ssid', 'example-ssid-2', and one that is not valid UTF-8.
    store
        .query("INSERT INTO ssids (id, ssid, hidden) VALUES (1, X'6578616D706C652D73736964', 0)")
        .expect("the ssid should go in");
    store
        .query(
            "INSERT INTO ssids (id, ssid, hidden) VALUES (2, X'6578616D706C652D737369642D32', 0)",
        )
        .expect("the ssid should go in");
    store
        .query("INSERT INTO ssids (id, ssid, hidden) VALUES (3, X'FFFE', 1)")
        .expect("the ssid should go in");

    let devices = [
        (1, 1_762_300_060_000i64, -42, -55, "ap"),
        (2, 1_762_300_050_000i64, -60, -70, "client"),
        (3, 1_762_300_040_000i64, -61, -71, "client"),
        (4, 1_762_300_030_000i64, -62, -72, "client"),
        (5, 1_762_300_020_000i64, -63, -73, "client"),
    ];
    for (id, last_seen, max_rssi, last_rssi, kind) in devices {
        let randomized = if kind == "ap" { 0 } else { 1 };
        store
            .query(&format!(
                "INSERT INTO devices (id, mac, oui, kind, randomized, first_seen_ms, last_seen_ms, \
                 max_rssi, last_rssi, label) VALUES ({id}, '00:11:22:33:44:0{id}', '00:11:22', \
                 '{kind}', {randomized}, 1762300000000, {last_seen}, {max_rssi}, {last_rssi}, \
                 'example-device')"
            ))
            .expect("the device should go in");
    }

    store
        .query(
            "INSERT INTO access_points (device_id, ssid_id, channel, freq_mhz, band, security, \
             akm, pairwise, group_cipher, pmf, wps, ht, vht, he, vendor_ies, beacon_int, \
             last_beacon_ms) VALUES (1, 1, 36, 5180, '5', 'WPA2-PSK', 'PSK', 'CCMP', 'CCMP', \
             'optional', 0, 1, 1, 0, NULL, 100, 1762300060000)",
        )
        .expect("the access point should go in");
    store
        .query(
            "INSERT INTO access_points (device_id, ssid_id, channel, freq_mhz, band, security, \
             akm, pairwise, group_cipher, pmf, wps, ht, vht, he, vendor_ies, beacon_int, \
             last_beacon_ms) VALUES (2, 3, 6, 2437, '2.4 GHz', 'WPA2', 'PSK', 'CCMP', 'CCMP', \
             'required', 1, 1, 0, 0, 'example-vendor', 100, 1762300040000)",
        )
        .expect("the access point should go in");

    for (device, last_seen) in [
        (2, 1_762_300_050_000i64),
        (3, 1_762_300_040_000i64),
        (4, 1_762_300_030_000i64),
    ] {
        store
            .query(&format!(
                "INSERT INTO clients (device_id, bssid_device_id, first_seen_ms, last_seen_ms) \
                 VALUES ({device}, 1, 1762300000000, {last_seen})"
            ))
            .expect("the client should go in");
    }

    store
        .query(
            "INSERT INTO probes (device_id, ssid_id, first_seen_ms, last_seen_ms, count) \
             VALUES (2, 1, 1762300000000, 1762300060000, 3)",
        )
        .expect("the probe should go in");
    store
        .query(
            "INSERT INTO probes (device_id, ssid_id, first_seen_ms, last_seen_ms, count) \
             VALUES (3, 2, 1762300000000, 1762300050000, 1)",
        )
        .expect("the probe should go in");

    store
        .query(
            "INSERT INTO sightings (device_id, source_id, bucket_ms, n, rssi_min, rssi_max, \
             rssi_avg, channel, lat, lon, alt, fix) VALUES (1, 1, 1762300060000, 3, -60, -42, \
             -51.0, 36, NULL, NULL, NULL, NULL)",
        )
        .expect("the sighting should go in");
    store
        .query(
            "INSERT INTO sightings (device_id, source_id, bucket_ms, n, rssi_min, rssi_max, \
             rssi_avg, channel) VALUES (2, 1, 1762300050000, 1, -70, -70, -70.0, 36)",
        )
        .expect("the sighting should go in");

    store
        .query(
            "INSERT INTO alerts (id, ts_ms, rule, severity, device_id, summary, details) \
             VALUES (1, 1762300060000, 'new_device', 'info', 1, 'example-ssid', NULL)",
        )
        .expect("the alert should go in");
}

/// A SQLite value as a JSON value.
fn value_to_json(value: &Value) -> Json {
    match value {
        Value::Null => Json::Null,
        Value::Integer(number) => json!(number),
        Value::Real(number) => json!(number),
        Value::Text(text) => json!(text),
        Value::Blob(bytes) => json!(String::from_utf8_lossy(bytes)),
    }
}

/// Every row of every table, as JSON.
fn snapshot(store: &Store) -> Json {
    let tables = [
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
    let mut out = Map::new();
    for table in tables {
        let rows = store
            .query(&format!("SELECT * FROM {table}"))
            .expect("the query should succeed");
        let items: Vec<Json> = (0..rows.len())
            .map(|index| {
                let mut row = Map::new();
                for (column, value) in rows.columns().iter().zip(rows.rows()[index].iter()) {
                    row.insert(column.clone(), value_to_json(value));
                }
                Json::Object(row)
            })
            .collect();
        out.insert(table.to_string(), Json::Array(items));
    }
    Json::Object(out)
}

/// The parameters each method needs.
fn params_for(method: &str) -> Json {
    match method {
        "devices.get" => json!({"mac": "00:11:22:33:44:01"}),
        _ => json!({}),
    }
}

/// Every method answers with the shape the contract gives.
#[test]
fn every_method_answers_with_the_documented_shape() {
    let server = TestServer::populated();

    for method in METHODS {
        let response = server.response(method, params_for(method));
        assert_eq!(response["jsonrpc"], json!("2.0"), "the method {method}");
        assert_eq!(response["id"], json!(1), "the method {method}");
        assert!(
            response.get("result").is_some(),
            "the method {method} should have answered: {response}"
        );
    }

    let result = server.result("status", json!({}));
    assert_eq!(result["version"], json!(VERSION));
    assert_eq!(result["api"], json!(API_VERSION));
    assert!(result["uptime_s"].is_number());
    assert_eq!(result["sources"][0]["name"], json!("pcap:wlan1mon"));
    assert_eq!(result["sources"][0]["kind"], json!("pcap"));
    assert_eq!(result["sources"][0]["status"], json!("running"));
    assert_eq!(result["sources"][0]["frames"], json!(12345));
    assert_eq!(result["sources"][0]["errors"], json!(0));
    assert_eq!(result["counts"]["devices"], json!(5));
    assert_eq!(result["counts"]["aps"], json!(2));
    assert_eq!(result["counts"]["clients"], json!(3));
    assert_eq!(result["counts"]["ble"], json!(0));
    assert!(result["db_bytes"].is_number());
    assert!(result["rss_kb"].is_number());

    let result = server.result("devices.list", json!({}));
    assert!(result["next_cursor"].is_null());
    let item = &result["items"][0];
    assert_eq!(item["mac"], json!("00:11:22:33:44:05"));
    assert_eq!(item["kind"], json!("client"));
    assert_eq!(item["oui"], json!("00:11:22"));
    assert_eq!(item["randomized"], json!(true));
    assert_eq!(item["first_seen_ms"], json!(1_762_300_000_000i64));
    assert_eq!(item["last_seen_ms"], json!(1_762_300_020_000i64));
    assert_eq!(item["max_rssi"], json!(-63));
    assert_eq!(item["last_rssi"], json!(-73));

    let result = server.result("devices.get", json!({"mac": "00:11:22:33:44:01"}));
    assert_eq!(result["device"]["mac"], json!("00:11:22:33:44:01"));
    assert_eq!(result["device"]["kind"], json!("ap"));
    assert_eq!(result["access_point"]["bssid"], json!("00:11:22:33:44:01"));
    assert_eq!(result["access_point"]["ssid"], json!("example-ssid"));
    assert_eq!(result["access_point"]["ssid_hidden"], json!(false));
    assert_eq!(result["access_point"]["channel"], json!(36));
    assert_eq!(result["access_point"]["freq_mhz"], json!(5180));
    assert_eq!(result["access_point"]["band"], json!("5"));
    assert_eq!(result["access_point"]["security"], json!("WPA2-PSK"));
    assert_eq!(result["access_point"]["akm"], json!("PSK"));
    assert_eq!(result["access_point"]["pairwise"], json!("CCMP"));
    assert_eq!(result["access_point"]["group_cipher"], json!("CCMP"));
    assert_eq!(result["access_point"]["pmf_required"], json!(false));
    assert_eq!(result["access_point"]["wps"], json!(false));
    assert_eq!(result["access_point"]["ht"], json!(true));
    assert_eq!(result["access_point"]["vht"], json!(true));
    assert_eq!(result["access_point"]["he"], json!(false));
    assert!(result["access_point"]["vendor_ies"].is_null());
    assert_eq!(result["access_point"]["beacon_int"], json!(100));
    assert_eq!(
        result["access_point"]["last_beacon_ms"],
        json!(1_762_300_060_000i64)
    );
    assert!(result["ble"].is_null());
    assert_eq!(result["sightings"][0]["ts_ms"], json!(1_762_300_060_000i64));
    assert_eq!(
        result["sightings"][0]["bucket_ms"],
        json!(1_762_300_060_000i64)
    );
    assert_eq!(result["sightings"][0]["n"], json!(3));
    assert_eq!(result["sightings"][0]["rssi_min"], json!(-60));
    assert_eq!(result["sightings"][0]["rssi_max"], json!(-42));
    assert_eq!(result["sightings"][0]["rssi_avg"], json!(-51.0));
    assert_eq!(result["sightings"][0]["channel"], json!(36));
    assert!(result["sightings"][0]["lat"].is_null());
    assert!(result["sightings"][0]["lon"].is_null());
    assert!(result["sightings"][0]["alt"].is_null());
    assert!(result["sightings"][0]["fix"].is_null());

    let result = server.result("aps.list", json!({}));
    assert!(result["next_cursor"].is_null());
    assert_eq!(result["items"].as_array().map(Vec::len), Some(2));
    assert_eq!(result["items"][1]["bssid"], json!("00:11:22:33:44:01"));
    assert_eq!(result["items"][1]["ssid"], json!("example-ssid"));

    let result = server.result("clients.list", json!({}));
    assert_eq!(result["items"].as_array().map(Vec::len), Some(3));
    assert_eq!(result["items"][0]["client"], json!("00:11:22:33:44:04"));
    assert_eq!(result["items"][0]["bssid"], json!("00:11:22:33:44:01"));
    assert_eq!(
        result["items"][0]["first_seen_ms"],
        json!(1_762_300_000_000i64)
    );
    assert_eq!(
        result["items"][0]["last_seen_ms"],
        json!(1_762_300_030_000i64)
    );

    let result = server.result("probes.list", json!({}));
    assert_eq!(result["items"].as_array().map(Vec::len), Some(2));
    assert_eq!(result["items"][0]["client"], json!("00:11:22:33:44:03"));
    assert_eq!(result["items"][0]["ssid"], json!("example-ssid-2"));
    assert_eq!(result["items"][0]["count"], json!(1));
    assert_eq!(result["items"][1]["client"], json!("00:11:22:33:44:02"));
    assert_eq!(result["items"][1]["count"], json!(3));

    // The Bluetooth list is empty until the blue5 ingest lands.
    let result = server.result("ble.list", json!({}));
    assert_eq!(result["items"].as_array().map(Vec::len), Some(0));
    assert!(result["next_cursor"].is_null());

    let result = server.result("sightings.list", json!({}));
    assert_eq!(result["items"].as_array().map(Vec::len), Some(2));
    assert_eq!(result["items"][0]["device_id"], json!(2));
    assert_eq!(result["items"][0]["source_id"], json!(1));
    assert_eq!(result["items"][0]["bucket_ms"], json!(1_762_300_050_000i64));
    assert_eq!(result["items"][0]["n"], json!(1));
    assert_eq!(result["items"][0]["rssi_avg"], json!(-70.0));
    assert!(result["items"][0]["lat"].is_null());
    assert!(result["items"][0]["fix"].is_null());

    let result = server.result("alerts.list", json!({}));
    assert_eq!(result["items"].as_array().map(Vec::len), Some(1));
    assert_eq!(result["items"][0]["id"], json!(1));
    assert_eq!(result["items"][0]["ts_ms"], json!(1_762_300_060_000i64));
    assert_eq!(result["items"][0]["rule"], json!("new_device"));
    assert_eq!(result["items"][0]["severity"], json!("info"));
    assert_eq!(result["items"][0]["device_id"], json!(1));
    assert_eq!(result["items"][0]["summary"], json!("example-ssid"));
    assert!(result["items"][0]["details"].is_null());

    let result = server.result("sources.list", json!({}));
    assert_eq!(result["items"].as_array().map(Vec::len), Some(1));
    assert_eq!(result["items"][0]["name"], json!("pcap:wlan1mon"));
    assert_eq!(result["items"][0]["kind"], json!("pcap"));
    assert_eq!(result["items"][0]["iface"], json!("wlan1mon"));
    assert_eq!(result["items"][0]["status"], json!("running"));
    assert_eq!(
        result["items"][0]["last_seen_ms"],
        json!(1_762_300_060_000i64)
    );
    assert_eq!(result["items"][0]["frames"], json!(12345));
    assert_eq!(result["items"][0]["errors"], json!(0));
}

/// The filters narrow the lists.
#[test]
fn the_filters_narrow_the_lists() {
    let server = TestServer::populated();

    let result = server.result("devices.list", json!({"kind": "ap"}));
    assert_eq!(result["items"].as_array().map(Vec::len), Some(1));
    assert_eq!(result["items"][0]["mac"], json!("00:11:22:33:44:01"));

    let result = server.result("devices.list", json!({"oui": "00:11:22"}));
    assert_eq!(result["items"].as_array().map(Vec::len), Some(5));

    let result = server.result("devices.list", json!({"min_rssi": -50}));
    assert_eq!(result["items"].as_array().map(Vec::len), Some(1));

    let result = server.result("devices.list", json!({"since_ms": 1_762_300_050_000i64}));
    assert_eq!(result["items"].as_array().map(Vec::len), Some(2));

    let result = server.result("aps.list", json!({"band": "5"}));
    assert_eq!(result["items"].as_array().map(Vec::len), Some(1));
    assert_eq!(result["items"][0]["bssid"], json!("00:11:22:33:44:01"));

    let result = server.result("aps.list", json!({"band": "2.4"}));
    assert_eq!(result["items"].as_array().map(Vec::len), Some(1));
    assert_eq!(result["items"][0]["bssid"], json!("00:11:22:33:44:02"));

    let result = server.result("aps.list", json!({"security": "WPA2-PSK"}));
    assert_eq!(result["items"].as_array().map(Vec::len), Some(1));

    let result = server.result("aps.list", json!({"ssid": "example-ssid"}));
    assert_eq!(result["items"].as_array().map(Vec::len), Some(1));

    let result = server.result("clients.list", json!({"bssid": "00:11:22:33:44:01"}));
    assert_eq!(result["items"].as_array().map(Vec::len), Some(3));

    let result = server.result("probes.list", json!({"client": "00:11:22:33:44:02"}));
    assert_eq!(result["items"].as_array().map(Vec::len), Some(1));

    let result = server.result("sightings.list", json!({"mac": "00:11:22:33:44:01"}));
    assert_eq!(result["items"].as_array().map(Vec::len), Some(1));

    let result = server.result("sightings.list", json!({"from_ms": 1_762_300_060_000i64}));
    assert_eq!(result["items"].as_array().map(Vec::len), Some(1));

    let result = server.result("alerts.list", json!({"rule": "new_device"}));
    assert_eq!(result["items"].as_array().map(Vec::len), Some(1));

    let result = server.result("alerts.list", json!({"severity": "warning"}));
    assert_eq!(result["items"].as_array().map(Vec::len), Some(0));
}

/// An SSID that is not valid UTF-8 is decoded, not dropped.
#[test]
fn an_ssid_that_is_not_utf8_is_decoded_with_the_replacement_character() {
    let server = TestServer::populated();

    let result = server.result("aps.list", json!({}));
    let item = &result["items"][0];
    assert_eq!(item["bssid"], json!("00:11:22:33:44:02"));
    assert_eq!(item["ssid"], json!("\u{FFFD}\u{FFFD}"));
    assert_eq!(item["ssid_hidden"], json!(true));
    assert_eq!(item["pmf_required"], json!(true));
    assert_eq!(item["wps"], json!(true));
    assert_eq!(item["vendor_ies"], json!("example-vendor"));
}

/// An unknown method, a malformed line and a missing token are refused.
#[test]
fn the_errors_are_the_ones_the_contract_names() {
    let server = TestServer::populated();

    let response = server.response("no.such.method", json!({}));
    assert_eq!(response["error"]["code"], json!(METHOD_NOT_FOUND));
    assert_eq!(response["error"]["message"], json!("no such method"));
    assert!(response.get("result").is_none());

    let response = server
        .server
        .handle_line("this is not json")
        .expect("there should be a response");
    assert_eq!(response["error"]["code"], json!(PARSE_ERROR));
    assert!(response.get("result").is_none());

    let response = server.raw("devices.list", json!({}));
    assert_eq!(response["error"]["code"], json!(UNAUTHORIZED));

    let response = server.raw("devices.list", json!({"token": "not the token"}));
    assert_eq!(response["error"]["code"], json!(UNAUTHORIZED));

    let response = server.raw("devices.list", json!({"token": 42}));
    assert_eq!(response["error"]["code"], json!(UNAUTHORIZED));

    let response = server
        .server
        .handle_line("{\"jsonrpc\":\"1.0\",\"id\":1,\"method\":\"status\"}")
        .expect("there should be a response");
    assert_eq!(response["error"]["code"], json!(INVALID_REQUEST));

    let response = server.response("devices.get", json!({}));
    assert_eq!(response["error"]["code"], json!(INVALID_PARAMS));

    let response = server.response("devices.list", json!({"limit": 0}));
    assert_eq!(response["error"]["code"], json!(INVALID_PARAMS));

    let response = server.response("devices.list", json!({"limit": "many"}));
    assert_eq!(response["error"]["code"], json!(INVALID_PARAMS));
}

/// The token is checked before the method, so the methods cannot be probed.
#[test]
fn the_token_is_checked_before_the_method() {
    let server = TestServer::populated();

    // A method that does not exist, with a token that does not fit: the
    // answer is about the token, not about the method.
    let response = server.raw("no.such.method", json!({"token": "not the token"}));
    assert_eq!(response["error"]["code"], json!(UNAUTHORIZED));

    // Every method answers the same way without a token.
    for method in METHODS {
        let response = server.raw(method, json!({}));
        assert_eq!(
            response["error"]["code"],
            json!(UNAUTHORIZED),
            "the method {method}"
        );
    }
}

/// A request without an id is a notification, and gets no response.
#[test]
fn a_notification_gets_no_response() {
    let server = TestServer::populated();

    let request = json!({"jsonrpc": "2.0", "method": "status", "params": {"token": TOKEN}});
    let line = serde_json::to_string(&request).expect("the request should serialize");
    assert!(server.server.handle_line(&line).is_none());

    let request = json!({"jsonrpc": "2.0", "method": "status"});
    let line = serde_json::to_string(&request).expect("the request should serialize");
    assert!(server.server.handle_line(&line).is_none());
}

/// No method writes: the database is the same afterwards.
#[test]
fn no_method_writes_to_the_database() {
    let path = temp_database_path();
    remove_database(&path);

    let store = Store::open(&path).expect("the store should open");
    populate(&store);
    let before = snapshot(&store);

    let server = TestServer::with_store(store);
    for method in METHODS {
        let response = server.response(method, params_for(method));
        assert!(
            response.get("result").is_some(),
            "the method {method} should have answered: {response}"
        );
    }
    server.server.stop();

    let after_store = Store::open(&path).expect("the store should open again");
    let after = snapshot(&after_store);
    assert_eq!(before, after, "the database should not have changed");

    drop(after_store);
    remove_database(&path);
}

/// The pagination walks the rows without repeats or gaps.
#[test]
fn pagination_walks_the_rows_without_repeats_or_gaps() {
    let server = TestServer::populated();

    let mut macs: Vec<String> = Vec::new();
    let mut cursor = Json::Null;
    let mut pages = 0;

    loop {
        let params = if cursor.is_null() {
            json!({"limit": 2})
        } else {
            json!({"limit": 2, "cursor": cursor})
        };
        let result = server.result("devices.list", params);
        let items = result["items"]
            .as_array()
            .expect("the items should be an array")
            .clone();
        for item in items {
            macs.push(
                item["mac"]
                    .as_str()
                    .expect("the mac should be a string")
                    .to_string(),
            );
        }

        pages += 1;
        assert!(pages < 10, "the pagination should end");
        cursor = result["next_cursor"].clone();
        if cursor.is_null() {
            break;
        }
        assert!(cursor.is_string(), "the cursor should be a string");
    }

    assert_eq!(pages, 3, "five rows come in three pages of two");
    assert_eq!(
        macs,
        vec![
            "00:11:22:33:44:05",
            "00:11:22:33:44:04",
            "00:11:22:33:44:03",
            "00:11:22:33:44:02",
            "00:11:22:33:44:01",
        ]
    );
}

/// The pagination of a method whose cursor carries three sort columns.
#[test]
fn pagination_walks_the_three_part_cursors_too() {
    let server = TestServer::populated();

    let mut clients: Vec<String> = Vec::new();
    let mut cursor = Json::Null;
    let mut pages = 0;

    loop {
        let params = if cursor.is_null() {
            json!({"limit": 1})
        } else {
            json!({"limit": 1, "cursor": cursor})
        };
        let result = server.result("clients.list", params);
        for item in result["items"]
            .as_array()
            .expect("the items should be an array")
            .clone()
        {
            clients.push(
                item["client"]
                    .as_str()
                    .expect("the client should be a string")
                    .to_string(),
            );
        }

        pages += 1;
        assert!(pages < 10, "the pagination should end");
        cursor = result["next_cursor"].clone();
        if cursor.is_null() {
            break;
        }
    }

    assert_eq!(pages, 3, "three rows come in three pages of one");
    assert_eq!(
        clients,
        vec![
            "00:11:22:33:44:04",
            "00:11:22:33:44:03",
            "00:11:22:33:44:02",
        ]
    );
}

/// A filter value that contains a quote is data, not SQL.
///
/// The values are bound to the statement, so a quote in one cannot change
/// what the statement means. The property is pinned here: a value that
/// would match every row if it were written into the SQL matches no row,
/// and the tables are all still there afterwards.
#[test]
fn a_filter_value_with_a_quote_is_data_and_not_sql() {
    let server = TestServer::populated();

    // An SSID that tries to end the statement.
    let result = server.result("aps.list", json!({"ssid": "x'; DROP TABLE devices; --"}));
    assert_eq!(result["items"].as_array().map(Vec::len), Some(0));

    let result = server.result("probes.list", json!({"ssid": "x'; DROP TABLE devices; --"}));
    assert_eq!(result["items"].as_array().map(Vec::len), Some(0));

    // The filters that would match every row if the value were SQL.
    let result = server.result("devices.list", json!({"kind": "ap' OR '1'='1"}));
    assert_eq!(result["items"].as_array().map(Vec::len), Some(0));

    let result = server.result("devices.list", json!({"oui": "00:11:22' OR '1'='1"}));
    assert_eq!(result["items"].as_array().map(Vec::len), Some(0));

    let result = server.result("aps.list", json!({"security": "WPA2-PSK' OR '1'='1"}));
    assert_eq!(result["items"].as_array().map(Vec::len), Some(0));

    let result = server.result("aps.list", json!({"band": "5' OR '1'='1"}));
    assert_eq!(result["items"].as_array().map(Vec::len), Some(0));

    let result = server.result("alerts.list", json!({"rule": "new_device' OR '1'='1"}));
    assert_eq!(result["items"].as_array().map(Vec::len), Some(0));

    let result = server.result("alerts.list", json!({"severity": "info' OR '1'='1"}));
    assert_eq!(result["items"].as_array().map(Vec::len), Some(0));

    let result = server.result("ble.list", json!({"name": "x' OR '1'='1"}));
    assert_eq!(result["items"].as_array().map(Vec::len), Some(0));

    // A MAC is checked before it reaches the statement at all, so it is
    // refused rather than matched.
    let response = server.response(
        "devices.get",
        json!({"mac": "00:11:22:33:44:01' OR '1'='1"}),
    );
    assert_eq!(response["error"]["code"], json!(INVALID_PARAMS));

    // The tables are all still there, and they hold what they held.
    let result = server.result("devices.list", json!({}));
    assert_eq!(result["items"].as_array().map(Vec::len), Some(5));

    let result = server.result("status", json!({}));
    assert_eq!(result["counts"]["devices"], json!(5));
    assert_eq!(result["counts"]["aps"], json!(2));
    assert_eq!(result["counts"]["clients"], json!(3));
}

/// The cursor is opaque: it cannot be edited into meaning something else.
#[test]
fn a_cursor_cannot_be_edited() {
    let server = TestServer::populated();

    let result = server.result("devices.list", json!({"limit": 2}));
    let cursor = result["next_cursor"]
        .as_str()
        .expect("there should be a cursor")
        .to_string();

    // A cursor that was edited does not pass the checksum.
    let edited = format!("{cursor}0");
    let response = server.response("devices.list", json!({"limit": 2, "cursor": edited}));
    assert_eq!(response["error"]["code"], json!(INVALID_PARAMS));

    // A cursor that is not a cursor at all does not either.
    let response = server.response("devices.list", json!({"limit": 2, "cursor": "1"}));
    assert_eq!(response["error"]["code"], json!(INVALID_PARAMS));

    // A cursor from another method does not either.
    let response = server.response("aps.list", json!({"limit": 2, "cursor": cursor}));
    assert_eq!(response["error"]["code"], json!(INVALID_PARAMS));
}

/// The cursor of another method is refused, and the error says so.
#[test]
fn a_cursor_from_another_method_is_refused() {
    let server = TestServer::populated();

    let result = server.result("devices.list", json!({"limit": 2}));
    let cursor = result["next_cursor"].clone();
    let response = server.response("aps.list", json!({"limit": 2, "cursor": cursor}));
    assert_eq!(response["error"]["code"], json!(INVALID_PARAMS));
    assert!(
        response["error"]["message"]
            .as_str()
            .expect("the message should be a string")
            .contains("another method"),
        "the message should name the problem: {}",
        response["error"]["message"]
    );
}

/// A line that is not JSON does not kill the connection.
#[test]
fn a_bad_line_does_not_kill_the_connection() {
    let server = TestServer::populated();
    let worker = server.server.clone();
    let handle = thread::spawn(move || {
        let _ = worker.serve();
    });

    let mut stream = UnixStream::connect(&server.path).expect("the socket should connect");
    let mut reader = BufReader::new(stream.try_clone().expect("the stream should clone"));

    stream
        .write_all(b"this is not json\n")
        .expect("the line should be written");
    stream.flush().expect("the line should be flushed");

    let mut line = String::new();
    reader
        .read_line(&mut line)
        .expect("the answer should be read");
    let response: Json = serde_json::from_str(line.trim()).expect("the answer should be JSON");
    assert_eq!(response["error"]["code"], json!(PARSE_ERROR));

    // The connection is still open: the next request is answered.
    let request =
        json!({"jsonrpc": "2.0", "id": 2, "method": "status", "params": {"token": TOKEN}});
    let request = format!("{request}\n");
    stream
        .write_all(request.as_bytes())
        .expect("the request should be written");
    stream.flush().expect("the request should be flushed");

    let mut line = String::new();
    reader
        .read_line(&mut line)
        .expect("the answer should be read");
    let response: Json = serde_json::from_str(line.trim()).expect("the answer should be JSON");
    assert_eq!(response["id"], json!(2));
    assert!(response.get("result").is_some());

    server.server.stop();
    let _ = handle.join();
}

/// The request and the response are one line each.
#[test]
fn a_request_and_its_response_are_one_line_each() {
    let server = TestServer::populated();
    let worker = server.server.clone();
    let handle = thread::spawn(move || {
        let _ = worker.serve();
    });

    let mut stream = UnixStream::connect(&server.path).expect("the socket should connect");
    let mut reader = BufReader::new(stream.try_clone().expect("the stream should clone"));

    let request = json!({"jsonrpc": "2.0", "id": 7, "method": "devices.list", "params": {"token": TOKEN, "limit": 2}});
    let request = format!("{request}\n");
    assert_eq!(request.matches('\n').count(), 1, "the request is one line");

    stream
        .write_all(request.as_bytes())
        .expect("the request should be written");
    stream.flush().expect("the request should be flushed");

    let mut line = String::new();
    reader
        .read_line(&mut line)
        .expect("the answer should be read");
    assert!(line.ends_with('\n'), "the answer ends with a newline");
    assert_eq!(line.matches('\n').count(), 1, "the answer is one line");

    let response: Json = serde_json::from_str(line.trim()).expect("the answer should be JSON");
    assert_eq!(response["id"], json!(7));
    assert_eq!(response["jsonrpc"], json!("2.0"));

    server.server.stop();
    let _ = handle.join();
}

/// The server only runs statements that read.
#[test]
fn only_read_only_statements_are_run() {
    assert!(read_only("SELECT 1").is_ok());
    assert!(read_only("  select * from devices").is_ok());
    assert!(read_only("PRAGMA page_count").is_ok());
    assert!(read_only("PRAGMA page_size").is_ok());

    assert!(read_only("INSERT INTO devices (mac) VALUES ('00:11:22:33:44:99')").is_err());
    assert!(read_only("UPDATE devices SET mac = 'x'").is_err());
    assert!(read_only("DELETE FROM devices").is_err());
    assert!(read_only("DROP TABLE devices").is_err());
    assert!(read_only("PRAGMA journal_mode = DELETE").is_err());
}

/// The token is random enough and long enough to be worth something.
#[test]
fn a_generated_token_is_not_guessable() {
    let first = generate_token().expect("the token should be generated");
    let second = generate_token().expect("the token should be generated");

    assert!(first.len() >= 32, "the token should be long: {first}");
    assert_ne!(first, second, "two tokens should not be the same");
    assert!(
        first.chars().all(|character| character.is_ascii_hexdigit()),
        "the token should be hexadecimal: {first}"
    );
}

/// A plugin's token may only call the methods its manifest asked for.
#[test]
fn a_scoped_token_may_only_call_its_own_methods() {
    let server = TestServer::populated();

    // The plugin's own secret, scoped to two of the methods.
    server.server.add_token(
        "plugin-secret",
        vec!["status".to_string(), "devices.list".to_string()],
    );

    // A method it was given works.
    let allowed = server.raw(
        "devices.list",
        json!({"token": "plugin-secret", "limit": 10}),
    );
    assert!(
        allowed.get("result").is_some(),
        "the method it was given should work: {allowed}"
    );

    // A method it was not given does not, even though the method exists.
    let refused = server.raw("aps.list", json!({"token": "plugin-secret", "limit": 10}));
    assert_eq!(
        refused["error"]["code"],
        json!(UNAUTHORIZED),
        "a method outside the scope should be refused"
    );

    // And the daemon's own token still reaches everything.
    let own = server.response("aps.list", json!({"limit": 10}));
    assert!(
        own.get("result").is_some(),
        "the daemon's own token should reach everything: {own}"
    );
}
