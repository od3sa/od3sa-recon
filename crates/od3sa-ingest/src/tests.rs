//! The ingest adapter's tests.
//!
//! The files are synthetic: the WiGLE CSV rows carry made-up addresses and
//! made-up coordinates.

use std::collections::HashMap;

use super::blue5::*;

/// A WiGLE CSV, as blue5 writes one.
const WIGLE: &str = "WigleDB-Version,WigleDB-Timestamp,Latitude,Longitude,AltMeters,SSID,Channel,Frequency,MAC,AddressRadio,Noise,SignalStrength,BeaconType,EncryptionType,AuthenticationType,LastSeen,Today,Claimed,ClaimedAt,Country\n\
1,1762300000,52.520000,13.405000,34.0,example-net,36,5180,00:11:22:33:44:01,wifi,-95,-42,beacon,wpa2,wpa2,1762300000,08-11-2026,false,,DE\n";

#[test]
fn the_header_says_which_column_is_which() {
    let columns =
        read_header(WIGLE.lines().next().expect("the header")).expect("the header should parse");
    let network = read_row(WIGLE.lines().nth(1).expect("a row"), &columns)
        .expect("the row should parse")
        .expect("the row should be a network");

    assert_eq!(network.mac, "00:11:22:33:44:01");
    assert_eq!(network.ssid, "example-net");
    assert_eq!(network.channel, Some(36));
    assert_eq!(network.frequency, Some(5180));
    assert_eq!(network.signal, Some(-42));
    assert_eq!(network.latitude, Some(52.52));
    assert_eq!(network.longitude, Some(13.405));
    assert_eq!(network.altitude, Some(34.0));
}

#[test]
fn a_header_without_a_mac_is_an_error() {
    let error = read_header("a,b,c").expect_err("a header without a mac should fail");
    assert!(matches!(error, IngestError::UnknownColumn(_)));
}

#[test]
fn a_row_without_a_mac_is_skipped() {
    let columns =
        read_header(WIGLE.lines().next().expect("the header")).expect("the header should parse");
    assert_eq!(
        read_row(",,,,,,,,,,,,,,,,,,,,", &columns).expect("the row should parse"),
        None
    );
    assert_eq!(read_row("", &columns).expect("the row should parse"), None);
}

#[test]
fn a_missing_value_is_empty_rather_than_zero() {
    let columns =
        read_header(WIGLE.lines().next().expect("the header")).expect("the header should parse");
    // A row with an address but nothing else: the empty values are
    // empty, not zero.
    let row = "1,1762300000,,,,example-net,,,00:11:22:33:44:01,wifi,-95,,,,,,,,\n";
    let network = read_row(row, &columns)
        .expect("the row should parse")
        .expect("the row should be a network");
    assert_eq!(network.channel, None);
    assert_eq!(network.latitude, None);
    assert_eq!(network.signal, None);
    assert_eq!(network.mac, "00:11:22:33:44:01");
}

#[test]
fn a_quoted_field_with_a_comma_in_it_survives() {
    let columns =
        read_header(WIGLE.lines().next().expect("the header")).expect("the header should parse");
    let row = "1,1762300000,52.5,13.4,34.0,\"example, net\",36,5180,00:11:22:33:44:01,wifi,-95,-42,beacon,wpa2,wpa2,1762300000,08-11-2026,false,,DE\n";
    let network = read_row(row, &columns)
        .expect("the row should parse")
        .expect("the row should be a network");
    assert_eq!(network.ssid, "example, net");
    assert_eq!(network.mac, "00:11:22:33:44:01");
}

#[test]
fn a_doubled_quote_in_a_field_is_one_quote() {
    let columns =
        read_header(WIGLE.lines().next().expect("the header")).expect("the header should parse");
    let row = "1,1762300000,52.5,13.4,34.0,\"say \"\"hi\"\"\",36,5180,00:11:22:33:44:01,wifi,-95,-42,beacon,wpa2,wpa2,1762300000,08-11-2026,false,,DE\n";
    let network = read_row(row, &columns)
        .expect("the row should parse")
        .expect("the row should be a network");
    assert_eq!(network.ssid, "say \"hi\"");
}

#[test]
fn a_file_is_read_once() {
    let path = std::env::temp_dir().join(format!(
        "od3sa-ingest-test-{}-read.pcap",
        std::process::id()
    ));
    std::fs::write(&path, WIGLE).expect("the file should be written");

    let networks = read_all(&path).expect("the file should be read");
    assert_eq!(networks.len(), 1);
    assert_eq!(networks[0].mac, "00:11:22:33:44:01");

    let _ = std::fs::remove_file(&path);
}

#[test]
fn a_file_that_is_not_there_is_an_error() {
    let error =
        read_all(std::path::Path::new("/nonexistent/blue5.csv")).expect_err("it should fail");
    assert!(matches!(error, IngestError::Io(_)));
}

#[test]
fn a_network_that_has_not_changed_is_not_new() {
    let networks = vec![Network {
        mac: "00:11:22:33:44:01".to_string(),
        ssid: "example-net".to_string(),
        channel: Some(36),
        frequency: Some(5180),
        signal: Some(-42),
        latitude: None,
        longitude: None,
        altitude: None,
    }];
    let mut seen: HashMap<String, Network> = HashMap::new();

    // The first time, it is new.
    assert_eq!(new_networks(&mut seen, &networks).len(), 1);
    // The second time, it is not.
    assert_eq!(new_networks(&mut seen, &networks).len(), 0);
}

#[test]
fn a_network_that_got_stronger_is_new_again() {
    let weaker = Network {
        mac: "00:11:22:33:44:01".to_string(),
        ssid: "example-net".to_string(),
        channel: Some(36),
        frequency: Some(5180),
        signal: Some(-60),
        latitude: None,
        longitude: None,
        altitude: None,
    };
    let stronger = Network {
        signal: Some(-40),
        ..weaker.clone()
    };

    let mut seen: HashMap<String, Network> = HashMap::new();
    assert_eq!(
        new_networks(&mut seen, std::slice::from_ref(&weaker)).len(),
        1
    );
    assert_eq!(new_networks(&mut seen, &[stronger]).len(), 1);
}

#[test]
fn a_network_becomes_an_access_point() {
    let network = Network {
        mac: "00:11:22:33:44:01".to_string(),
        ssid: "example-net".to_string(),
        channel: Some(36),
        frequency: Some(5180),
        signal: Some(-42),
        latitude: Some(52.52),
        longitude: Some(13.405),
        altitude: Some(34.0),
    };
    let access_point = network.as_access_point();
    assert_eq!(access_point.bssid, [0x00, 0x11, 0x22, 0x33, 0x44, 0x01]);
    assert_eq!(access_point.ssid.as_deref(), Some(&b"example-net"[..]));
    assert_eq!(access_point.channel, Some(36));
    assert_eq!(access_point.freq_mhz, Some(5180));
}
