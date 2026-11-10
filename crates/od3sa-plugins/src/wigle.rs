//! The WiGLE CSV: the access points the daemon has seen, in the format the
//! WiGLE database takes.
//!
//! The export is one row per access point, taken from the daemon's
//! `aps.list`. The position and the signal come from a sighting of that
//! access point, which the daemon keeps with a fix on it when the Pager had
//! a GPS fix at the time.
//!
//! The file is written the way RFC 4180 says: a field that holds a comma, a
//! quote or a newline is quoted, and a quote inside a field is doubled. An
//! SSID with a comma in it does not break the file.
//!
//! The plugin reads and writes nothing but the CSV. It never touches a
//! radio, a channel or a service.

use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{Value, json};

use crate::client::{PluginError, QueryClient};

/// The header of a WiGLE CSV, exactly as the WiGLE database writes it.
pub const HEADER: &str = "WigleDB-Version,WigleDB-Timestamp,Latitude,Longitude,AltMeters,SSID,Channel,Frequency,MAC,AddressRadio,Noise,SignalStrength,BeaconType,EncryptionType,AuthenticationType,LastSeen,Today,Claimed,ClaimedAt,Country";

/// How far back, in milliseconds, a sighting of an access point is looked
/// for.
///
/// The daemon buckets its sightings by the minute and keeps them for as long
/// as its retention says. The window is around the last beacon of the access
/// point, because that is the sighting that goes with the position the row
/// carries: the position on a sighting is the place the Pager was when it
/// heard the access point, and the fix of that moment is the one that is
/// wanted.
///
/// An hour is sixty buckets, which is a small answer for the daemon to
/// hold, and long enough for the fix to still be there.
const SIGHTING_WINDOW_MS: i64 = 60 * 60 * 1_000;

/// The whole export, as a string.
///
/// The time is the time of the export, in unix epoch seconds. The rows come
/// from the daemon, one per access point, in the order the daemon gives
/// them.
///
/// # Errors
///
/// Returns an error when the daemon cannot be reached or does not answer
/// with what the query API says it answers with.
pub fn export(client: &QueryClient, exported_at: i64) -> Result<String, PluginError> {
    let access_points = client.call_all("aps.list", json!({}))?;

    let mut csv = String::with_capacity(HEADER.len() + 96 * access_points.len());
    csv.push_str(HEADER);
    csv.push('\n');

    for item in &access_points {
        let access_point = AccessPoint::from_json(item);
        let sighting = newest_sighting(client, &access_point, exported_at)?;
        csv.push_str(&row(&access_point, sighting.as_ref(), exported_at));
        csv.push('\n');
    }

    Ok(csv)
}

/// The whole export, as a string, at the time of the call.
///
/// # Errors
///
/// Returns an error when the daemon cannot be reached or does not answer
/// with what the query API says it answers with.
pub fn export_now(client: &QueryClient) -> Result<String, PluginError> {
    export(client, unix_seconds())
}

/// One access point, as the export needs it.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct AccessPoint {
    /// The BSSID, lower case with colons, as the daemon writes it.
    pub bssid: Option<String>,
    /// The name of the network, if it has one.
    pub ssid: Option<String>,
    /// Whether the network hides its name.
    pub ssid_hidden: bool,
    /// The channel the access point was last heard on.
    pub channel: Option<i64>,
    /// The frequency of that channel, in megahertz.
    pub freq_mhz: Option<i64>,
    /// The security label of the network, as the daemon names it.
    pub security: Option<String>,
    /// When the access point was last heard, in unix epoch milliseconds.
    pub last_beacon_ms: Option<i64>,
}

impl AccessPoint {
    /// Read an access point out of an `aps.list` item.
    pub fn from_json(item: &Value) -> AccessPoint {
        AccessPoint {
            bssid: text_of(item, "bssid"),
            ssid: text_of(item, "ssid"),
            ssid_hidden: item
                .get("ssid_hidden")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            channel: item.get("channel").and_then(Value::as_i64),
            freq_mhz: item.get("freq_mhz").and_then(Value::as_i64),
            security: text_of(item, "security"),
            last_beacon_ms: item.get("last_beacon_ms").and_then(Value::as_i64),
        }
    }
}

/// One sighting of an access point, as the export needs it.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Sighting {
    /// The bucket of the sighting, in unix epoch milliseconds.
    pub bucket_ms: i64,
    /// The signal, in dBm. It is negative.
    pub rssi: Option<i64>,
    /// The latitude, in degrees.
    pub lat: Option<f64>,
    /// The longitude, in degrees.
    pub lon: Option<f64>,
    /// The altitude, in metres.
    pub alt: Option<f64>,
}

impl Sighting {
    /// Read a sighting out of a `sightings.list` item.
    pub fn from_json(item: &Value) -> Sighting {
        Sighting {
            bucket_ms: item.get("bucket_ms").and_then(Value::as_i64).unwrap_or(0),
            rssi: rssi_of(item),
            lat: number_of(item, "lat"),
            lon: number_of(item, "lon"),
            alt: number_of(item, "alt"),
        }
    }

    /// Whether the sighting carries a position.
    pub fn has_position(&self) -> bool {
        self.lat.is_some() && self.lon.is_some()
    }
}

/// The row of one access point, as a line of CSV.
///
/// The position and the signal are empty when there is no sighting, or when
/// the sighting carries no fix. The exported time is the time of the export.
pub fn row(access_point: &AccessPoint, sighting: Option<&Sighting>, exported_at: i64) -> String {
    let last_seen = access_point.last_beacon_ms.map(|ms| ms / 1_000);
    let (encryption, authentication) = security_columns(access_point.security.as_deref());

    let mut fields: Vec<String> = Vec::with_capacity(20);
    fields.push(String::new());
    fields.push(exported_at.to_string());

    match sighting {
        Some(sighting) if sighting.has_position() => {
            fields.push(sighting.lat.map(format_coordinate).unwrap_or_default());
            fields.push(sighting.lon.map(format_coordinate).unwrap_or_default());
            fields.push(sighting.alt.map(format_number).unwrap_or_default());
        }
        _ => {
            fields.push(String::new());
            fields.push(String::new());
            fields.push(String::new());
        }
    }

    if access_point.ssid_hidden {
        fields.push(String::new());
    } else {
        fields.push(access_point.ssid.clone().unwrap_or_default());
    }

    fields.push(opt_number(access_point.channel));
    fields.push(opt_number(access_point.freq_mhz));
    fields.push(mac_upper(access_point.bssid.as_deref()));
    fields.push("wifi".to_string());
    fields.push(String::new());
    fields.push(
        sighting
            .and_then(|sighting| sighting.rssi)
            .map(|rssi| rssi.to_string())
            .unwrap_or_default(),
    );
    fields.push("beacon".to_string());
    fields.push(encryption.to_string());
    fields.push(authentication.to_string());
    fields.push(
        last_seen
            .map(|seconds| seconds.to_string())
            .unwrap_or_default(),
    );
    fields.push(last_seen.map(format_day).unwrap_or_default());
    fields.push("false".to_string());
    fields.push(String::new());
    fields.push(String::new());

    fields
        .iter()
        .map(|field| csv_field(field))
        .collect::<Vec<String>>()
        .join(",")
}

/// The encryption and the authentication of a network, as WiGLE names them.
///
/// The daemon labels a network with the security it saw in its beacons:
/// "open", "WPA-PSK", "WPA2-PSK", "WPA3-SAE", "WEP" and so on. WiGLE asks
/// for the generation of the network, so a WPA2 network is `wpa2` and a
/// WPA one is `wpa`, whether it is a personal or an enterprise network.
///
/// A network the daemon could not name, and a WEP one, have no generation
/// of their own in the set WiGLE uses here. Both are private networks, and
/// both are written as `wpa`: they are not open ones, and `wpa` is the
/// wider of the two.
pub fn security_columns(security: Option<&str>) -> (&'static str, &'static str) {
    let label = security.unwrap_or("").trim().to_ascii_uppercase();

    if label.is_empty() || label == "OPEN" || label == "NONE" {
        return ("none", "open");
    }
    if label.contains("WPA2") || label.contains("WPA3") {
        return ("wpa2", "wpa2");
    }
    if label.contains("WPA") {
        return ("wpa", "wpa");
    }
    ("wpa", "wpa")
}

/// The MAC of an access point, upper case with colons.
///
/// The daemon writes a MAC lower case; WiGLE writes it upper case.
pub fn mac_upper(bssid: Option<&str>) -> String {
    bssid.unwrap_or("").trim().to_ascii_uppercase()
}

/// One field of a CSV line, quoted when it has to be.
///
/// A field with a comma, a quote or a newline in it is quoted, and a quote
/// inside it is doubled.
pub fn csv_field(value: &str) -> String {
    if !value.contains([',', '"', '\n', '\r']) {
        return value.to_string();
    }

    let mut quoted = String::with_capacity(value.len() + 2);
    quoted.push('"');
    for character in value.chars() {
        if character == '"' {
            quoted.push('"');
        }
        quoted.push(character);
    }
    quoted.push('"');
    quoted
}

/// The day of a time, as `DD-MM-YYYY`.
///
/// The time is in unix epoch seconds, and the day is the UTC one.
pub fn format_day(epoch_seconds: i64) -> String {
    let days = epoch_seconds.div_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    format!("{day:02}-{month:02}-{year:04}")
}

/// The number of seconds since the epoch, now.
pub fn unix_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|since| since.as_secs() as i64)
        .unwrap_or(0)
}

/// The sighting a row carries.
///
/// The newest sighting that has a position wins, because a row without a
/// position is worth little to WiGLE. When no sighting has one, the newest
/// sighting of all is used, so that the row still carries a signal.
fn newest_sighting(
    client: &QueryClient,
    access_point: &AccessPoint,
    exported_at: i64,
) -> Result<Option<Sighting>, PluginError> {
    let Some(bssid) = access_point.bssid.as_deref() else {
        return Ok(None);
    };
    if !is_mac(bssid) {
        return Ok(None);
    }

    // The anchor is the last time the access point was heard. A zero means
    // it was never heard, and then the export time is the best guess there
    // is.
    let anchor = match access_point.last_beacon_ms {
        Some(ms) if ms > 0 => ms,
        _ => exported_at.saturating_mul(1_000),
    };

    let sightings = sightings_in(client, bssid, anchor, SIGHTING_WINDOW_MS)?;
    Ok(pick_sighting(&sightings))
}

/// The sightings of one access point, within a window around an anchor.
///
/// The window is in milliseconds and the anchor is one too. The window runs
/// on both sides of the anchor: a sighting is bucketed by the minute, so
/// the bucket of the last beacon can sit on either side of it.
fn sightings_in(
    client: &QueryClient,
    bssid: &str,
    anchor_ms: i64,
    window_ms: i64,
) -> Result<Vec<Sighting>, PluginError> {
    let items = client.call_all(
        "sightings.list",
        json!({
            "mac": bssid,
            "from_ms": anchor_ms.saturating_sub(window_ms),
            "to_ms": anchor_ms.saturating_add(window_ms),
        }),
    )?;
    Ok(items.iter().map(Sighting::from_json).collect())
}

/// The sighting a row carries: the newest one with a position, or the
/// newest one of all.
fn pick_sighting(sightings: &[Sighting]) -> Option<Sighting> {
    let with_position = sightings
        .iter()
        .filter(|sighting| sighting.has_position())
        .max_by_key(|sighting| sighting.bucket_ms);

    match with_position {
        Some(sighting) => Some(sighting.clone()),
        None => sightings
            .iter()
            .max_by_key(|sighting| sighting.bucket_ms)
            .cloned(),
    }
}

/// Whether a string looks like a MAC address.
///
/// The daemon writes them lower case with colons, and the query API refuses
/// anything else, so a malformed one is skipped rather than sent.
fn is_mac(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 17
        && bytes
            .iter()
            .enumerate()
            .all(|(index, byte)| match index % 3 {
                2 => *byte == b':',
                _ => byte.is_ascii_hexdigit(),
            })
}

/// A coordinate, to six decimals.
///
/// WiGLE writes a coordinate with six decimals, which is about a tenth of a
/// metre.
fn format_coordinate(value: f64) -> String {
    if !value.is_finite() {
        return String::new();
    }
    format!("{value:.6}")
}

/// A number as it is written: no trailing zeros, no trailing point.
fn format_number(value: f64) -> String {
    if !value.is_finite() {
        return String::new();
    }
    let text = format!("{value:.6}");
    let text = text.trim_end_matches('0');
    let text = text.trim_end_matches('.');
    if text == "-0" {
        return "0".to_string();
    }
    text.to_string()
}

/// A whole number as it is written, or nothing.
fn opt_number(value: Option<i64>) -> String {
    value.map(|number| number.to_string()).unwrap_or_default()
}

/// A string field of an item, or nothing.
fn text_of(item: &Value, field: &str) -> Option<String> {
    item.get(field)
        .and_then(Value::as_str)
        .map(|text| text.to_string())
}

/// A number field of an item, or nothing.
///
/// SQLite is dynamically typed, so a column that is a `REAL` may hold an
/// integer.
fn number_of(item: &Value, field: &str) -> Option<f64> {
    let value = item.get(field)?;
    value
        .as_f64()
        .or_else(|| value.as_i64().map(|number| number as f64))
}

/// The signal of a sighting, in dBm.
///
/// The average of the bucket is the signal of the access point; the strongest
/// and the weakest are the fallbacks.
fn rssi_of(item: &Value) -> Option<i64> {
    if let Some(average) = number_of(item, "rssi_avg") {
        return Some(average.round() as i64);
    }
    item.get("rssi_max")
        .and_then(Value::as_i64)
        .or_else(|| item.get("rssi_min").and_then(Value::as_i64))
}

/// The civil date of a number of days since the epoch.
///
/// This is Howard Hinnant's `civil_from_days`, the usual proleptic
/// Gregorian day count.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let shifted = days + 719_468;
    let era = if shifted >= 0 {
        shifted
    } else {
        shifted - 146_096
    } / 146_097;
    let day_of_era = shifted - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_of_year = (5 * day_of_year + 2) / 153;
    let day = (day_of_year - (153 * month_of_year + 2) / 5 + 1) as u32;
    let month = if month_of_year < 10 {
        month_of_year + 3
    } else {
        month_of_year - 9
    } as u32;
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// A scripted client that answers the two methods the export uses.
    fn client(aps: Value, sightings: Value) -> QueryClient {
        QueryClient::scripted(vec![("aps.list", aps), ("sightings.list", sightings)])
    }

    /// One access point, as the daemon would answer.
    fn ap_item() -> Value {
        json!({
            "bssid": "00:11:22:33:44:01",
            "ssid": "example-ssid",
            "ssid_hidden": false,
            "channel": 36,
            "freq_mhz": 5180,
            "security": "WPA2-PSK",
            "last_beacon_ms": 1_762_300_060_000i64,
        })
    }

    /// One sighting with a fix on it.
    fn sighted() -> Value {
        json!({
            "bucket_ms": 1_762_300_060_000i64,
            "rssi_avg": -51.0,
            "rssi_min": -60,
            "rssi_max": -42,
            "lat": 32.05,
            "lon": 34.75,
            "alt": 12.5,
            "fix": 3,
        })
    }

    /// One sighting without a fix on it.
    fn unsighted() -> Value {
        json!({
            "bucket_ms": 1_762_300_060_000i64,
            "rssi_avg": -51.0,
            "lat": null,
            "lon": null,
            "alt": null,
            "fix": null,
        })
    }

    /// The fields of a whole file, parsed. A quoted field may hold a
    /// newline, so the file is read as one string and not line by line.
    fn parse_csv(text: &str) -> Vec<Vec<String>> {
        let mut rows = Vec::new();
        let mut fields = Vec::new();
        let mut field = String::new();
        let mut quoted = false;
        let mut characters = text.chars().peekable();

        while let Some(character) = characters.next() {
            if quoted {
                if character == '"' {
                    if characters.peek() == Some(&'"') {
                        characters.next();
                        field.push('"');
                    } else {
                        quoted = false;
                    }
                } else {
                    field.push(character);
                }
            } else if character == '"' {
                quoted = true;
            } else if character == ',' {
                fields.push(std::mem::take(&mut field));
            } else if character == '\n' {
                fields.push(std::mem::take(&mut field));
                rows.push(std::mem::take(&mut fields));
            } else {
                field.push(character);
            }
        }
        if !field.is_empty() || !fields.is_empty() {
            fields.push(field);
            rows.push(fields);
        }
        rows
    }

    /// Test 1: the header is exactly the line the WiGLE database writes.
    #[test]
    fn the_header_is_the_wigle_header() {
        assert_eq!(
            HEADER,
            "WigleDB-Version,WigleDB-Timestamp,Latitude,Longitude,AltMeters,SSID,Channel,Frequency,MAC,AddressRadio,Noise,SignalStrength,BeaconType,EncryptionType,AuthenticationType,LastSeen,Today,Claimed,ClaimedAt,Country"
        );
    }

    /// Test 2: a row with a position carries it, and a row without one has
    /// the three position columns empty.
    #[test]
    fn a_position_is_carried_and_its_absence_is_empty() {
        let access_point = AccessPoint::from_json(&ap_item());

        let with_position = parse_csv(&format!(
            "{}\n",
            row(
                &access_point,
                Some(&Sighting::from_json(&sighted())),
                1_762_300_060,
            )
        ));
        assert_eq!(with_position[0][2], "32.050000");
        assert_eq!(with_position[0][3], "34.750000");
        assert_eq!(with_position[0][4], "12.5");

        let without_position = parse_csv(&format!(
            "{}\n",
            row(
                &access_point,
                Some(&Sighting::from_json(&unsighted())),
                1_762_300_060,
            )
        ));
        assert_eq!(without_position[0][2], "");
        assert_eq!(without_position[0][3], "");
        assert_eq!(without_position[0][4], "");

        let without_sighting = parse_csv(&format!("{}\n", row(&access_point, None, 1_762_300_060)));
        assert_eq!(without_sighting[0][2], "");
        assert_eq!(without_sighting[0][3], "");
        assert_eq!(without_sighting[0][4], "");
    }

    /// Test 3: an SSID with a comma, a quote or a newline in it is quoted,
    /// and the file still parses as CSV.
    #[test]
    fn an_ssid_with_a_comma_a_quote_or_a_newline_is_quoted() {
        for ssid in [
            "example,ssid",
            "example\"ssid",
            "example\nssid",
            "example, \"quoted\"\nssid",
        ] {
            let item = json!({
                "bssid": "00:11:22:33:44:01",
                "ssid": ssid,
                "ssid_hidden": false,
                "channel": 6,
                "freq_mhz": 2437,
                "security": "open",
                "last_beacon_ms": 1_762_300_060_000i64,
            });
            let csv = export(
                &client(json!({ "items": [item] }), json!({ "items": [sighted()] })),
                1_762_300_060,
            )
            .expect("the export should succeed");

            let rows = parse_csv(&csv);
            assert!(rows.len() >= 2, "the file should have a header and a row");
            for parsed in &rows {
                assert_eq!(parsed.len(), 20, "every row has twenty fields");
            }
            assert_eq!(rows[1][5], ssid, "the SSID survives the round trip");
        }
    }

    /// Test 3, again: the quoting itself.
    #[test]
    fn a_field_with_a_comma_a_quote_or_a_newline_is_quoted() {
        assert_eq!(csv_field("plain"), "plain");
        assert_eq!(csv_field("a,b"), "\"a,b\"");
        assert_eq!(csv_field("a\"b"), "\"a\"\"b\"");
        assert_eq!(csv_field("a\nb"), "\"a\nb\"");
    }

    /// Test 4: the MAC is upper case with colons.
    #[test]
    fn the_mac_is_upper_case_with_colons() {
        assert_eq!(mac_upper(Some("00:11:22:33:44:ab")), "00:11:22:33:44:AB");
        assert_eq!(mac_upper(Some("00:11:22:33:44:01")), "00:11:22:33:44:01");
        assert_eq!(mac_upper(None), "");

        let access_point = AccessPoint::from_json(&json!({
            "bssid": "aa:bb:cc:dd:ee:ff",
            "last_beacon_ms": 1_762_300_060_000i64,
        }));
        let fields = parse_csv(&format!("{}\n", row(&access_point, None, 1_762_300_060)));
        assert_eq!(fields[0][8], "AA:BB:CC:DD:EE:FF");
    }

    /// Test 5: the encryption and the authentication follow the security
    /// label of the network.
    #[test]
    fn the_security_label_drives_the_encryption_and_the_authentication() {
        assert_eq!(security_columns(Some("open")), ("none", "open"));
        assert_eq!(security_columns(None), ("none", "open"));
        assert_eq!(security_columns(Some("WPA-PSK")), ("wpa", "wpa"));
        assert_eq!(security_columns(Some("WPA-ENTERPRISE")), ("wpa", "wpa"));
        assert_eq!(security_columns(Some("WPA2-PSK")), ("wpa2", "wpa2"));
        assert_eq!(security_columns(Some("WPA2-ENTERPRISE")), ("wpa2", "wpa2"));
        assert_eq!(security_columns(Some("WPA3-SAE")), ("wpa2", "wpa2"));

        let access_point = AccessPoint::from_json(&json!({
            "bssid": "00:11:22:33:44:01",
            "security": "WPA2-PSK",
            "last_beacon_ms": 1_762_300_060_000i64,
        }));
        let fields = parse_csv(&format!("{}\n", row(&access_point, None, 1_762_300_060)));
        assert_eq!(fields[0][13], "wpa2");
        assert_eq!(fields[0][14], "wpa2");

        let open = AccessPoint::from_json(&json!({
            "bssid": "00:11:22:33:44:02",
            "security": "open",
            "last_beacon_ms": 1_762_300_060_000i64,
        }));
        let fields = parse_csv(&format!("{}\n", row(&open, None, 1_762_300_060)));
        assert_eq!(fields[0][13], "none");
        assert_eq!(fields[0][14], "open");
    }

    /// The fixed columns of a row: the radio, the beacon type, the claim
    /// and the country.
    #[test]
    fn the_fixed_columns_are_what_wigle_expects() {
        let access_point = AccessPoint::from_json(&ap_item());
        let fields = parse_csv(&format!(
            "{}\n",
            row(
                &access_point,
                Some(&Sighting::from_json(&sighted())),
                1_762_300_060,
            )
        ));
        let fields = &fields[0];

        assert_eq!(fields[1], "1762300060", "the export time");
        assert_eq!(fields[9], "wifi", "the radio");
        assert_eq!(fields[10], "", "there is no noise");
        assert_eq!(fields[11], "-51", "the signal in dBm");
        assert_eq!(fields[12], "beacon", "the beacon type");
        assert_eq!(fields[15], "1762300060", "the last time it was heard");
        assert_eq!(fields[16], "04-11-2025", "the day it was last heard");
        assert_eq!(fields[17], "false", "the row is not claimed");
        assert_eq!(fields[18], "", "the row is not claimed at a time");
        assert_eq!(fields[19], "", "the country is not known");
    }

    /// A hidden network has no name in the row.
    #[test]
    fn a_hidden_network_has_no_name() {
        let access_point = AccessPoint::from_json(&json!({
            "bssid": "00:11:22:33:44:03",
            "ssid": "example-ssid",
            "ssid_hidden": true,
            "last_beacon_ms": 1_762_300_060_000i64,
        }));
        let fields = parse_csv(&format!("{}\n", row(&access_point, None, 1_762_300_060)));
        assert_eq!(fields[0][5], "");
    }

    /// The export has a header and one row per access point.
    #[test]
    fn the_export_has_a_row_per_access_point() {
        let csv = export(
            &client(
                json!({ "items": [ap_item(), ap_item(), ap_item()] }),
                json!({ "items": [sighted()] }),
            ),
            1_762_300_060,
        )
        .expect("the export should succeed");

        let rows = parse_csv(&csv);
        assert_eq!(rows.len(), 4, "a header and three rows");
        assert_eq!(rows[0], parse_csv(&format!("{HEADER}\n"))[0]);
        for parsed in &rows {
            assert_eq!(parsed.len(), 20, "every row has twenty fields");
        }
    }

    /// Test 6: a daemon that cannot be reached is an error with a message,
    /// and not a panic.
    #[test]
    fn a_daemon_that_cannot_be_reached_is_an_error() {
        let client = QueryClient::new(
            std::path::PathBuf::from("/nonexistent/query.sock"),
            "t".into(),
        );
        let error = export(&client, 1_762_300_060).expect_err("the daemon is not there");
        assert!(!error.to_string().is_empty(), "the error says why");
    }

    /// A method the daemon does not have is an error too, and not a panic.
    #[test]
    fn a_method_the_daemon_does_not_have_is_an_error() {
        let client = QueryClient::scripted(vec![("aps.list", json!({ "items": [ap_item()] }))]);
        let error = export(&client, 1_762_300_060).expect_err("sightings.list is missing");
        assert!(!error.to_string().is_empty(), "the error says why");
    }

    /// The manifest of this plugin, as it is on disk.
    fn read_manifest() -> String {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../plugins/wigle-export/plugin.toml");
        std::fs::read_to_string(&path).unwrap_or_else(|error| {
            panic!("the manifest should be read: {}: {error}", path.display())
        })
    }

    /// The manifest asks for the two methods the export calls, and for
    /// nothing else.
    #[test]
    fn the_manifest_asks_for_the_methods_the_export_calls() {
        let manifest = read_manifest();

        assert!(manifest.contains("name = \"wigle-export\""), "the name");
        assert!(
            manifest.contains("exec = \"bin/wigle-export\""),
            "the binary"
        );
        assert!(manifest.contains("run = \"external\""), "it is run by hand");
        assert!(manifest.contains("network = false"), "it opens no sockets");

        let asked: Vec<&str> = manifest
            .split("\"query:")
            .skip(1)
            .filter_map(|rest| rest.split('"').next())
            .collect();
        assert_eq!(asked, vec!["aps.list", "sightings.list"]);
    }
}
