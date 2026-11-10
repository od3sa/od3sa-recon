//! The `kismet-feed` plugin: the access points the daemon has seen, written
//! as Kismet **netspot** files.
//!
//! # Why the netspot file path
//!
//! The task offered two ways to feed a Kismet server, and this is the one
//! that fits the project:
//!
//! - A Kismet **external datasource** means writing a Kismet plugin in C
//!   against Kismet's own headers. That is a build dependency on Kismet's
//!   source, on a machine that deliberately does not run Kismet: the
//!   project pivoted away from Kismet because it does not fit in the 104 MB
//!   of RAM the Pager has.
//! - Kismet's **scan-report API** is a *read* API. It reports what Kismet
//!   saw; it does not accept observations, so there is nothing to post to.
//! - Kismet's **netspot** JSON is how observations get *into* Kismet. It is
//!   a directory Kismet watches for `.json` files that describe networks.
//!   It needs no Kismet build, no plugin and no running Kismet to write.
//!
//! So this plugin writes netspot files into a directory, and a Kismet that
//! watches that directory picks them up.
//!
//! # What is written
//!
//! One file per access point, named after the access point's BSSID, so the
//! same network is never written twice under two names. The file is written
//! again every time the access point is seen: Kismet reads the file, and a
//! file that changes is a new observation, so a later sighting with a
//! different signal level replaces the older one.
//!
//! Every file is written under a temporary name and renamed into place, so
//! a Kismet watching the directory never reads half a file.
//!
//! The values come from the daemon's `aps.list`, and the signal level from
//! the access point's sightings. Nothing else: no payload, no key
//! material, and nothing that touches a radio.

use std::fmt;
use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use crate::client::{PluginError, QueryClient};
use serde_json::{Value, json};

/// Why the feed stopped.
#[derive(Debug)]
pub enum FeedError {
    /// The daemon could not be reached, or refused the request.
    Query(PluginError),
    /// A file could not be written.
    Io(std::io::Error),
    /// The daemon's answer did not make sense.
    Record(String),
}

impl fmt::Display for FeedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Query(error) => write!(f, "{error}"),
            Self::Io(error) => write!(f, "cannot write the netspot file: {error}"),
            Self::Record(reason) => write!(f, "the daemon's answer made no sense: {reason}"),
        }
    }
}

impl std::error::Error for FeedError {}

impl From<PluginError> for FeedError {
    fn from(error: PluginError) -> FeedError {
        FeedError::Query(error)
    }
}

impl From<std::io::Error> for FeedError {
    fn from(error: std::io::Error) -> FeedError {
        FeedError::Io(error)
    }
}

/// The name of the file an access point's netspot record lives in.
///
/// The name is the access point's BSSID, so that the same network always
/// lands in the same file, and so that a reader can tell which file belongs
/// to which access point.
pub fn netspot_file_name(bssid: &str) -> String {
    format!("{bssid}.json")
}

/// The name of the temporary file a netspot record is written to.
///
/// It is hidden and it does not end in `.json`, so a Kismet watching the
/// directory for netspot files does not pick it up.
fn netspot_temp_name(bssid: &str) -> String {
    format!(".netspot-{bssid}.tmp")
}

/// The netspot record for one access point.
///
/// The keys are the ones Kismet reads: `essid` and `ssid` are the network
/// name, `channel` and `frequency` say where it is, `signal` is the signal
/// level in dBm, `type` says it is an access point, `radio` says it is
/// Wi-Fi, `key` is the name of an encryption key (there is none here, so
/// it is empty), and `fakearrays` carries the signal level as the one
/// antenna reading Kismet expects.
pub fn netspot_record(access_point: &Value, signal: i64) -> Value {
    let ssid = access_point
        .get("ssid")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let bssid = access_point
        .get("bssid")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let channel = access_point
        .get("channel")
        .and_then(Value::as_i64)
        .unwrap_or_default();
    let frequency = access_point
        .get("freq_mhz")
        .and_then(Value::as_i64)
        .unwrap_or_default();

    json!({
        "essid": ssid,
        "bssid": bssid,
        "ssid": ssid,
        "channel": channel,
        "frequency": frequency,
        "signal": signal,
        "type": "ap",
        "radio": "wifi",
        "key": "",
        "fakearrays": [[signal]],
    })
}

/// The signal level of the most recent sighting in a list of sightings.
///
/// The list is the answer to `sightings.list`. The newest sighting wins;
/// its average signal level is used, and the strongest reading it recorded
/// is used if it has no average.
pub fn signal_from_sightings(sightings: &[Value]) -> Option<i64> {
    let newest = sightings.iter().max_by_key(|sighting| {
        sighting
            .get("bucket_ms")
            .and_then(Value::as_u64)
            .unwrap_or(0)
    })?;

    if let Some(average) = newest.get("rssi_avg").and_then(Value::as_f64) {
        return Some(average.round() as i64);
    }
    if let Some(strongest) = newest.get("rssi_max").and_then(Value::as_i64) {
        return Some(strongest);
    }
    newest.get("rssi_min").and_then(Value::as_i64)
}

/// Write the body of a netspot record under a temporary name.
///
/// The file is created and filled here; it is not yet the file Kismet
/// reads. This is the first half of the atomic write.
fn write_record(directory: &Path, temp_name: &str, body: &str) -> Result<PathBuf, FeedError> {
    let temp_path = directory.join(temp_name);
    {
        let mut file = fs::File::create(&temp_path)?;
        file.write_all(body.as_bytes())?;
        // The bytes are on the card before the rename, so a reader that
        // sees the file sees the whole of it.
        file.sync_all()?;
    }
    Ok(temp_path)
}

/// Rename a temporary netspot file into the name Kismet reads.
///
/// This is the second half of the atomic write: before it, the file is
/// under a name Kismet ignores; after it, the file is complete.
fn commit_record(
    directory: &Path,
    temp_path: &Path,
    final_name: &str,
) -> Result<PathBuf, FeedError> {
    let final_path = directory.join(final_name);
    fs::rename(temp_path, &final_path)?;
    Ok(final_path)
}

/// Write one netspot file, atomically.
///
/// This is the whole write in one call: write under a temporary name, then
/// rename it into place.
pub fn write_netspot_file(
    directory: &Path,
    access_point: &Value,
    signal: i64,
) -> Result<PathBuf, FeedError> {
    let bssid = access_point
        .get("bssid")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if bssid.is_empty() {
        return Err(FeedError::Record(
            "an access point has no BSSID".to_string(),
        ));
    }

    let record = netspot_record(access_point, signal);
    let body = serde_json::to_string_pretty(&record)
        .map_err(|error| FeedError::Record(error.to_string()))?;

    let final_name = netspot_file_name(bssid);
    let temp_name = netspot_temp_name(bssid);
    let temp_path = write_record(directory, &temp_name, &body)?;
    commit_record(directory, &temp_path, &final_name)
}

/// The signal level of an access point, from the daemon's sightings.
fn signal_for(client: &QueryClient, bssid: &str) -> Result<i64, FeedError> {
    let sightings = client.call_all("sightings.list", json!({"mac": bssid}))?;
    // No sighting yet means no signal level; zero says "not known", which
    // is what Kismet shows for a network it has never heard a frame from.
    Ok(signal_from_sightings(&sightings).unwrap_or(0))
}

/// Write a netspot file for every access point the daemon knows about.
///
/// Each access point gets one file, named after its BSSID, holding the
/// access point's details and its most recent signal level. The paths of
/// the files that were written are returned, in the order they were
/// written.
pub fn feed(client: &QueryClient, directory: &Path) -> Result<Vec<PathBuf>, FeedError> {
    let access_points = client.call_all("aps.list", json!({}))?;

    let mut written = Vec::with_capacity(access_points.len());
    for access_point in &access_points {
        let Some(bssid) = access_point.get("bssid").and_then(Value::as_str) else {
            continue;
        };
        if bssid.is_empty() {
            continue;
        }
        let signal = signal_for(client, bssid)?;
        written.push(write_netspot_file(directory, access_point, signal)?);
    }
    Ok(written)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    /// A temporary directory of our own, so two tests do not share one.
    fn scratch(name: &str) -> PathBuf {
        let directory = std::env::temp_dir().join(format!("od3sa-kismet-{name}"));
        let _ = fs::remove_dir_all(&directory);
        fs::create_dir_all(&directory).expect("the scratch directory should be made");
        directory
    }

    /// One access point, as `aps.list` describes it.
    fn access_point() -> Value {
        json!({
            "bssid": "00:11:22:33:44:01",
            "ssid": "example-ssid",
            "ssid_hidden": false,
            "channel": 36,
            "freq_mhz": 5180,
            "band": "5",
            "security": "WPA2-PSK",
        })
    }

    /// One sighting, as `sightings.list` describes it.
    fn sighting(bucket_ms: u64, average: f64, strongest: i64) -> Value {
        json!({
            "device_id": 1,
            "source_id": 1,
            "bucket_ms": bucket_ms,
            "n": 3,
            "rssi_min": -70,
            "rssi_max": strongest,
            "rssi_avg": average,
            "channel": 36,
        })
    }

    #[test]
    fn a_netspot_file_is_written_for_an_access_point() {
        let directory = scratch("write");
        let client = QueryClient::scripted(vec![
            (
                "aps.list",
                json!({"items": [access_point()], "next_cursor": null}),
            ),
            (
                "sightings.list",
                json!({"items": [sighting(1762300000000, -51.0, -42)], "next_cursor": null}),
            ),
        ]);

        let written = feed(&client, &directory).expect("the feed should write");
        assert_eq!(written.len(), 1);

        let path = &written[0];
        assert_eq!(path.file_name().unwrap(), "00:11:22:33:44:01.json");

        let text = fs::read_to_string(path).expect("the file should be readable");
        let record: Value = serde_json::from_str(&text).expect("the file should be JSON");

        // The keys Kismet reads.
        assert_eq!(record["essid"], json!("example-ssid"));
        assert_eq!(record["ssid"], json!("example-ssid"));
        assert_eq!(record["bssid"], json!("00:11:22:33:44:01"));
        assert_eq!(record["channel"], json!(36));
        assert_eq!(record["frequency"], json!(5180));
        assert_eq!(record["signal"], json!(-51));
        assert_eq!(record["type"], json!("ap"));
        assert_eq!(record["radio"], json!("wifi"));
        assert_eq!(record["key"], json!(""));
        assert!(record["fakearrays"].is_array());

        let _ = fs::remove_dir_all(&directory);
    }

    #[test]
    fn the_same_access_point_seen_again_is_written_again() {
        let directory = scratch("seen-again");
        let path = write_netspot_file(&directory, &access_point(), -60).expect("the first write");
        assert_eq!(path.file_name().unwrap(), "00:11:22:33:44:01.json");

        // The access point is seen again, with a better signal.
        let path = write_netspot_file(&directory, &access_point(), -42).expect("the second write");
        assert_eq!(path.file_name().unwrap(), "00:11:22:33:44:01.json");

        // The same file, with the newer signal in it.
        let text = fs::read_to_string(&path).expect("the file should be readable");
        let record: Value = serde_json::from_str(&text).expect("the file should be JSON");
        assert_eq!(record["signal"], json!(-42));
        assert_eq!(record["bssid"], json!("00:11:22:33:44:01"));

        // And only one file for that access point.
        let names: Vec<String> = fs::read_dir(&directory)
            .expect("the directory should be readable")
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, vec!["00:11:22:33:44:01.json".to_string()]);

        let _ = fs::remove_dir_all(&directory);
    }

    #[test]
    fn a_second_pass_over_the_same_access_point_rewrites_the_file() {
        let directory = scratch("second-pass");

        // The first pass: the access point is seen with a weak signal.
        let first = QueryClient::scripted(vec![
            (
                "aps.list",
                json!({"items": [access_point()], "next_cursor": null}),
            ),
            (
                "sightings.list",
                json!({"items": [sighting(1762300000000, -70.0, -66)], "next_cursor": null}),
            ),
        ]);
        feed(&first, &directory).expect("the first feed should write");
        let text = fs::read_to_string(directory.join("00:11:22:33:44:01.json"))
            .expect("the file should be readable");
        let record: Value = serde_json::from_str(&text).expect("the file should be JSON");
        assert_eq!(record["signal"], json!(-70));

        // The second pass: the same access point, seen again with a better
        // signal. The file is written again, with the newer signal.
        let second = QueryClient::scripted(vec![
            (
                "aps.list",
                json!({"items": [access_point()], "next_cursor": null}),
            ),
            (
                "sightings.list",
                json!({"items": [sighting(1762300060000, -42.0, -38)], "next_cursor": null}),
            ),
        ]);
        feed(&second, &directory).expect("the second feed should write");
        let text = fs::read_to_string(directory.join("00:11:22:33:44:01.json"))
            .expect("the file should be readable");
        let record: Value = serde_json::from_str(&text).expect("the file should be JSON");
        assert_eq!(record["signal"], json!(-42));

        // Still one file for that access point.
        let names: Vec<String> = fs::read_dir(&directory)
            .expect("the directory should be readable")
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, vec!["00:11:22:33:44:01.json".to_string()]);

        let _ = fs::remove_dir_all(&directory);
    }

    #[test]
    fn a_reader_playing_kismet_picks_the_file_up() {
        let directory = scratch("reader");
        let client = QueryClient::scripted(vec![
            (
                "aps.list",
                json!({"items": [access_point()], "next_cursor": null}),
            ),
            (
                "sightings.list",
                json!({"items": [sighting(1762300000000, -51.0, -42)], "next_cursor": null}),
            ),
        ]);
        feed(&client, &directory).expect("the feed should write");

        // A reader that plays the part of Kismet: it reads the directory,
        // parses the JSON, and looks for the network.
        let mut found: Option<Value> = None;
        for entry in fs::read_dir(&directory).expect("the directory should be readable") {
            let entry = entry.expect("the entry should be readable");
            let path = entry.path();
            if path.extension().and_then(|extension| extension.to_str()) != Some("json") {
                continue;
            }
            let text = fs::read_to_string(&path).expect("the file should be readable");
            let record: Value = serde_json::from_str(&text).expect("the file should be JSON");
            if record["bssid"] == json!("00:11:22:33:44:01") {
                found = Some(record);
            }
        }

        let record = found.expect("the reader should have found the network");
        assert_eq!(record["essid"], json!("example-ssid"));
        assert_eq!(record["type"], json!("ap"));

        let _ = fs::remove_dir_all(&directory);
    }

    #[test]
    fn no_half_written_file_is_ever_visible() {
        let directory = scratch("atomic");

        // The first half of the write leaves the file under a name Kismet
        // ignores: the name Kismet reads does not exist yet.
        let final_name = netspot_file_name("00:11:22:33:44:01");
        let temp_name = netspot_temp_name("00:11:22:33:44:01");
        let body = serde_json::to_string_pretty(&netspot_record(&access_point(), -51))
            .expect("the record should serialise");
        let temp_path = write_record(&directory, &temp_name, &body).expect("the write should work");

        assert!(!directory.join(&final_name).exists());
        assert!(temp_path.exists());
        // The temporary file is not one Kismet would read.
        assert_ne!(temp_path.file_name().unwrap(), final_name.as_str());

        // The second half renames it into place.
        let path =
            commit_record(&directory, &temp_path, &final_name).expect("the rename should work");
        assert_eq!(path.file_name().unwrap(), "00:11:22:33:44:01.json");
        assert!(!temp_path.exists());

        // And while the file is written over and over, a reader that only
        // ever looks at the final name never sees half a file.
        let stop = Arc::new(AtomicBool::new(false));
        let reader_stop = Arc::clone(&stop);
        let reader_directory = directory.clone();
        let reader = std::thread::spawn(move || {
            while !reader_stop.load(Ordering::Relaxed) {
                let path = reader_directory.join(&final_name);
                if path.exists() {
                    let text = fs::read_to_string(&path).expect("the file should be readable");
                    let record: Value =
                        serde_json::from_str(&text).expect("the file should always be whole JSON");
                    assert_eq!(record["bssid"], json!("00:11:22:33:44:01"));
                }
            }
        });

        for signal in -80..-40 {
            write_netspot_file(&directory, &access_point(), signal).expect("the write should work");
        }
        stop.store(true, Ordering::Relaxed);
        reader.join().expect("the reader should finish");

        // Nothing but the one file is left behind.
        let names: Vec<String> = fs::read_dir(&directory)
            .expect("the directory should be readable")
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, vec!["00:11:22:33:44:01.json".to_string()]);

        let _ = fs::remove_dir_all(&directory);
    }

    #[test]
    fn a_daemon_that_cannot_be_reached_is_an_error() {
        let directory = scratch("unreachable");
        // A socket that is not there: the client cannot connect.
        let client = QueryClient::new(
            PathBuf::from("/nonexistent/od3sa-recon/query.sock"),
            "token".to_string(),
        );

        let error = feed(&client, &directory).expect_err("the feed should fail");
        let message = error.to_string();
        assert!(!message.is_empty());
        assert!(
            message.contains("cannot reach the daemon"),
            "the message should say what went wrong: {message}"
        );

        let _ = fs::remove_dir_all(&directory);
    }

    #[test]
    fn the_signal_comes_from_the_newest_sighting() {
        let sightings = vec![
            sighting(1762300000000, -70.0, -60),
            sighting(1762300060000, -51.0, -42),
            sighting(1762300030000, -80.0, -75),
        ];
        assert_eq!(signal_from_sightings(&sightings), Some(-51));
        assert_eq!(signal_from_sightings(&[]), None);
    }
}
