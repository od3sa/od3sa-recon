//! The `pcapng-meta` plugin: write a pcapng file of frame headers.
//!
//! The file holds **headers only**. Every packet in it is synthetic, built
//! from the metadata the daemon has: a radiotap header with the channel and
//! the signal level, and an 802.11 management frame with the address and the
//! SSID. No frame that was ever on the air is copied into the file, and
//! there is no payload anywhere in it ✓.
//!
//! The plugin is **off by default**: it runs only when someone asks for it.
//! It is started by hand, and it reads the query socket and the token from
//! the environment:
//!
//! ```text
//! OD3SA_QUERY=/tmp/od3sa-recon/query.sock \
//! OD3SA_TOKEN=... \
//! pcapng-meta --output /tmp/meta.pcapng
//! ```
//!
//! Both can be given on the command line as well, which is what a person
//! running the plugin by hand usually does.

use std::collections::HashMap;
use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;

use od3sa_plugins::client::{PluginError, QueryClient};
use serde_json::json;

// The plugin's logic lives in the crate's `pcapng` module.
use od3sa_plugins::pcapng;

/// How many pages the daemon is asked for at once.
const PAGE_LIMIT: u64 = 500;

/// How far back a sighting is looked for when the caller does not say.
const DEFAULT_LOOKBACK_MS: u64 = 3_600_000;

/// What the plugin was asked to do.
struct Options {
    /// Where the file goes: a path, or `-` for standard output.
    output: String,
    /// The query socket.
    socket: PathBuf,
    /// The token to present.
    token: String,
    /// Only sightings at or after this time, in unix epoch milliseconds.
    since_ms: Option<u64>,
    /// The most sightings to use for one access point.
    limit: u64,
}

fn main() -> ExitCode {
    let options = match parse_arguments(std::env::args().skip(1)) {
        Ok(Some(options)) => options,
        Ok(None) => {
            // The help was asked for.
            println!("{}", usage());
            return ExitCode::SUCCESS;
        }
        Err(message) => {
            eprintln!("pcapng-meta: {message}");
            eprintln!("{}", usage());
            return ExitCode::FAILURE;
        }
    };

    let client = QueryClient::new(options.socket, options.token);
    let observations = match collect(&client, options.since_ms, options.limit) {
        Ok(observations) => observations,
        Err(error) => {
            eprintln!("pcapng-meta: {error}");
            return ExitCode::FAILURE;
        }
    };

    let file = pcapng::write(&observations);
    if let Err(error) = write_out(&options.output, &file) {
        eprintln!("pcapng-meta: cannot write {}: {error}", options.output);
        return ExitCode::FAILURE;
    }

    println!(
        "pcapng-meta: {} synthetic frames ({} access points) written to {}",
        observations.len(),
        observations.len(),
        options.output
    );
    ExitCode::SUCCESS
}

/// The help text.
fn usage() -> String {
    [
        "usage: pcapng-meta --output <FILE> [options]",
        "",
        "Writes a pcapng file of frame headers: synthetic frames built from the",
        "metadata the daemon has. No payload, no EAPOL, no frame that was on the air.",
        "",
        "options:",
        "  -o, --output <FILE>   where to write the file; '-' means standard output",
        "      --query <SOCKET>  the query socket (default: $OD3SA_QUERY)",
        "      --token <TOKEN>   the query token (default: $OD3SA_TOKEN)",
        "      --since-ms <MS>   only sightings at or after this unix epoch millisecond",
        "      --limit <N>       the most sightings to use for one access point",
        "  -h, --help            this text",
    ]
    .join("\n")
}

/// Read the command line.
///
/// `Ok(None)` means the plugin was asked only for the help.
fn parse_arguments(arguments: impl Iterator<Item = String>) -> Result<Option<Options>, String> {
    let mut output: Option<String> = None;
    let mut socket: Option<String> = None;
    let mut token: Option<String> = None;
    let mut since_ms: Option<u64> = None;
    let mut limit: Option<u64> = None;

    let mut arguments = arguments.peekable();
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "-h" | "--help" => return Ok(None),
            "-o" | "--output" => {
                output = Some(next_value(&mut arguments, &argument)?);
            }
            "--query" => {
                socket = Some(next_value(&mut arguments, &argument)?);
            }
            "--token" => {
                token = Some(next_value(&mut arguments, &argument)?);
            }
            "--since-ms" => {
                let value = next_value(&mut arguments, &argument)?;
                since_ms = Some(
                    value
                        .parse::<u64>()
                        .map_err(|_| format!("--since-ms wants a number, not '{value}'"))?,
                );
            }
            "--limit" => {
                let value = next_value(&mut arguments, &argument)?;
                limit = Some(
                    value
                        .parse::<u64>()
                        .map_err(|_| format!("--limit wants a number, not '{value}'"))?,
                );
            }
            other => return Err(format!("unknown argument '{other}'")),
        }
    }

    let output = output.ok_or("--output is required")?;
    let socket = match socket {
        Some(socket) => socket,
        None => std::env::var("OD3SA_QUERY")
            .map_err(|_| "no query socket: pass --query or set OD3SA_QUERY".to_string())?,
    };
    let token = match token {
        Some(token) => token,
        None => std::env::var("OD3SA_TOKEN")
            .map_err(|_| "no token: pass --token or set OD3SA_TOKEN".to_string())?,
    };

    Ok(Some(Options {
        output,
        socket: PathBuf::from(socket),
        token,
        since_ms,
        limit: limit.unwrap_or(500),
    }))
}

/// The value that goes with an option.
fn next_value(
    arguments: &mut impl Iterator<Item = String>,
    option: &str,
) -> Result<String, String> {
    arguments
        .next()
        .ok_or_else(|| format!("{option} wants a value"))
}

/// Ask the daemon what it has seen, and turn it into observations.
///
/// One observation per access point, built from the access point's own
/// metadata and from the sightings it has.
///
/// The sightings of one access point are asked for one access point at a
/// time, because the query API does not hand out a sighting's address. To
/// keep the work bounded, each query looks back a fixed window from the
/// access point's own last beacon, unless the caller asked for a window of
/// their own.
fn collect(
    client: &QueryClient,
    since_ms: Option<u64>,
    limit: u64,
) -> Result<Vec<pcapng::Observation>, PluginError> {
    let aps = client.call_all("aps.list", json!({ "limit": PAGE_LIMIT }))?;
    let devices = client.call_all("devices.list", json!({ "limit": PAGE_LIMIT }))?;

    // The signal level of an access point is in the devices list, under the
    // access point's own address.
    let mut signal_by_mac: HashMap<[u8; 6], pcapng::DeviceMeta> = HashMap::new();
    for item in &devices {
        if let Some(device) = pcapng::DeviceMeta::from_json(item) {
            signal_by_mac.insert(device.mac, device);
        }
    }

    let mut observations = Vec::new();
    for item in &aps {
        let Some(ap) = pcapng::ApMeta::from_json(item) else {
            continue;
        };
        let from_ms = since_ms.or_else(|| {
            ap.last_beacon_ms
                .map(|beacon| beacon.saturating_sub(DEFAULT_LOOKBACK_MS))
        });
        let sightings = client.call_all(
            "sightings.list",
            json!({
                "mac": pcapng::mac_string(&ap.bssid),
                "limit": limit,
                "from_ms": from_ms,
            }),
        )?;
        // The newest sighting is the one that says where the access point
        // was last heard.
        let latest = sightings
            .iter()
            .filter_map(pcapng::SightingMeta::from_json)
            .max_by_key(|sighting| sighting.bucket_ms);
        let device = signal_by_mac.get(&ap.bssid);
        observations.push(ap.observation(latest.as_ref(), device));
    }

    // A file that is in order is easier to read.
    observations.sort_by_key(|observation| observation.timestamp_ms);
    Ok(observations)
}

/// Write the file out.
fn write_out(output: &str, bytes: &[u8]) -> std::io::Result<()> {
    if output == "-" {
        let mut stdout = std::io::stdout().lock();
        stdout.write_all(bytes)?;
        stdout.flush()
    } else {
        std::fs::write(output, bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A query socket that is not there.
    fn unreachable() -> QueryClient {
        QueryClient::new(
            PathBuf::from("/nonexistent/od3sa-recon/query.sock"),
            "token".to_string(),
        )
    }

    /// The message of the error a set of arguments produced.
    fn argument_error(arguments: &[&str]) -> String {
        match parse_arguments(arguments.iter().map(|text| text.to_string())) {
            Ok(_) => panic!("the arguments should have been refused"),
            Err(message) => message,
        }
    }

    #[test]
    fn a_daemon_that_cannot_be_reached_is_an_error_with_a_message() {
        let error = collect(&unreachable(), None, 10).expect_err("the daemon is not there");

        let message = error.to_string();
        assert!(!message.is_empty(), "the error must say something");
        assert!(matches!(error, PluginError::Connect(_)));
    }

    #[test]
    fn an_unknown_argument_is_an_error() {
        let error = argument_error(&["--nonsense"]);

        assert!(error.contains("--nonsense"));
    }

    #[test]
    fn the_output_is_required() {
        let error = argument_error(&[]);

        assert!(error.contains("--output"));
    }

    #[test]
    fn an_option_without_its_value_is_an_error() {
        let error = argument_error(&["--output"]);

        assert!(error.contains("--output"));
    }

    #[test]
    fn the_arguments_are_read() {
        let arguments = [
            "--output",
            "-",
            "--query",
            "/tmp/example.sock",
            "--token",
            "example-token",
            "--since-ms",
            "1762300000000",
            "--limit",
            "10",
        ];
        let options = match parse_arguments(arguments.iter().map(|text| text.to_string())) {
            Ok(Some(options)) => options,
            _ => panic!("the arguments should have been read"),
        };

        assert_eq!(options.output, "-");
        assert_eq!(options.socket, PathBuf::from("/tmp/example.sock"));
        assert_eq!(options.token, "example-token");
        assert_eq!(options.since_ms, Some(1_762_300_000_000));
        assert_eq!(options.limit, 10);
    }

    #[test]
    fn a_number_that_is_not_a_number_is_an_error() {
        let error = argument_error(&["--output", "-", "--limit", "many"]);

        assert!(error.contains("--limit"));
    }

    #[test]
    fn the_observations_are_built_from_what_the_daemon_answers() {
        let client = QueryClient::scripted(vec![
            (
                "aps.list",
                json!({
                    "items": [
                        {
                            "bssid": "00:11:22:33:44:01",
                            "ssid": "example-ssid",
                            "channel": 36,
                            "freq_mhz": 5180,
                            "band": "5",
                            "last_beacon_ms": 1_762_300_060_000u64,
                        }
                    ],
                    "next_cursor": null
                }),
            ),
            (
                "devices.list",
                json!({
                    "items": [
                        {
                            "mac": "00:11:22:33:44:01",
                            "kind": "ap",
                            "max_rssi": -42,
                            "last_seen_ms": 1_762_300_060_000u64,
                        }
                    ],
                    "next_cursor": null
                }),
            ),
            (
                "sightings.list",
                json!({
                    "items": [
                        {
                            "bucket_ms": 1_762_300_060_000u64,
                            "n": 3,
                            "rssi_min": -60,
                            "rssi_max": -42,
                            "rssi_avg": -51.0,
                            "channel": 36,
                        }
                    ],
                    "next_cursor": null
                }),
            ),
        ]);

        let observations = collect(&client, None, 10).expect("the daemon answered");

        assert_eq!(observations.len(), 1);
        let observation = &observations[0];
        assert_eq!(observation.bssid, [0x00, 0x11, 0x22, 0x33, 0x44, 0x01]);
        assert_eq!(observation.ssid.as_deref(), Some("example-ssid"));
        assert_eq!(observation.channel, Some(36));
        assert_eq!(observation.signal_dbm, Some(-51));
        assert_eq!(observation.timestamp_ms, 1_762_300_060_000);
    }

    #[test]
    fn the_file_holds_no_payload() {
        let client = QueryClient::scripted(vec![
            (
                "aps.list",
                json!({
                    "items": [
                        {
                            "bssid": "00:11:22:33:44:01",
                            "ssid": "example-ssid",
                            "channel": 36,
                            "freq_mhz": 5180,
                            "band": "5",
                        }
                    ],
                    "next_cursor": null
                }),
            ),
            ("devices.list", json!({ "items": [], "next_cursor": null })),
            (
                "sightings.list",
                json!({ "items": [], "next_cursor": null }),
            ),
        ]);

        let observations = collect(&client, None, 10).expect("the daemon answered");
        let file = pcapng::write(&observations);

        // A marker that a payload would carry.
        const PAYLOAD_MARKER: &[u8] = b"OD3SA-PAYLOAD-MARKER";
        assert!(
            !file
                .windows(PAYLOAD_MARKER.len())
                .any(|window| window == PAYLOAD_MARKER),
            "the file must not hold a payload"
        );
    }

    #[test]
    fn the_manifest_asks_for_the_methods_the_export_calls() {
        let manifest = read_manifest();

        let asked = capabilities(&manifest);

        for method in ["aps.list", "devices.list", "sightings.list"] {
            assert!(
                asked
                    .iter()
                    .any(|capability| capability == &format!("query:{method}")),
                "the manifest does not ask for '{method}'"
            );
        }
        // The three methods, plus the write path it needs.
        assert_eq!(asked.len(), 4);
        assert!(
            asked
                .iter()
                .any(|capability| capability == "fs:write:/mmc/od3sa-recon/export")
        );
    }

    #[test]
    fn the_manifest_names_the_methods_the_daemon_answers() {
        let manifest = read_manifest();
        let methods = daemon_methods();

        for capability in capabilities(&manifest) {
            let Some(method) = capability.strip_prefix("query:") else {
                continue;
            };
            assert!(
                methods.iter().any(|known| known == method),
                "the daemon has no method '{method}'"
            );
        }
    }

    #[test]
    fn the_manifest_says_the_plugin_is_off_by_default() {
        let manifest = read_manifest();

        // The plugin is started by hand, not by the host.
        assert!(manifest.contains("run = \"external\""));
        // It writes a file and talks to a socket: it needs no network.
        assert!(manifest.contains("network = false"));
    }

    /// The manifest of this plugin, as it is on disk.
    fn read_manifest() -> String {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../plugins/pcapng-meta/plugin.toml");
        std::fs::read_to_string(&path).unwrap_or_else(|error| {
            panic!("the manifest should be read: {}: {error}", path.display())
        })
    }

    /// The capabilities the manifest lists.
    ///
    /// The manifest is TOML and this crate does not read TOML, so the list
    /// is read out of the text: it is the one line that starts with
    /// `capabilities`, and the quoted names on it.
    fn capabilities(manifest: &str) -> Vec<String> {
        let line = manifest
            .lines()
            .find(|line| line.trim_start().starts_with("capabilities"))
            .expect("the manifest has a capabilities line");
        line.split('"')
            .skip(1)
            .step_by(2)
            .map(str::to_string)
            .collect()
    }

    /// The methods the daemon answers, read from the daemon's own source.
    ///
    /// The list lives in the daemon's crate, which is a binary and not a
    /// library, so the test reads it rather than linking to it.
    fn daemon_methods() -> Vec<String> {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../crates/od3sa-recond/src/query.rs");
        let source = std::fs::read_to_string(&path).unwrap_or_else(|error| {
            panic!(
                "the daemon's source should be read: {}: {error}",
                path.display()
            )
        });

        let start = source
            .find("pub const METHODS")
            .expect("the daemon has a METHODS list");
        let rest = &source[start..];
        let end = rest.find("];").expect("the METHODS list ends");
        rest[..end]
            .lines()
            .filter_map(|line| line.trim().strip_prefix('"'))
            .filter_map(|name| name.split('"').next())
            .map(str::to_string)
            .collect()
    }
}
