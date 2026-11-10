//! The `ndjson-export` plugin: what the daemon has seen, one JSON object
//! per line.
//!
//! The export reads the daemon through the read-only query socket and
//! writes **NDJSON**: one JSON object per line, so a consumer can read the
//! file a line at a time without holding it all in memory.
//!
//! Two things matter here, and both are about the device this runs on:
//!
//! - **The output is written as it goes.** The daemon pages its answers, and
//!   a busy device may have seen a lot. The export writes each page's
//!   objects to the file and asks for the next page, so the memory the
//!   export needs is one page, not the whole database.
//! - **The objects are the daemon's own.** The export does not rename a
//!   field, does not round a number and does not drop a null: what lands in
//!   the file is what the daemon sent, so the shapes are the ones in
//!   `docs/QUERY-API.md`.
//!
//! The export never writes to a radio and never writes to the database. It
//! only reads, and it only writes the file it was asked for.

use std::io::Write;
use std::path::Path;

use serde_json::{Value, json};

use crate::client::{PluginError, QueryClient};

/// How many objects the export asks for in one page.
///
/// The daemon's own limit is 500, so this is the largest page it will give.
const PAGE_LIMIT: usize = 500;

/// What can be exported.
///
/// Every kind is one read-only query method. There is no kind here that
/// touches a radio, a channel or a service.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// The devices the daemon has seen, access points and clients alike.
    Devices,
    /// The access points the daemon has seen.
    Aps,
    /// The client links the daemon has seen.
    Clients,
    /// The sightings the daemon has seen.
    Sightings,
    /// The alerts the daemon has raised.
    Alerts,
}

impl Kind {
    /// Every kind, in the order the export writes them.
    pub const ALL: [Kind; 5] = [
        Kind::Devices,
        Kind::Aps,
        Kind::Clients,
        Kind::Sightings,
        Kind::Alerts,
    ];

    /// The query method that answers for this kind.
    pub fn method(self) -> &'static str {
        match self {
            Self::Devices => "devices.list",
            Self::Aps => "aps.list",
            Self::Clients => "clients.list",
            Self::Sightings => "sightings.list",
            Self::Alerts => "alerts.list",
        }
    }

    /// The name the command line and the file names use.
    pub fn name(self) -> &'static str {
        match self {
            Self::Devices => "devices",
            Self::Aps => "aps",
            Self::Clients => "clients",
            Self::Sightings => "sightings",
            Self::Alerts => "alerts",
        }
    }

    /// Read a kind out of its name.
    ///
    /// Returns `None` for a name that is not a kind. The command line says
    /// so rather than guessing.
    pub fn parse(name: &str) -> Option<Kind> {
        match name.trim() {
            "devices" => Some(Self::Devices),
            "aps" => Some(Self::Aps),
            "clients" => Some(Self::Clients),
            "sightings" => Some(Self::Sightings),
            "alerts" => Some(Self::Alerts),
            _ => None,
        }
    }
}

/// The kinds a name stands for.
///
/// `all` stands for every kind, and a name may hold several kinds separated
/// by commas. `None` is for a name that is not a kind.
pub fn kinds_named(name: &str) -> Option<Vec<Kind>> {
    let trimmed = name.trim();
    if trimmed == "all" {
        return Some(Kind::ALL.to_vec());
    }
    let mut kinds = Vec::new();
    for part in trimmed.split(',') {
        kinds.push(Kind::parse(part)?);
    }
    if kinds.is_empty() {
        return None;
    }
    Some(kinds)
}

/// The names the kinds go by, for a message that says what is allowed.
pub fn kind_names() -> String {
    Kind::ALL
        .iter()
        .map(|kind| kind.name())
        .collect::<Vec<&str>>()
        .join(", ")
}

/// Why an export stopped.
#[derive(Debug)]
pub enum ExportError {
    /// The daemon could not be reached, or refused.
    Query(PluginError),
    /// The object could not be turned into JSON.
    Encode(serde_json::Error),
    /// The output could not be written.
    Write(std::io::Error),
}

impl std::fmt::Display for ExportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Query(error) => write!(f, "{error}"),
            Self::Encode(error) => write!(f, "cannot write the object as JSON: {error}"),
            Self::Write(error) => write!(f, "cannot write the export: {error}"),
        }
    }
}

impl std::error::Error for ExportError {}

impl From<PluginError> for ExportError {
    fn from(error: PluginError) -> Self {
        Self::Query(error)
    }
}

impl From<serde_json::Error> for ExportError {
    fn from(error: serde_json::Error) -> Self {
        Self::Encode(error)
    }
}

impl From<std::io::Error> for ExportError {
    fn from(error: std::io::Error) -> Self {
        Self::Write(error)
    }
}

/// Write one kind of what the daemon has seen, one JSON object per line.
///
/// The daemon's pages are written as they arrive: the export asks for one
/// page, writes it, asks for the next, and so on. Nothing is collected
/// first, so the export needs the memory of one page and no more.
///
/// The objects are the daemon's own, unchanged. A `null` stays a `null` and
/// a string stays a string, so the shapes in the file are the shapes in
/// `docs/QUERY-API.md`.
///
/// # Errors
///
/// Returns an error when the daemon cannot be reached or refuses, when an
/// object cannot be written as JSON, and when the output cannot be written.
/// What was written before the error stays written.
pub fn export_kind<W: Write>(
    client: &QueryClient,
    kind: Kind,
    out: &mut W,
) -> Result<u64, ExportError> {
    let mut params = json!({"limit": PAGE_LIMIT});
    let mut written: u64 = 0;
    let mut cursor: Option<String> = None;

    loop {
        let page = client.call(kind.method(), params.clone())?;

        if let Some(items) = page.get("items").and_then(Value::as_array) {
            for item in items {
                // One write per line, so a line is whole or it is not there
                // at all.
                let mut line = serde_json::to_string(item)?;
                line.push('\n');
                out.write_all(line.as_bytes())?;
                written += 1;
            }
        }

        // The page is on disk before the next one is asked for.
        out.flush()?;

        let next = page
            .get("next_cursor")
            .and_then(Value::as_str)
            .filter(|cursor| !cursor.is_empty())
            .map(str::to_string);

        match next {
            // A cursor that is the one we just sent means the daemon is not
            // moving on. Stop rather than ask for the same page for ever.
            Some(next) if Some(&next) != cursor.as_ref() => {
                params["cursor"] = Value::String(next.clone());
                cursor = Some(next);
            }
            _ => return Ok(written),
        }
    }
}

/// What an export wrote.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Report {
    /// The objects written, per kind.
    pub objects: Vec<(Kind, u64)>,
}

impl Report {
    /// The total number of objects written.
    pub fn total(&self) -> u64 {
        self.objects.iter().map(|(_, count)| count).sum()
    }
}

/// Write the kinds to a path.
///
/// One kind goes to the file at `path`. More than one kind goes to a
/// directory at `path`, one file per kind, so that a file holds one shape
/// and a consumer never has to guess what a line is.
///
/// # Errors
///
/// Returns an error when the daemon cannot be reached or refuses, when the
/// directory cannot be made, and when the output cannot be written.
pub fn export_to_path(
    client: &QueryClient,
    kinds: &[Kind],
    path: &Path,
) -> Result<Report, ExportError> {
    let mut report = Report::default();

    if kinds.len() == 1 {
        let kind = kinds[0];
        let count = write_one(client, kind, path)?;
        report.objects.push((kind, count));
        return Ok(report);
    }

    std::fs::create_dir_all(path)?;

    for kind in kinds {
        let file = path.join(format!("{}.ndjson", kind.name()));
        let count = write_one(client, *kind, &file)?;
        report.objects.push((*kind, count));
    }

    Ok(report)
}

/// Write one kind to one file.
fn write_one(client: &QueryClient, kind: Kind, path: &Path) -> Result<u64, ExportError> {
    let file = std::fs::File::create(path)?;
    let mut out = std::io::BufWriter::new(file);
    let count = export_kind(client, kind, &mut out)?;
    out.flush()?;
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// A device, as the daemon would send it.
    fn device() -> Value {
        json!({
            "mac": "00:11:22:33:44:01",
            "kind": "ap",
            "oui": "00:11:22",
            "randomized": false,
            "first_seen_ms": 1762300000000i64,
            "last_seen_ms": 1762300060000i64,
            "max_rssi": -42,
            "last_rssi": -55,
        })
    }

    /// A writer that fails after a given number of bytes, and keeps what
    /// it was given.
    struct FailingWriter {
        written: Vec<u8>,
        limit: usize,
    }

    impl FailingWriter {
        fn new(limit: usize) -> FailingWriter {
            FailingWriter {
                written: Vec::new(),
                limit,
            }
        }
    }

    impl Write for FailingWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            if self.written.len() >= self.limit {
                return Err(std::io::Error::other("the disk is full"));
            }
            let room = self.limit - self.written.len();
            let taken = room.min(buf.len());
            self.written.extend_from_slice(&buf[..taken]);
            Ok(taken)
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn a_kind_names_its_method() {
        assert_eq!(Kind::Devices.method(), "devices.list");
        assert_eq!(Kind::Aps.method(), "aps.list");
        assert_eq!(Kind::Clients.method(), "clients.list");
        assert_eq!(Kind::Sightings.method(), "sightings.list");
        assert_eq!(Kind::Alerts.method(), "alerts.list");
    }

    #[test]
    fn a_kind_is_read_out_of_its_name() {
        assert_eq!(Kind::parse("devices"), Some(Kind::Devices));
        assert_eq!(Kind::parse(" alerts "), Some(Kind::Alerts));
        assert_eq!(Kind::parse("probes"), None);
        assert_eq!(Kind::parse(""), None);
    }

    #[test]
    fn all_stands_for_every_kind() {
        assert_eq!(kinds_named("all"), Some(Kind::ALL.to_vec()));
        assert_eq!(kinds_named("aps"), Some(vec![Kind::Aps]));
        assert_eq!(kinds_named("nothing"), None);
    }

    #[test]
    fn the_export_writes_one_object_per_line() {
        let client = QueryClient::scripted(vec![(
            "devices.list",
            json!({"items": [device(), device()], "next_cursor": null}),
        )]);

        let mut out: Vec<u8> = Vec::new();
        let written =
            export_kind(&client, Kind::Devices, &mut out).expect("the export should work");

        assert_eq!(written, 2);
        let text = String::from_utf8(out).expect("the export is text");
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2);
        for line in lines {
            let object: Value = serde_json::from_str(line).expect("each line is one JSON object");
            assert!(object.is_object());
        }
    }

    #[test]
    fn the_lines_carry_the_fields_the_daemon_sent() {
        let client = QueryClient::scripted(vec![(
            "aps.list",
            json!({"items": [{
                "bssid": "00:11:22:33:44:01",
                "ssid": "example-ssid",
                "channel": 36,
                "freq_mhz": 5180,
                "band": "5",
                "security": "WPA2-PSK",
                "pmf_required": false,
            }]}),
        )]);

        let mut out: Vec<u8> = Vec::new();
        export_kind(&client, Kind::Aps, &mut out).expect("the export should work");

        let text = String::from_utf8(out).expect("the export is text");
        let object: Value = serde_json::from_str(text.trim()).expect("the line is JSON");

        // The daemon's own fields, with the daemon's own values.
        assert_eq!(object["bssid"], json!("00:11:22:33:44:01"));
        assert_eq!(object["ssid"], json!("example-ssid"));
        assert_eq!(object["channel"], json!(36));
        assert_eq!(object["band"], json!("5"));
        assert_eq!(object["security"], json!("WPA2-PSK"));
        assert_eq!(object["pmf_required"], json!(false));
        // A field the daemon did not send is not invented.
        assert!(object.get("max_rssi").is_none());
    }

    #[test]
    fn a_null_stays_a_null() {
        let client = QueryClient::scripted(vec![(
            "sightings.list",
            json!({"items": [{
                "device_id": 1,
                "bucket_ms": 1762300060000i64,
                "n": 3,
                "rssi_min": -60,
                "rssi_max": -42,
                "rssi_avg": -51.0,
                "channel": 36,
                "lat": null,
                "lon": null,
            }]}),
        )]);

        let mut out: Vec<u8> = Vec::new();
        export_kind(&client, Kind::Sightings, &mut out).expect("the export should work");

        let text = String::from_utf8(out).expect("the export is text");
        let object: Value = serde_json::from_str(text.trim()).expect("the line is JSON");
        assert!(object["lat"].is_null());
        assert!(object["lon"].is_null());
    }

    #[test]
    fn what_was_written_stays_written_when_the_writer_fails() {
        let client = QueryClient::scripted(vec![(
            "alerts.list",
            json!({"items": [
                {"id": 1, "ts_ms": 1762300060000i64, "rule": "new_device", "severity": "info"},
                {"id": 2, "ts_ms": 1762300070000i64, "rule": "new_ap", "severity": "notice"},
            ]}),
        )]);

        // Room for the first line and a bit of the second.
        let first = serde_json::to_string(&json!({
            "id": 1,
            "ts_ms": 1762300060000i64,
            "rule": "new_device",
            "severity": "info",
        }))
        .expect("the object is JSON");
        let mut out = FailingWriter::new(first.len() + 1);

        let error =
            export_kind(&client, Kind::Alerts, &mut out).expect_err("the writer should fail");

        assert!(matches!(error, ExportError::Write(_)));
        // The first line is there, in full.
        let text = String::from_utf8(out.written).expect("the export is text");
        let lines: Vec<&str> = text.lines().collect();
        assert!(!lines.is_empty());
        let first_line: Value = serde_json::from_str(lines[0]).expect("the line is JSON");
        assert_eq!(first_line["id"], json!(1));
    }

    #[test]
    fn a_daemon_that_cannot_be_reached_is_an_error() {
        // A socket that is not there: the plugin says so, it does not panic.
        let client = QueryClient::new(
            std::path::PathBuf::from("/nonexistent/od3sa-recon/query.sock"),
            "token".to_string(),
        );

        let mut out: Vec<u8> = Vec::new();
        let error =
            export_kind(&client, Kind::Devices, &mut out).expect_err("the daemon is not there");

        match error {
            ExportError::Query(PluginError::Connect(_)) => {}
            other => panic!("expected a connect error, got {other:?}"),
        }
        // The message says what went wrong.
        let message = error.to_string();
        assert!(message.contains("cannot reach the daemon"), "{message}");
    }

    #[test]
    fn a_method_the_daemon_does_not_have_is_an_error() {
        // The scripted client has no answer for `probes.list`.
        let client = QueryClient::scripted(vec![("aps.list", json!({"items": []}))]);

        let mut out: Vec<u8> = Vec::new();
        let error = export_kind(&client, Kind::Alerts, &mut out)
            .expect_err("the daemon does not answer that");

        assert!(matches!(
            error,
            ExportError::Query(PluginError::Protocol(_))
        ));
    }

    #[test]
    fn the_export_to_a_path_writes_one_file_per_kind() {
        let client = QueryClient::scripted(vec![
            ("devices.list", json!({"items": [device()]})),
            ("aps.list", json!({"items": []})),
            ("clients.list", json!({"items": []})),
            ("sightings.list", json!({"items": []})),
            ("alerts.list", json!({"items": []})),
        ]);

        let directory =
            std::env::temp_dir().join(format!("od3sa-ndjson-export-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&directory);

        let report = export_to_path(&client, Kind::ALL.as_ref(), &directory)
            .expect("the export should work");

        assert_eq!(report.total(), 1);
        for kind in Kind::ALL {
            let file = directory.join(format!("{}.ndjson", kind.name()));
            assert!(file.is_file(), "{} is missing", file.display());
        }

        let _ = std::fs::remove_dir_all(&directory);
    }

    /// A daemon that answers with pages, over a real socket.
    ///
    /// The client opens a connection per call, so the fake daemon accepts
    /// one connection per page and answers it with one line.
    fn fake_daemon(
        pages: Vec<Value>,
    ) -> (std::path::PathBuf, std::thread::JoinHandle<Vec<String>>) {
        use std::io::{BufRead, BufReader, Write};
        use std::os::unix::net::UnixListener;

        let path = std::env::temp_dir().join(format!(
            "od3sa-ndjson-fake-{}-{}.sock",
            std::process::id(),
            pages.len()
        ));
        let _ = std::fs::remove_file(&path);

        let listener = UnixListener::bind(&path).expect("the fake daemon should bind");
        let handle = std::thread::spawn(move || {
            let mut requests = Vec::new();
            for page in pages {
                let (stream, _) = match listener.accept() {
                    Ok(pair) => pair,
                    Err(_) => break,
                };
                let mut reader =
                    BufReader::new(stream.try_clone().expect("the stream should clone"));
                let mut request = String::new();
                reader
                    .read_line(&mut request)
                    .expect("the request should read");
                requests.push(request.clone());

                let mut stream = stream;
                let answer = json!({
                    "jsonrpc": "2.0",
                    "id": 1,
                    "result": page,
                });
                let line = serde_json::to_string(&answer).expect("the answer is JSON");
                stream
                    .write_all(line.as_bytes())
                    .and_then(|()| stream.write_all(b"\n"))
                    .expect("the answer should write");
                stream.flush().expect("the answer should flush");
            }
            requests
        });

        (path, handle)
    }

    #[test]
    fn the_export_follows_the_cursor_and_writes_the_pages_as_they_come() {
        let (socket, daemon) = fake_daemon(vec![
            json!({"items": [device()], "next_cursor": "v1.00.00"}),
            json!({"items": [device()], "next_cursor": null}),
        ]);

        let client = QueryClient::new(socket.clone(), "token".to_string());
        let mut out: Vec<u8> = Vec::new();
        let written =
            export_kind(&client, Kind::Devices, &mut out).expect("the export should work");
        let requests = daemon.join().expect("the daemon should finish");

        // Both pages, two objects.
        assert_eq!(written, 2);
        let text = String::from_utf8(out).expect("the export is text");
        assert_eq!(text.lines().count(), 2);
        assert_eq!(requests.len(), 2);
        // The second request carries the cursor of the first page.
        assert!(!requests[0].contains("cursor"), "{}", requests[0]);
        assert!(requests[1].contains("cursor"), "{}", requests[1]);

        let _ = std::fs::remove_file(&socket);
    }

    #[test]
    fn the_manifest_parses_and_names_methods_that_exist() {
        let manifest = read_manifest();
        let fields = flat_fields(&manifest);

        // The fields the host needs, with the values they should have.
        assert_eq!(
            fields.get("name").and_then(Field::as_str),
            Some("ndjson-export")
        );
        assert_eq!(
            fields.get("exec").and_then(Field::as_str),
            Some("bin/ndjson-export")
        );
        assert_eq!(fields.get("run").and_then(Field::as_str), Some("external"));
        assert_eq!(fields.get("memory_mb").and_then(Field::as_int), Some(8));
        assert_eq!(fields.get("network").and_then(Field::as_bool), Some(false));
        // The API version. The host reads it as a whole number, so that is
        // how it is written.
        assert_eq!(fields.get("api").and_then(Field::as_int), Some(0));

        // Every capability names a method the daemon has. The write path
        // is a capability too, and it is not a query method.
        let capabilities = fields
            .get("capabilities")
            .and_then(Field::as_list)
            .expect("the manifest should have capabilities");
        assert_eq!(capabilities.len(), 6);

        let methods = daemon_methods();
        for capability in capabilities {
            if let Some(path) = capability.strip_prefix("fs:write:") {
                assert_eq!(path, "/mmc/od3sa-recon/export");
                continue;
            }
            let method = capability
                .strip_prefix("query:")
                .unwrap_or_else(|| panic!("{capability} is not a query capability"));
            assert!(
                methods.iter().any(|known| *known == method),
                "the daemon has no method '{method}'"
            );
        }
    }

    #[test]
    fn the_manifest_asks_for_the_methods_the_export_calls() {
        let manifest = read_manifest();
        let fields = flat_fields(&manifest);
        let capabilities = fields
            .get("capabilities")
            .and_then(Field::as_list)
            .expect("the manifest should have capabilities");

        let asked: Vec<&str> = capabilities
            .iter()
            .filter_map(|capability| capability.strip_prefix("query:"))
            .collect();

        for kind in Kind::ALL {
            assert!(
                asked.contains(&kind.method()),
                "the manifest does not ask for '{}'",
                kind.method()
            );
        }
        assert_eq!(asked.len(), Kind::ALL.len());
    }

    /// The manifest of this plugin, as it is on disk.
    fn read_manifest() -> String {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../plugins/ndjson-export/plugin.toml");
        std::fs::read_to_string(&path).unwrap_or_else(|error| {
            panic!("the manifest should be read: {}: {error}", path.display())
        })
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

    /// A value in a flat manifest.
    #[derive(Debug, Clone, PartialEq)]
    enum Field {
        Text(String),
        Integer(i64),
        Boolean(bool),
        List(Vec<String>),
    }

    impl Field {
        fn as_str(&self) -> Option<&str> {
            match self {
                Self::Text(text) => Some(text),
                _ => None,
            }
        }

        fn as_int(&self) -> Option<i64> {
            match self {
                Self::Integer(value) => Some(*value),
                _ => None,
            }
        }

        fn as_bool(&self) -> Option<bool> {
            match self {
                Self::Boolean(value) => Some(*value),
                _ => None,
            }
        }

        fn as_list(&self) -> Option<&[String]> {
            match self {
                Self::List(items) => Some(items),
                _ => None,
            }
        }
    }

    /// Read a flat manifest: `key = value` lines, nothing nested.
    ///
    /// The manifest is a flat table, so this is enough to read it, and it
    /// keeps the plugin free of a TOML dependency.
    fn flat_fields(text: &str) -> std::collections::HashMap<String, Field> {
        let mut fields = std::collections::HashMap::new();

        for line in text.lines() {
            let line = match line.split_once('#') {
                Some((before, _)) => before,
                None => line,
            };
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let Some((key, value)) = line.split_once('=') else {
                continue;
            };
            let key = key.trim().to_string();
            let value = value.trim();

            let field = if value.starts_with('[') {
                let inner = value.trim_start_matches('[').trim_end_matches(']');
                let items = inner
                    .split(',')
                    .map(|item| item.trim().trim_matches('"').to_string())
                    .filter(|item| !item.is_empty())
                    .collect();
                Field::List(items)
            } else if value.starts_with('"') {
                Field::Text(value.trim_matches('"').to_string())
            } else if value == "true" {
                Field::Boolean(true)
            } else if value == "false" {
                Field::Boolean(false)
            } else {
                match value.parse::<i64>() {
                    Ok(number) => Field::Integer(number),
                    Err(_) => Field::Text(value.to_string()),
                }
            };

            fields.insert(key, field);
        }

        fields
    }

    #[test]
    fn the_export_to_a_path_writes_one_kind_to_one_file() {
        let client = QueryClient::scripted(vec![(
            "devices.list",
            json!({"items": [device(), device()]}),
        )]);

        let directory =
            std::env::temp_dir().join(format!("od3sa-ndjson-export-one-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&directory);
        std::fs::create_dir_all(&directory).expect("the directory should be made");

        let file = directory.join("devices.ndjson");
        let report =
            export_to_path(&client, &[Kind::Devices], &file).expect("the export should work");

        assert_eq!(report.total(), 2);
        let text = std::fs::read_to_string(&file).expect("the file should be there");
        assert_eq!(text.lines().count(), 2);

        let _ = std::fs::remove_dir_all(&directory);
    }
}
