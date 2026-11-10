//! The read-only JSON-RPC 2.0 query socket.
//!
//! The daemon owns the socket; this module is the server behind it. It
//! speaks JSON-RPC 2.0 over NDJSON: one request per line, one response per
//! line. The wire shapes are the contract in `docs/QUERY-API.md`.
//!
//! # Read-only
//!
//! Every statement the server runs is a `SELECT` (or one of two read-only
//! `PRAGMA`s that report the size of the database). There is no method that
//! writes, no method that takes a SQL string from the caller, and no method
//! that touches a radio, a channel, an interface mode or a service. The
//! [`Store`] is held behind a mutex and never handed out.
//!
//! # The token
//!
//! Every request carries a `token` in its parameters. The token is checked
//! **before** the method is looked up, so a caller that cannot authenticate
//! cannot learn which methods exist by probing them.
//!
//! # The cursor
//!
//! `next_cursor` is opaque: it carries the sort key of the last row of the
//! page, the name of the method that produced it, and a checksum keyed with
//! the token. A cursor that was edited by hand, or that belongs to another
//! method, is refused.

use std::fmt;
use std::fmt::Write as _;
use std::fs;
use std::io::{self, BufRead, Write};
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, RwLock};
use std::thread;
use std::time::{Duration, Instant};

use od3sa_store::{Rows, Store, StoreError, Value, ValueExt};
use serde_json::{Map, Value as Json, json};

#[cfg(test)]
mod tests;

/// The default path of the query socket.
pub const DEFAULT_SOCKET_PATH: &str = "/tmp/od3sa-recon/query.sock";

/// The version of the query API this build speaks.
pub const API_VERSION: u32 = 0;

/// The largest number of rows a caller may ask for.
pub const MAX_LIMIT: usize = 500;

/// The number of rows returned when the caller does not ask for a number.
pub const DEFAULT_LIMIT: usize = 100;

/// The JSON-RPC error code for a line that is not JSON.
pub const PARSE_ERROR: i64 = -32700;

/// The JSON-RPC error code for a request that is not JSON-RPC 2.0.
pub const INVALID_REQUEST: i64 = -32600;

/// The JSON-RPC error code for a method that does not exist.
pub const METHOD_NOT_FOUND: i64 = -32601;

/// The JSON-RPC error code for parameters the method cannot use.
pub const INVALID_PARAMS: i64 = -32602;

/// The JSON-RPC error code for a database error.
pub const DATABASE_ERROR: i64 = -32000;

/// The JSON-RPC error code for a missing or wrong token.
pub const UNAUTHORIZED: i64 = -32001;

/// The version of the daemon, as the `status` method reports it.
const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The longest request line the server reads.
const MAX_LINE: usize = 64 * 1024;

/// How many recent sightings `devices.get` returns.
const DEVICE_SIGHTINGS: usize = 100;

/// The methods the server answers.
///
/// Every one of them is a read.
pub const METHODS: &[&str] = &[
    "status",
    "devices.list",
    "devices.get",
    "aps.list",
    "clients.list",
    "probes.list",
    "ble.list",
    "sightings.list",
    "alerts.list",
    "sources.list",
];

/// Something went wrong in the query server.
#[derive(Debug)]
#[non_exhaustive]
pub enum QueryError {
    /// The socket or the file behind it could not be used.
    Io(io::Error),
    /// The database reported an error.
    Store(StoreError),
}

impl fmt::Display for QueryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(source) => write!(f, "query socket error: {source}"),
            Self::Store(source) => write!(f, "query database error: {source}"),
        }
    }
}

impl std::error::Error for QueryError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(source) => Some(source),
            Self::Store(source) => Some(source),
        }
    }
}

impl From<io::Error> for QueryError {
    fn from(source: io::Error) -> Self {
        Self::Io(source)
    }
}

impl From<StoreError> for QueryError {
    fn from(source: StoreError) -> Self {
        Self::Store(source)
    }
}

/// A JSON-RPC error, with the code the contract gives it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct RpcError {
    code: i64,
    message: String,
}

impl RpcError {
    /// Build an error with a code and a message.
    fn new(code: i64, message: impl Into<String>) -> RpcError {
        RpcError {
            code,
            message: message.into(),
        }
    }
}

/// The state every connection shares.
#[derive(Debug)]
struct ServerState {
    store: Mutex<Store>,
    token: String,
    /// Tokens that may only call some of the methods.
    ///
    /// A plugin gets a token of its own, scoped to the methods its manifest
    /// asked for, so it cannot read what it was not given.
    scoped_tokens: RwLock<Vec<(String, Vec<String>)>>,
    key: u64,
    started: Instant,
    stopping: AtomicBool,
}

impl ServerState {
    /// The store, with the lock held for the length of the statement.
    fn store(&self) -> MutexGuard<'_, Store> {
        match self.store.lock() {
            Ok(guard) => guard,
            // A poisoned lock means a previous query panicked. The database
            // is still consistent, so the lock is taken over.
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    /// Run a read-only statement and return its rows.
    ///
    /// The values the statement takes are bound, never written into the SQL
    /// text, so a value cannot change what the statement means.
    fn query(&self, sql: &str, params: &[Value]) -> Result<Rows, RpcError> {
        let sql = read_only(sql)?;
        let store = self.store();
        store
            .query_with(sql, params)
            .map_err(|error| RpcError::new(DATABASE_ERROR, format!("database error: {error}")))
    }

    /// The number of rows a `count(*)` statement returns.
    fn count(&self, sql: &str) -> Result<i64, RpcError> {
        let rows = self.query(sql, &[])?;
        Ok(integer_of(&rows, 0, "n").unwrap_or(0))
    }

    /// Answer one line of input.
    ///
    /// Returns the response to write, or `None` when the line was a
    /// notification (a request without an `id`), which gets no response.
    fn handle_line(&self, line: &str) -> Option<Json> {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            return None;
        }

        let parsed: Json = match serde_json::from_str(trimmed) {
            Ok(parsed) => parsed,
            // A line that is not JSON is an error, and the connection stays
            // open.
            Err(_) => return Some(error_response(Json::Null, PARSE_ERROR, "parse error")),
        };

        let object = match parsed.as_object() {
            Some(object) => object,
            None => {
                return Some(error_response(
                    Json::Null,
                    INVALID_REQUEST,
                    "invalid request",
                ));
            }
        };

        let id = object.get("id").cloned();
        let response_id = id.clone().unwrap_or(Json::Null);
        let notification = id.is_none();

        if object.get("jsonrpc").and_then(Json::as_str) != Some("2.0") {
            return Some(error_response(
                response_id,
                INVALID_REQUEST,
                "invalid request",
            ));
        }

        let method = match object.get("method").and_then(Json::as_str) {
            Some(method) => method,
            None => {
                return Some(error_response(
                    response_id,
                    INVALID_REQUEST,
                    "invalid request",
                ));
            }
        };

        // The token is checked before the method is looked up, so a caller
        // that cannot authenticate cannot learn which methods exist.
        let params = object.get("params").and_then(Json::as_object);
        let token = params
            .and_then(|params| params.get("token"))
            .and_then(Json::as_str);
        let token = match token {
            Some(value) => value,
            None => {
                return if notification {
                    None
                } else {
                    Some(error_response(
                        response_id,
                        UNAUTHORIZED,
                        "bad or missing token",
                    ))
                };
            }
        };
        if !self.token_is_known(token) {
            return if notification {
                None
            } else {
                Some(error_response(
                    response_id,
                    UNAUTHORIZED,
                    "bad or missing token",
                ))
            };
        }

        let empty = Map::new();
        let params = params.unwrap_or(&empty);

        let outcome = self.dispatch(method, params, token);
        if notification {
            return None;
        }

        Some(match outcome {
            Ok(result) => json!({"jsonrpc": "2.0", "id": response_id, "result": result}),
            Err(error) => error_response(response_id, error.code, &error.message),
        })
    }

    /// Run one method.
    /// Whether this is the daemon's own token or a plugin's.
    fn token_is_known(&self, token: &str) -> bool {
        if token == self.token {
            return true;
        }
        self.scope_for(token).is_some()
    }

    /// The methods a scoped token may call.
    fn scope_for(&self, token: &str) -> Option<Vec<String>> {
        let tokens = match self.scoped_tokens.read() {
            Ok(tokens) => tokens,
            Err(poisoned) => poisoned.into_inner(),
        };
        tokens
            .iter()
            .find(|(secret, _)| secret == token)
            .map(|(_, methods)| methods.clone())
    }

    fn dispatch(
        &self,
        method: &str,
        params: &Map<String, Json>,
        token: &str,
    ) -> Result<Json, RpcError> {
        // A plugin's token may only call the methods its manifest asked
        // for. The method exists, but this token may not have it.
        if let Some(scope) = self.scope_for(token)
            && !scope.iter().any(|allowed| allowed == method)
        {
            return Err(RpcError::new(
                UNAUTHORIZED,
                "this token may not call that method",
            ));
        }
        match method {
            "status" => self.status(),
            "devices.list" => self.devices_list(params),
            "devices.get" => self.device_get(params),
            "aps.list" => self.aps_list(params),
            "clients.list" => self.clients_list(params),
            "probes.list" => self.probes_list(params),
            "ble.list" => self.ble_list(params),
            "sightings.list" => self.sightings_list(params),
            "alerts.list" => self.alerts_list(params),
            "sources.list" => self.sources_list(params),
            _ => Err(RpcError::new(METHOD_NOT_FOUND, "no such method")),
        }
    }

    /// The `status` method: what the daemon is doing and what it holds.
    fn status(&self) -> Result<Json, RpcError> {
        let sources = self.query(
            "SELECT name, kind, status, frames, errors FROM sources ORDER BY id",
            &[],
        )?;
        let source_items: Vec<Json> = (0..sources.len())
            .map(|index| {
                json!({
                    "name": text_of(&sources, index, "name"),
                    "kind": text_of(&sources, index, "kind"),
                    "status": text_of(&sources, index, "status"),
                    "frames": integer_of(&sources, index, "frames"),
                    "errors": integer_of(&sources, index, "errors"),
                })
            })
            .collect();

        let devices = self.count("SELECT count(*) AS n FROM devices")?;
        let aps = self.count("SELECT count(*) AS n FROM access_points")?;
        let clients = self.count("SELECT count(*) AS n FROM clients")?;
        let ble = self.count("SELECT count(*) AS n FROM ble_devices")?;

        Ok(json!({
            "version": VERSION,
            "api": API_VERSION,
            "uptime_s": self.started.elapsed().as_secs(),
            "sources": source_items,
            "counts": {
                "devices": devices,
                "aps": aps,
                "clients": clients,
                "ble": ble,
            },
            "db_bytes": self.database_bytes()?,
            "rss_kb": resident_kb(),
        }))
    }

    /// The size of the database, in bytes.
    fn database_bytes(&self) -> Result<i64, RpcError> {
        let pages = self.pragma_number("page_count")?;
        let size = self.pragma_number("page_size")?;
        Ok(pages * size)
    }

    /// The number a read-only pragma reports.
    fn pragma_number(&self, pragma: &str) -> Result<i64, RpcError> {
        let rows = self.query(&format!("PRAGMA {pragma}"), &[])?;
        Ok(integer_of(&rows, 0, pragma).unwrap_or(0))
    }

    /// The `devices.list` method.
    fn devices_list(&self, params: &Map<String, Json>) -> Result<Json, RpcError> {
        let (limit, cursor) = self.paging(params, "devices.list")?;

        let mut sql = String::from(
            "SELECT id, mac, kind, oui, randomized, first_seen_ms, last_seen_ms, max_rssi, last_rssi, \
             COALESCE(last_seen_ms, 0) AS sort_0, id AS sort_1 FROM devices d WHERE 1 = 1",
        );
        let mut values: Vec<Value> = Vec::new();

        if let Some(kind) = param_str(params, "kind") {
            sql.push_str(" AND d.kind = ?");
            values.push(Value::Text(kind.to_string()));
        }
        if let Some(since) = param_int(params, "since_ms")? {
            sql.push_str(" AND COALESCE(d.last_seen_ms, 0) >= ?");
            values.push(Value::Integer(since));
        }
        if let Some(oui) = param_str(params, "oui") {
            sql.push_str(" AND d.oui = ?");
            values.push(Value::Text(oui.to_ascii_lowercase()));
        }
        if let Some(min_rssi) = param_int(params, "min_rssi")? {
            sql.push_str(" AND d.max_rssi IS NOT NULL AND d.max_rssi >= ?");
            values.push(Value::Integer(min_rssi));
        }
        if let Some(parts) = &cursor {
            let parts = cursor_values(parts, 2)?;
            sql.push_str(" AND (COALESCE(d.last_seen_ms, 0), d.id) > (?, ?)");
            values.push(Value::Integer(parts[0]));
            values.push(Value::Integer(parts[1]));
        }
        sql.push_str(" ORDER BY sort_0 ASC, sort_1 ASC LIMIT ?");
        values.push(Value::Integer(limit as i64 + 1));

        let rows = self.query(&sql, &values)?;
        Ok(page_response(
            &rows,
            limit,
            "devices.list",
            self.key,
            2,
            |index| device_item(&rows, index),
        ))
    }

    /// The `devices.get` method: one device and what is known about it.
    fn device_get(&self, params: &Map<String, Json>) -> Result<Json, RpcError> {
        let mac = param_str(params, "mac")
            .ok_or_else(|| RpcError::new(INVALID_PARAMS, "'mac' is required"))?;
        let mac = normalize_mac(mac)?;

        let rows = self.query(
            "SELECT id, mac, kind, oui, randomized, first_seen_ms, last_seen_ms, max_rssi, last_rssi \
             FROM devices WHERE mac = ?",
            &[Value::Text(mac.clone())],
        )?;
        if rows.is_empty() {
            return Err(RpcError::new(
                INVALID_PARAMS,
                "no device with that mac address",
            ));
        }
        let id = integer_of(&rows, 0, "id").unwrap_or(0);
        let device = device_item(&rows, 0);

        let aps = self.query(
            "SELECT a.device_id, d.mac AS bssid, s.ssid AS ssid, s.hidden AS ssid_hidden, \
             a.channel AS channel, a.freq_mhz AS freq_mhz, a.band AS band, a.security AS security, \
             a.akm AS akm, a.pairwise AS pairwise, a.group_cipher AS group_cipher, a.pmf AS pmf, \
             a.wps AS wps, a.ht AS ht, a.vht AS vht, a.he AS he, a.vendor_ies AS vendor_ies, \
             a.beacon_int AS beacon_int, a.last_beacon_ms AS last_beacon_ms \
             FROM access_points a JOIN devices d ON d.id = a.device_id \
             LEFT JOIN ssids s ON s.id = a.ssid_id WHERE a.device_id = ?",
            &[Value::Integer(id)],
        )?;
        let access_point = if aps.is_empty() {
            Json::Null
        } else {
            ap_item(&aps, 0)
        };

        let ble = self.query(
            "SELECT d.mac AS mac, d.kind AS kind, d.oui AS oui, d.randomized AS randomized, \
             d.first_seen_ms AS first_seen_ms, d.last_seen_ms AS last_seen_ms, \
             d.max_rssi AS max_rssi, d.last_rssi AS last_rssi, b.name AS name, \
             b.addr_type AS addr_type, b.manufacturer_id AS manufacturer_id, \
             b.services AS services, b.tx_power AS tx_power, b.source AS source \
             FROM ble_devices b JOIN devices d ON d.id = b.device_id WHERE b.device_id = ?",
            &[Value::Integer(id)],
        )?;
        let ble = if ble.is_empty() {
            Json::Null
        } else {
            ble_item(&ble, 0)
        };

        let sightings = self.query(
            "SELECT bucket_ms AS bucket_ms, n AS n, rssi_min AS rssi_min, rssi_max AS rssi_max, \
             rssi_avg AS rssi_avg, channel AS channel, lat AS lat, lon AS lon, alt AS alt, \
             fix AS fix FROM sightings WHERE device_id = ? \
             ORDER BY bucket_ms DESC LIMIT ?",
            &[Value::Integer(id), Value::Integer(DEVICE_SIGHTINGS as i64)],
        )?;
        let sighting_items: Vec<Json> = (0..sightings.len())
            .map(|index| {
                let bucket = integer_of(&sightings, index, "bucket_ms");
                json!({
                    "ts_ms": bucket,
                    "bucket_ms": bucket,
                    "n": integer_of(&sightings, index, "n"),
                    "rssi_min": integer_of(&sightings, index, "rssi_min"),
                    "rssi_max": integer_of(&sightings, index, "rssi_max"),
                    "rssi_avg": real_of(&sightings, index, "rssi_avg"),
                    "channel": integer_of(&sightings, index, "channel"),
                    "lat": real_of(&sightings, index, "lat"),
                    "lon": real_of(&sightings, index, "lon"),
                    "alt": real_of(&sightings, index, "alt"),
                    "fix": integer_of(&sightings, index, "fix"),
                })
            })
            .collect();

        Ok(json!({
            "device": device,
            "access_point": access_point,
            "ble": ble,
            "sightings": sighting_items,
        }))
    }

    /// The `aps.list` method.
    fn aps_list(&self, params: &Map<String, Json>) -> Result<Json, RpcError> {
        let (limit, cursor) = self.paging(params, "aps.list")?;

        let mut sql = String::from(
            "SELECT a.device_id AS device_id, d.mac AS bssid, s.ssid AS ssid, s.hidden AS ssid_hidden, \
             a.channel AS channel, a.freq_mhz AS freq_mhz, a.band AS band, a.security AS security, \
             a.akm AS akm, a.pairwise AS pairwise, a.group_cipher AS group_cipher, a.pmf AS pmf, \
             a.wps AS wps, a.ht AS ht, a.vht AS vht, a.he AS he, a.vendor_ies AS vendor_ies, \
             a.beacon_int AS beacon_int, a.last_beacon_ms AS last_beacon_ms, \
             COALESCE(a.last_beacon_ms, 0) AS sort_0, a.device_id AS sort_1 \
             FROM access_points a JOIN devices d ON d.id = a.device_id \
             LEFT JOIN ssids s ON s.id = a.ssid_id WHERE 1 = 1",
        );
        let mut values: Vec<Value> = Vec::new();

        if let Some(ssid) = param_str(params, "ssid") {
            sql.push_str(" AND s.ssid = ?");
            values.push(Value::Blob(ssid.as_bytes().to_vec()));
        }
        if let Some(band) = param_str(params, "band") {
            // The wildcard is part of the pattern, not of the statement.
            sql.push_str(" AND a.band LIKE ?");
            values.push(Value::Text(format!("{band}%")));
        }
        if let Some(security) = param_str(params, "security") {
            sql.push_str(" AND a.security = ?");
            values.push(Value::Text(security.to_string()));
        }
        if let Some(since) = param_int(params, "since_ms")? {
            sql.push_str(" AND COALESCE(a.last_beacon_ms, 0) >= ?");
            values.push(Value::Integer(since));
        }
        if let Some(parts) = &cursor {
            let parts = cursor_values(parts, 2)?;
            sql.push_str(" AND (COALESCE(a.last_beacon_ms, 0), a.device_id) > (?, ?)");
            values.push(Value::Integer(parts[0]));
            values.push(Value::Integer(parts[1]));
        }
        sql.push_str(" ORDER BY sort_0 ASC, sort_1 ASC LIMIT ?");
        values.push(Value::Integer(limit as i64 + 1));

        let rows = self.query(&sql, &values)?;
        Ok(page_response(
            &rows,
            limit,
            "aps.list",
            self.key,
            2,
            |index| ap_item(&rows, index),
        ))
    }

    /// The `clients.list` method.
    fn clients_list(&self, params: &Map<String, Json>) -> Result<Json, RpcError> {
        let (limit, cursor) = self.paging(params, "clients.list")?;

        let mut sql = String::from(
            "SELECT cd.mac AS client, bd.mac AS bssid, c.first_seen_ms AS first_seen_ms, \
             c.last_seen_ms AS last_seen_ms, COALESCE(c.last_seen_ms, 0) AS sort_0, \
             c.device_id AS sort_1, c.bssid_device_id AS sort_2 \
             FROM clients c JOIN devices cd ON cd.id = c.device_id \
             JOIN devices bd ON bd.id = c.bssid_device_id WHERE 1 = 1",
        );
        let mut values: Vec<Value> = Vec::new();

        if let Some(bssid) = param_str(params, "bssid") {
            let bssid = normalize_mac(bssid)?;
            sql.push_str(" AND bd.mac = ?");
            values.push(Value::Text(bssid));
        }
        if let Some(since) = param_int(params, "since_ms")? {
            sql.push_str(" AND COALESCE(c.last_seen_ms, 0) >= ?");
            values.push(Value::Integer(since));
        }
        if let Some(parts) = &cursor {
            let parts = cursor_values(parts, 3)?;
            sql.push_str(
                " AND (COALESCE(c.last_seen_ms, 0), c.device_id, c.bssid_device_id) > (?, ?, ?)",
            );
            values.push(Value::Integer(parts[0]));
            values.push(Value::Integer(parts[1]));
            values.push(Value::Integer(parts[2]));
        }
        sql.push_str(" ORDER BY sort_0 ASC, sort_1 ASC, sort_2 ASC LIMIT ?");
        values.push(Value::Integer(limit as i64 + 1));

        let rows = self.query(&sql, &values)?;
        Ok(page_response(
            &rows,
            limit,
            "clients.list",
            self.key,
            3,
            |index| {
                json!({
                    "client": mac_of(&rows, index, "client"),
                    "bssid": mac_of(&rows, index, "bssid"),
                    "first_seen_ms": integer_of(&rows, index, "first_seen_ms"),
                    "last_seen_ms": integer_of(&rows, index, "last_seen_ms"),
                })
            },
        ))
    }

    /// The `probes.list` method.
    fn probes_list(&self, params: &Map<String, Json>) -> Result<Json, RpcError> {
        let (limit, cursor) = self.paging(params, "probes.list")?;

        let mut sql = String::from(
            "SELECT cd.mac AS client, s.ssid AS ssid, p.first_seen_ms AS first_seen_ms, \
             p.last_seen_ms AS last_seen_ms, p.count AS count, \
             COALESCE(p.last_seen_ms, 0) AS sort_0, p.device_id AS sort_1, \
             COALESCE(p.ssid_id, -1) AS sort_2 \
             FROM probes p JOIN devices cd ON cd.id = p.device_id \
             LEFT JOIN ssids s ON s.id = p.ssid_id WHERE 1 = 1",
        );
        let mut values: Vec<Value> = Vec::new();

        if let Some(client) = param_str(params, "client") {
            let client = normalize_mac(client)?;
            sql.push_str(" AND cd.mac = ?");
            values.push(Value::Text(client));
        }
        if let Some(ssid) = param_str(params, "ssid") {
            sql.push_str(" AND s.ssid = ?");
            values.push(Value::Blob(ssid.as_bytes().to_vec()));
        }
        if let Some(since) = param_int(params, "since_ms")? {
            sql.push_str(" AND COALESCE(p.last_seen_ms, 0) >= ?");
            values.push(Value::Integer(since));
        }
        if let Some(parts) = &cursor {
            let parts = cursor_values(parts, 3)?;
            sql.push_str(
                " AND (COALESCE(p.last_seen_ms, 0), p.device_id, COALESCE(p.ssid_id, -1)) \
                 > (?, ?, ?)",
            );
            values.push(Value::Integer(parts[0]));
            values.push(Value::Integer(parts[1]));
            values.push(Value::Integer(parts[2]));
        }
        sql.push_str(" ORDER BY sort_0 ASC, sort_1 ASC, sort_2 ASC LIMIT ?");
        values.push(Value::Integer(limit as i64 + 1));

        let rows = self.query(&sql, &values)?;
        Ok(page_response(
            &rows,
            limit,
            "probes.list",
            self.key,
            3,
            |index| {
                json!({
                    "client": mac_of(&rows, index, "client"),
                    "ssid": ssid_of(&rows, index, "ssid"),
                    "first_seen_ms": integer_of(&rows, index, "first_seen_ms"),
                    "last_seen_ms": integer_of(&rows, index, "last_seen_ms"),
                    "count": integer_of(&rows, index, "count"),
                })
            },
        ))
    }

    /// The `ble.list` method.
    ///
    /// Empty until the blue5 ingest lands (OR-501): there is nothing to
    /// read yet, but the method is there and reads the table.
    fn ble_list(&self, params: &Map<String, Json>) -> Result<Json, RpcError> {
        let (limit, cursor) = self.paging(params, "ble.list")?;

        let mut sql = String::from(
            "SELECT d.mac AS mac, d.kind AS kind, d.oui AS oui, d.randomized AS randomized, \
             d.first_seen_ms AS first_seen_ms, d.last_seen_ms AS last_seen_ms, \
             d.max_rssi AS max_rssi, d.last_rssi AS last_rssi, b.name AS name, \
             b.addr_type AS addr_type, b.manufacturer_id AS manufacturer_id, \
             b.services AS services, b.tx_power AS tx_power, b.source AS source, \
             COALESCE(d.last_seen_ms, 0) AS sort_0, d.id AS sort_1 \
             FROM ble_devices b JOIN devices d ON d.id = b.device_id WHERE 1 = 1",
        );
        let mut values: Vec<Value> = Vec::new();

        if let Some(since) = param_int(params, "since_ms")? {
            sql.push_str(" AND COALESCE(d.last_seen_ms, 0) >= ?");
            values.push(Value::Integer(since));
        }
        if let Some(name) = param_str(params, "name") {
            sql.push_str(" AND b.name = ?");
            values.push(Value::Text(name.to_string()));
        }
        if let Some(parts) = &cursor {
            let parts = cursor_values(parts, 2)?;
            sql.push_str(" AND (COALESCE(d.last_seen_ms, 0), d.id) > (?, ?)");
            values.push(Value::Integer(parts[0]));
            values.push(Value::Integer(parts[1]));
        }
        sql.push_str(" ORDER BY sort_0 ASC, sort_1 ASC LIMIT ?");
        values.push(Value::Integer(limit as i64 + 1));

        let rows = self.query(&sql, &values)?;
        Ok(page_response(
            &rows,
            limit,
            "ble.list",
            self.key,
            2,
            |index| ble_item(&rows, index),
        ))
    }

    /// The `sightings.list` method.
    fn sightings_list(&self, params: &Map<String, Json>) -> Result<Json, RpcError> {
        let (limit, cursor) = self.paging(params, "sightings.list")?;

        let mut sql = String::from(
            "SELECT s.device_id AS device_id, s.source_id AS source_id, s.bucket_ms AS bucket_ms, \
             s.n AS n, s.rssi_min AS rssi_min, s.rssi_max AS rssi_max, s.rssi_avg AS rssi_avg, \
             s.channel AS channel, s.lat AS lat, s.lon AS lon, s.alt AS alt, s.fix AS fix, \
             s.bucket_ms AS sort_0, s.device_id AS sort_1, s.source_id AS sort_2 \
             FROM sightings s JOIN devices d ON d.id = s.device_id WHERE 1 = 1",
        );
        let mut values: Vec<Value> = Vec::new();

        if let Some(mac) = param_str(params, "mac") {
            let mac = normalize_mac(mac)?;
            sql.push_str(" AND d.mac = ?");
            values.push(Value::Text(mac));
        }
        if let Some(from) = param_int(params, "from_ms")? {
            sql.push_str(" AND s.bucket_ms >= ?");
            values.push(Value::Integer(from));
        }
        if let Some(to) = param_int(params, "to_ms")? {
            sql.push_str(" AND s.bucket_ms <= ?");
            values.push(Value::Integer(to));
        }
        if let Some(parts) = &cursor {
            let parts = cursor_values(parts, 3)?;
            sql.push_str(" AND (s.bucket_ms, s.device_id, s.source_id) > (?, ?, ?)");
            values.push(Value::Integer(parts[0]));
            values.push(Value::Integer(parts[1]));
            values.push(Value::Integer(parts[2]));
        }
        sql.push_str(" ORDER BY sort_0 ASC, sort_1 ASC, sort_2 ASC LIMIT ?");
        values.push(Value::Integer(limit as i64 + 1));

        let rows = self.query(&sql, &values)?;
        Ok(page_response(
            &rows,
            limit,
            "sightings.list",
            self.key,
            3,
            |index| {
                json!({
                    "device_id": integer_of(&rows, index, "device_id"),
                    "source_id": integer_of(&rows, index, "source_id"),
                    "bucket_ms": integer_of(&rows, index, "bucket_ms"),
                    "n": integer_of(&rows, index, "n"),
                    "rssi_min": integer_of(&rows, index, "rssi_min"),
                    "rssi_max": integer_of(&rows, index, "rssi_max"),
                    "rssi_avg": real_of(&rows, index, "rssi_avg"),
                    "channel": integer_of(&rows, index, "channel"),
                    "lat": real_of(&rows, index, "lat"),
                    "lon": real_of(&rows, index, "lon"),
                    "alt": real_of(&rows, index, "alt"),
                    "fix": integer_of(&rows, index, "fix"),
                })
            },
        ))
    }

    /// The `alerts.list` method.
    fn alerts_list(&self, params: &Map<String, Json>) -> Result<Json, RpcError> {
        let (limit, cursor) = self.paging(params, "alerts.list")?;

        let mut sql = String::from(
            "SELECT a.id AS id, a.ts_ms AS ts_ms, a.rule AS rule, a.severity AS severity, \
             a.device_id AS device_id, a.summary AS summary, a.details AS details, \
             COALESCE(a.ts_ms, 0) AS sort_0, a.id AS sort_1 FROM alerts a WHERE 1 = 1",
        );
        let mut values: Vec<Value> = Vec::new();

        if let Some(since) = param_int(params, "since_ms")? {
            sql.push_str(" AND COALESCE(a.ts_ms, 0) >= ?");
            values.push(Value::Integer(since));
        }
        if let Some(rule) = param_str(params, "rule") {
            sql.push_str(" AND a.rule = ?");
            values.push(Value::Text(rule.to_string()));
        }
        if let Some(severity) = param_str(params, "severity") {
            sql.push_str(" AND a.severity = ?");
            values.push(Value::Text(severity.to_string()));
        }
        if let Some(parts) = &cursor {
            let parts = cursor_values(parts, 2)?;
            sql.push_str(" AND (COALESCE(a.ts_ms, 0), a.id) > (?, ?)");
            values.push(Value::Integer(parts[0]));
            values.push(Value::Integer(parts[1]));
        }
        sql.push_str(" ORDER BY sort_0 ASC, sort_1 ASC LIMIT ?");
        values.push(Value::Integer(limit as i64 + 1));

        let rows = self.query(&sql, &values)?;
        Ok(page_response(
            &rows,
            limit,
            "alerts.list",
            self.key,
            2,
            |index| {
                json!({
                    "id": integer_of(&rows, index, "id"),
                    "ts_ms": integer_of(&rows, index, "ts_ms"),
                    "rule": text_of(&rows, index, "rule"),
                    "severity": text_of(&rows, index, "severity"),
                    "device_id": integer_of(&rows, index, "device_id"),
                    "summary": text_of(&rows, index, "summary"),
                    "details": text_of(&rows, index, "details"),
                })
            },
        ))
    }

    /// The `sources.list` method.
    fn sources_list(&self, params: &Map<String, Json>) -> Result<Json, RpcError> {
        let (limit, cursor) = self.paging(params, "sources.list")?;

        let mut sql = String::from(
            "SELECT s.name AS name, s.kind AS kind, s.iface AS iface, s.status AS status, \
             s.last_seen_ms AS last_seen_ms, s.frames AS frames, s.errors AS errors, \
             COALESCE(s.last_seen_ms, 0) AS sort_0, s.id AS sort_1 FROM sources s WHERE 1 = 1",
        );
        let mut values: Vec<Value> = Vec::new();

        if let Some(parts) = &cursor {
            let parts = cursor_values(parts, 2)?;
            sql.push_str(" AND (COALESCE(s.last_seen_ms, 0), s.id) > (?, ?)");
            values.push(Value::Integer(parts[0]));
            values.push(Value::Integer(parts[1]));
        }
        sql.push_str(" ORDER BY sort_0 ASC, sort_1 ASC LIMIT ?");
        values.push(Value::Integer(limit as i64 + 1));

        let rows = self.query(&sql, &values)?;
        Ok(page_response(
            &rows,
            limit,
            "sources.list",
            self.key,
            2,
            |index| {
                json!({
                    "name": text_of(&rows, index, "name"),
                    "kind": text_of(&rows, index, "kind"),
                    "iface": text_of(&rows, index, "iface"),
                    "status": text_of(&rows, index, "status"),
                    "last_seen_ms": integer_of(&rows, index, "last_seen_ms"),
                    "frames": integer_of(&rows, index, "frames"),
                    "errors": integer_of(&rows, index, "errors"),
                })
            },
        ))
    }

    /// The page size and the cursor of one request.
    fn paging(
        &self,
        params: &Map<String, Json>,
        method: &str,
    ) -> Result<(usize, Option<Vec<i64>>), RpcError> {
        let limit = param_limit(params)?;
        let cursor = match param_str(params, "cursor") {
            Some(cursor) if !cursor.is_empty() => Some(decode_cursor(method, cursor, self.key)?),
            _ => None,
        };
        Ok((limit, cursor))
    }
}

/// The query socket.
///
/// The daemon owns one of these. It answers read-only JSON-RPC 2.0 requests
/// over a Unix stream socket, one request per line.
#[derive(Clone, Debug)]
pub struct QueryServer {
    listener: Arc<UnixListener>,
    state: Arc<ServerState>,
    socket_path: PathBuf,
}

impl QueryServer {
    /// Bind the socket and take the store.
    ///
    /// A socket file left over from a previous run is removed first. A path
    /// that exists and is not a socket is left alone and reported as an
    /// error: the daemon does not delete files it does not own.
    ///
    /// The socket is created with mode `0600`, so only the owner of the
    /// daemon may talk to it.
    ///
    /// # Errors
    ///
    /// Returns an error if the path cannot be bound, if the path exists and
    /// is not a socket, or if the socket cannot be made private.
    pub fn bind(
        path: &Path,
        store: Store,
        token: impl Into<String>,
    ) -> Result<QueryServer, QueryError> {
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent)?;
        }

        match fs::symlink_metadata(path) {
            Ok(metadata) if metadata.file_type().is_socket() => fs::remove_file(path)?,
            Ok(_) => {
                return Err(QueryError::Io(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    format!("'{}' exists and is not a socket", path.display()),
                )));
            }
            Err(_) => {}
        }

        let listener = UnixListener::bind(path)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;

        let token = token.into();
        let key = token_key(&token);

        Ok(QueryServer {
            listener: Arc::new(listener),
            state: Arc::new(ServerState {
                store: Mutex::new(store),
                token,
                scoped_tokens: RwLock::new(Vec::new()),
                key,
                started: Instant::now(),
                stopping: AtomicBool::new(false),
            }),
            socket_path: path.to_path_buf(),
        })
    }

    /// The path of the socket.
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    /// Give a token the right to call only some of the methods.
    ///
    /// The plugin host calls this for each plugin it starts, with the
    /// plugin's own secret and the methods its manifest asked for. A plugin
    /// presenting that secret may call those methods and no others: the
    /// method exists, but this token may not have it.
    // The daemon registers the plugins' tokens here, once the plugin host
    // is wired in. Until then nothing calls it.
    #[allow(dead_code)]
    pub fn add_token(&self, token: impl Into<String>, methods: Vec<String>) {
        let token = token.into();
        let mut tokens = match self.state.scoped_tokens.write() {
            Ok(tokens) => tokens,
            Err(poisoned) => poisoned.into_inner(),
        };
        tokens.retain(|(existing, _)| existing != &token);
        tokens.push((token, methods));
    }

    /// Ask the server to stop.
    ///
    /// The accept loop notices at its next turn. Connections that are open
    /// stay open until the client closes them.
    pub fn stop(&self) {
        self.state.stopping.store(true, Ordering::SeqCst);
    }

    /// Run the server until it is stopped.
    ///
    /// Every connection is served on a thread of its own, so a client that
    /// stops reading cannot hold the others up.
    ///
    /// # Errors
    ///
    /// Returns an error if the socket stops accepting connections.
    pub fn serve(&self) -> Result<(), QueryError> {
        self.listener.set_nonblocking(true)?;

        while !self.state.stopping.load(Ordering::SeqCst) {
            match self.listener.accept() {
                Ok((stream, _address)) => {
                    let worker = self.clone();
                    let _worker = thread::Builder::new()
                        .name("od3sa-query".to_string())
                        .spawn(move || {
                            if let Err(error) = worker.serve_connection(stream) {
                                // A client that goes away mid-request is not
                                // a failure of the server.
                                if error.kind() != io::ErrorKind::BrokenPipe {
                                    eprintln!("od3sa-recond: query connection ended: {error}");
                                }
                            }
                        });
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(20));
                }
                Err(error) => return Err(QueryError::Io(error)),
            }
        }

        Ok(())
    }

    /// Answer one line of input.
    ///
    /// Returns the response to write, or `None` when the line was a
    /// notification, which gets no response.
    pub fn handle_line(&self, line: &str) -> Option<Json> {
        self.state.handle_line(line)
    }

    /// Read the requests of one connection and answer them.
    fn serve_connection(&self, stream: UnixStream) -> io::Result<()> {
        let mut writer = stream.try_clone()?;
        let mut reader = io::BufReader::new(stream);
        let mut line = Vec::new();

        loop {
            line.clear();
            match read_line(&mut reader, &mut line)? {
                Line::EndOfFile => break,
                Line::TooLong => {
                    let response =
                        error_response(Json::Null, INVALID_REQUEST, "the request line is too long");
                    write_line(&mut writer, &response)?;
                    break;
                }
                Line::Complete => {}
            }

            let text = String::from_utf8_lossy(&line).into_owned();
            if let Some(response) = self.handle_line(&text) {
                write_line(&mut writer, &response)?;
            }
        }

        Ok(())
    }
}

/// What one read of a request line found.
enum Line {
    /// A whole line was read.
    Complete,
    /// The connection ended.
    EndOfFile,
    /// The line was longer than the server accepts.
    TooLong,
}

/// Read one line, up to [`MAX_LINE`] bytes.
///
/// A line that is too long ends the connection: the rest of it cannot be
/// trusted to be a request.
fn read_line(reader: &mut impl BufRead, buffer: &mut Vec<u8>) -> io::Result<Line> {
    loop {
        let available = match reader.fill_buf() {
            Ok(available) => available,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        };

        if available.is_empty() {
            return Ok(if buffer.is_empty() {
                Line::EndOfFile
            } else {
                Line::Complete
            });
        }

        match available.iter().position(|byte| *byte == b'\n') {
            Some(index) => {
                if buffer.len() + index > MAX_LINE {
                    return Ok(Line::TooLong);
                }
                buffer.extend_from_slice(&available[..index]);
                reader.consume(index + 1);
                return Ok(Line::Complete);
            }
            None => {
                if buffer.len() + available.len() > MAX_LINE {
                    return Ok(Line::TooLong);
                }
                let length = available.len();
                buffer.extend_from_slice(available);
                reader.consume(length);
            }
        }
    }
}

/// Write one response, on one line.
fn write_line(writer: &mut impl Write, response: &Json) -> io::Result<()> {
    let text = serde_json::to_string(response)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    writer.write_all(text.as_bytes())?;
    writer.write_all(b"\n")?;
    writer.flush()
}

/// Build an error response.
fn error_response(id: Json, code: i64, message: &str) -> Json {
    json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}})
}

/// Check that a statement only reads.
///
/// The server runs `SELECT`s and two read-only `PRAGMA`s that report the
/// size of the database. Anything else is refused, so a mistake in the SQL
/// this module builds cannot write.
fn read_only(sql: &str) -> Result<&str, RpcError> {
    let trimmed = sql.trim_start();
    let keyword = trimmed
        .split_whitespace()
        .next()
        .unwrap_or_default()
        .to_ascii_uppercase();

    if keyword == "SELECT" {
        return Ok(sql);
    }

    if keyword == "PRAGMA" {
        let name = trimmed[6..]
            .split_whitespace()
            .next()
            .unwrap_or_default()
            .to_ascii_lowercase();
        if name == "page_count" || name == "page_size" {
            return Ok(sql);
        }
    }

    Err(RpcError::new(
        DATABASE_ERROR,
        "the query server only runs read-only statements",
    ))
}

/// Generate a token for the query socket.
///
/// The bytes come from the kernel's random device, so the token is not
/// guessable. The caller writes it to the log once.
pub fn generate_token() -> Result<String, QueryError> {
    use std::io::Read;

    let mut bytes = [0u8; 24];
    let mut source = fs::File::open("/dev/urandom")?;
    source.read_exact(&mut bytes)?;
    Ok(hex(&bytes))
}

/// The token as a hexadecimal string.
fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// The bytes of a hexadecimal string, if it is one.
fn unhex(text: &str) -> Option<Vec<u8>> {
    if !text.is_ascii() || !text.len().is_multiple_of(2) {
        return None;
    }
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 2);
    let mut index = 0;
    while index < bytes.len() {
        let high = (bytes[index] as char).to_digit(16)?;
        let low = (bytes[index + 1] as char).to_digit(16)?;
        out.push(((high << 4) | low) as u8);
        index += 2;
    }
    Some(out)
}

/// The key the cursor checksum is keyed with, derived from the token.
fn token_key(token: &str) -> u64 {
    keyed_hash(0xcbf2_9ce4_8422_2325, token.as_bytes())
}

/// A keyed checksum.
///
/// This is not a cryptographic message authentication code: it stops a
/// caller from editing a cursor by hand. A caller that holds the token can
/// forge one, but a caller that holds the token may already call the method
/// the cursor belongs to.
fn keyed_hash(key: u64, payload: &[u8]) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325 ^ key;
    for byte in payload {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

/// Encode a cursor.
///
/// The cursor carries the method it belongs to and the sort key of the last
/// row of the page, so that a caller cannot read it as something else.
fn encode_cursor(method: &str, parts: &[i64], key: u64) -> String {
    let values = parts
        .iter()
        .map(|part| part.to_string())
        .collect::<Vec<_>>()
        .join(",");
    let payload = format!("{method}\u{1}{values}");
    let checksum = keyed_hash(key, payload.as_bytes());
    format!(
        "v1.{}.{}",
        hex(payload.as_bytes()),
        hex(&checksum.to_be_bytes())
    )
}

/// Decode a cursor, and check that it belongs to this method.
fn decode_cursor(method: &str, cursor: &str, key: u64) -> Result<Vec<i64>, RpcError> {
    let mut fields = cursor.split('.');
    let version = fields.next().unwrap_or_default();
    let payload = fields.next().unwrap_or_default();
    let checksum = fields.next().unwrap_or_default();
    if version != "v1" || fields.next().is_some() {
        return Err(RpcError::new(INVALID_PARAMS, "the cursor is not valid"));
    }

    let payload =
        unhex(payload).ok_or_else(|| RpcError::new(INVALID_PARAMS, "the cursor is not valid"))?;
    let checksum =
        unhex(checksum).ok_or_else(|| RpcError::new(INVALID_PARAMS, "the cursor is not valid"))?;
    let checksum: [u8; 8] = checksum
        .try_into()
        .map_err(|_| RpcError::new(INVALID_PARAMS, "the cursor is not valid"))?;

    if keyed_hash(key, &payload) != u64::from_be_bytes(checksum) {
        return Err(RpcError::new(INVALID_PARAMS, "the cursor is not valid"));
    }

    let text = String::from_utf8(payload)
        .map_err(|_| RpcError::new(INVALID_PARAMS, "the cursor is not valid"))?;
    let mut fields = text.split('\u{1}');
    let cursor_method = fields.next().unwrap_or_default();
    let values = fields.next().unwrap_or_default();

    if cursor_method != method {
        return Err(RpcError::new(
            INVALID_PARAMS,
            "the cursor belongs to another method",
        ));
    }

    values
        .split(',')
        .map(|value| {
            value
                .parse::<i64>()
                .map_err(|_| RpcError::new(INVALID_PARAMS, "the cursor is not valid"))
        })
        .collect()
}

/// The sort key of a row, as the cursor carries it.
fn sort_parts(rows: &Rows, index: usize, count: usize) -> Vec<i64> {
    (0..count)
        .map(|part| integer_of(rows, index, &format!("sort_{part}")).unwrap_or(0))
        .collect()
}

/// The sort key a cursor must have, for one method.
fn cursor_values(parts: &[i64], expected: usize) -> Result<Vec<i64>, RpcError> {
    if parts.len() != expected {
        return Err(RpcError::new(
            INVALID_PARAMS,
            "the cursor belongs to another method",
        ));
    }
    Ok(parts.to_vec())
}

/// Build the response of a list method: the items and the next cursor.
///
/// `sort_columns` is how many sort columns the statement of the method
/// carries; the cursor holds all of them.
fn page_response(
    rows: &Rows,
    limit: usize,
    method: &str,
    key: u64,
    sort_columns: usize,
    item: impl Fn(usize) -> Json,
) -> Json {
    let count = rows.len();
    let taken = count.min(limit);
    let items: Vec<Json> = (0..taken).map(item).collect();

    let next_cursor = if count > limit && taken > 0 {
        let parts = sort_parts(rows, taken - 1, sort_columns);
        Json::String(encode_cursor(method, &parts, key))
    } else {
        Json::Null
    };

    json!({"items": items, "next_cursor": next_cursor})
}

/// A parameter that is a string, if it is there.
fn param_str<'a>(params: &'a Map<String, Json>, name: &str) -> Option<&'a str> {
    params.get(name).and_then(Json::as_str)
}

/// A parameter that is an integer, if it is there.
fn param_int(params: &Map<String, Json>, name: &str) -> Result<Option<i64>, RpcError> {
    match params.get(name) {
        None | Some(Json::Null) => Ok(None),
        Some(value) => value
            .as_i64()
            .map(Some)
            .ok_or_else(|| RpcError::new(INVALID_PARAMS, format!("'{name}' must be an integer"))),
    }
}

/// The number of rows the caller asks for.
///
/// The caller may ask for at most [`MAX_LIMIT`]; a larger number is clamped
/// rather than refused.
fn param_limit(params: &Map<String, Json>) -> Result<usize, RpcError> {
    let limit = match params.get("limit") {
        None | Some(Json::Null) => DEFAULT_LIMIT as u64,
        Some(value) => value
            .as_u64()
            .ok_or_else(|| RpcError::new(INVALID_PARAMS, "'limit' must be a number"))?,
    };
    if limit == 0 {
        return Err(RpcError::new(INVALID_PARAMS, "'limit' must be at least 1"));
    }
    Ok(limit.min(MAX_LIMIT as u64) as usize)
}

/// A MAC address, lower case and checked.
fn normalize_mac(mac: &str) -> Result<String, RpcError> {
    let trimmed = mac.trim().to_ascii_lowercase();
    let bytes = trimmed.as_bytes();
    if bytes.len() != 17 {
        return Err(RpcError::new(
            INVALID_PARAMS,
            "'mac' must look like aa:bb:cc:dd:ee:ff",
        ));
    }
    for (index, byte) in bytes.iter().enumerate() {
        let good = match index % 3 {
            2 => *byte == b':',
            _ => byte.is_ascii_hexdigit(),
        };
        if !good {
            return Err(RpcError::new(
                INVALID_PARAMS,
                "'mac' must look like aa:bb:cc:dd:ee:ff",
            ));
        }
    }
    Ok(trimmed)
}

/// The value of a column, as text.
fn text_of(rows: &Rows, index: usize, column: &str) -> Option<String> {
    rows.get(index, column)
        .and_then(|value| value.as_str())
        .map(str::to_string)
}

/// The value of a column, as an integer.
fn integer_of(rows: &Rows, index: usize, column: &str) -> Option<i64> {
    rows.get(index, column).and_then(|value| value.as_integer())
}

/// The value of a column, as a floating point number.
///
/// SQLite is dynamically typed, so a column declared `REAL` may hold an
/// integer.
fn real_of(rows: &Rows, index: usize, column: &str) -> Option<f64> {
    match rows.get(index, column) {
        Some(Value::Real(number)) => Some(*number),
        Some(Value::Integer(number)) => Some(*number as f64),
        _ => None,
    }
}

/// The value of a column, as a flag.
fn flag_of(rows: &Rows, index: usize, column: &str) -> bool {
    integer_of(rows, index, column).unwrap_or(0) != 0
}

/// The MAC address of a row, lower case.
///
/// The column it is in is named: a device has a `mac`, an access point a
/// `bssid` and a client row both a `client` and a `bssid`.
fn mac_of(rows: &Rows, index: usize, column: &str) -> Option<String> {
    text_of(rows, index, column).map(|mac| mac.to_ascii_lowercase())
}

/// The SSID of a row.
///
/// The schema keeps the SSID as a blob. Bytes that are not valid UTF-8 are
/// decoded with the replacement character, never dropped.
fn ssid_of(rows: &Rows, index: usize, column: &str) -> Option<String> {
    match rows.get(index, column) {
        Some(Value::Blob(bytes)) => Some(String::from_utf8_lossy(bytes).into_owned()),
        Some(Value::Text(text)) => Some(text.clone()),
        _ => None,
    }
}

/// Whether an access point requires protected management frames.
fn pmf_required(rows: &Rows, index: usize) -> bool {
    match text_of(rows, index, "pmf") {
        Some(pmf) => pmf.trim().eq_ignore_ascii_case("required"),
        None => false,
    }
}

/// One device, as the API reports it.
fn device_item(rows: &Rows, index: usize) -> Json {
    json!({
        "mac": mac_of(rows, index, "mac"),
        "kind": text_of(rows, index, "kind"),
        "oui": text_of(rows, index, "oui"),
        "randomized": flag_of(rows, index, "randomized"),
        "first_seen_ms": integer_of(rows, index, "first_seen_ms"),
        "last_seen_ms": integer_of(rows, index, "last_seen_ms"),
        "max_rssi": integer_of(rows, index, "max_rssi"),
        "last_rssi": integer_of(rows, index, "last_rssi"),
    })
}

/// One access point, as the API reports it.
fn ap_item(rows: &Rows, index: usize) -> Json {
    json!({
        "bssid": mac_of(rows, index, "bssid"),
        "ssid": ssid_of(rows, index, "ssid"),
        "ssid_hidden": flag_of(rows, index, "ssid_hidden"),
        "channel": integer_of(rows, index, "channel"),
        "freq_mhz": integer_of(rows, index, "freq_mhz"),
        "band": text_of(rows, index, "band"),
        "security": text_of(rows, index, "security"),
        "akm": text_of(rows, index, "akm"),
        "pairwise": text_of(rows, index, "pairwise"),
        "group_cipher": text_of(rows, index, "group_cipher"),
        "pmf_required": pmf_required(rows, index),
        "wps": flag_of(rows, index, "wps"),
        "ht": flag_of(rows, index, "ht"),
        "vht": flag_of(rows, index, "vht"),
        "he": flag_of(rows, index, "he"),
        "vendor_ies": text_of(rows, index, "vendor_ies"),
        "beacon_int": integer_of(rows, index, "beacon_int"),
        "last_beacon_ms": integer_of(rows, index, "last_beacon_ms"),
    })
}

/// One Bluetooth device, as the API reports it.
fn ble_item(rows: &Rows, index: usize) -> Json {
    json!({
        "mac": mac_of(rows, index, "mac"),
        "kind": text_of(rows, index, "kind"),
        "oui": text_of(rows, index, "oui"),
        "randomized": flag_of(rows, index, "randomized"),
        "first_seen_ms": integer_of(rows, index, "first_seen_ms"),
        "last_seen_ms": integer_of(rows, index, "last_seen_ms"),
        "max_rssi": integer_of(rows, index, "max_rssi"),
        "last_rssi": integer_of(rows, index, "last_rssi"),
        "name": text_of(rows, index, "name"),
        "addr_type": text_of(rows, index, "addr_type"),
        "manufacturer_id": integer_of(rows, index, "manufacturer_id"),
        "services": text_of(rows, index, "services"),
        "tx_power": integer_of(rows, index, "tx_power"),
        "source": text_of(rows, index, "source"),
    })
}

/// The resident set size of this process, in kilobytes.
fn resident_kb() -> i64 {
    let status = match fs::read_to_string("/proc/self/status") {
        Ok(status) => status,
        Err(_) => return 0,
    };
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("VmRSS:") {
            let digits: String = rest
                .trim()
                .chars()
                .take_while(char::is_ascii_digit)
                .collect();
            return digits.parse::<i64>().unwrap_or(0);
        }
    }
    0
}
