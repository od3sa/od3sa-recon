//! The batched writer.
//!
//! The aggregator turns frames into observations. This module puts those
//! observations into the database, in batches, and applies the retention and
//! rotation rules of `docs/SCHEMA.md`.
//!
//! # Batched
//!
//! The observations wait in memory and are written in one transaction, so a
//! busy channel does not mean a transaction per frame. The batch is flushed
//! when it is full or when the interval has passed.
//!
//! # Resolved, not duplicated
//!
//! `devices.mac` and `ssids.ssid` are UNIQUE. The writer resolves a MAC to
//! its row id and an SSID to its row id before it inserts anything that
//! refers to it, so the same beacon seen a hundred times leaves one device
//! row and one SSID row.
//!
//! # Metadata only
//!
//! Every write is in the schema of `docs/SCHEMA.md` and nowhere else. There
//! is no column for a frame payload and no side table for one: nothing this
//! module writes holds a payload or an EAPOL body.

use std::path::{Path, PathBuf};
use std::time::Instant;

use rusqlite::Connection;

use crate::aggregator::Observation;
use crate::{Store, StoreError};

/// The width of a sighting bucket, in milliseconds.
///
/// A sighting row holds a count and an average, so the rows are bucketed by
/// time: one row per device, per source, per minute.
pub const SIGHTING_BUCKET_MS: i64 = 60_000;

/// The number of milliseconds in a day.
const MS_PER_DAY: i64 = 86_400_000;

/// The kind a `sources` row gets when the writer resolves one.
///
/// The aggregator only ever sees 802.11 frames, so every source it names is
/// a capture source.
const SOURCE_KIND: &str = "pcap";

/// Writes observations to the database, in batches.
#[derive(Debug)]
pub struct Writer {
    /// The database the observations go into.
    store: Store,
    /// The observations waiting to be written.
    pending: Vec<Observation>,
    /// The batch is flushed once it holds this many observations.
    batch_size: usize,
    /// The batch is flushed at least this often, in milliseconds.
    flush_interval_ms: u64,
    /// When the last flush happened.
    last_flush: Instant,
}

impl Writer {
    /// A writer over `store` that flushes at most every `flush_interval_ms`
    /// and at most every `batch_size` observations.
    pub fn new(store: Store, flush_interval_ms: u64, batch_size: usize) -> Writer {
        Writer {
            store,
            pending: Vec::new(),
            batch_size: batch_size.max(1),
            flush_interval_ms,
            last_flush: Instant::now(),
        }
    }

    /// The database the writer writes into.
    pub fn store(&self) -> &Store {
        &self.store
    }

    /// Add one observation to the batch.
    ///
    /// The batch is flushed when it is full or when the flush interval has
    /// passed, so a busy channel does not mean a transaction per frame.
    ///
    /// # Errors
    ///
    /// Returns an error if the batch had to be flushed and the flush failed.
    /// The observation is kept in the batch in that case.
    pub fn write(&mut self, observation: &Observation) -> Result<(), StoreError> {
        self.pending.push(observation.clone());

        let full = self.pending.len() >= self.batch_size;
        let due = self.last_flush.elapsed().as_millis() as u64 >= self.flush_interval_ms;
        if full || due {
            self.flush()?;
        }
        Ok(())
    }

    /// Write everything pending, in one transaction.
    ///
    /// Returns how many observations were written.
    ///
    /// # Errors
    ///
    /// Returns an error if the transaction fails. The observations are kept
    /// in the batch, so nothing is lost.
    pub fn flush(&mut self) -> Result<usize, StoreError> {
        if self.pending.is_empty() {
            self.last_flush = Instant::now();
            return Ok(0);
        }

        let batch = std::mem::take(&mut self.pending);
        match write_batch(self.store.connection(), &batch) {
            Ok(()) => {
                self.last_flush = Instant::now();
                Ok(batch.len())
            }
            Err(error) => {
                // Nothing is lost: the observations go back into the batch.
                self.pending = batch;
                Err(error)
            }
        }
    }

    /// Write an alert into the `alerts` table.
    ///
    /// The device it is about is resolved the same way an observation's is,
    /// so the alert points at the same row the sighting does.
    pub fn write_alert(&mut self, alert: &AlertRow) -> Result<i64, StoreError> {
        let conn = self.store.connection();
        write_alert_row(conn, alert)
    }

    /// How many observations are waiting to be written.
    pub fn pending(&self) -> usize {
        self.pending.len()
    }

    /// Apply the retention rules: delete sightings older than `max_age_days`,
    /// and rotate the database if it is over `max_bytes`.
    ///
    /// The pending batch is flushed first, so the retention pass sees every
    /// observation that has been made.
    ///
    /// # Errors
    ///
    /// Returns an error if the flush or the database work fails.
    pub fn apply_retention(
        &mut self,
        now_ms: i64,
        max_age_days: i64,
        max_bytes: u64,
    ) -> Result<Retention, StoreError> {
        self.flush()?;

        let cutoff = now_ms.saturating_sub(max_age_days.saturating_mul(MS_PER_DAY));
        let deleted = self
            .store
            .connection()
            .execute("DELETE FROM sightings WHERE bucket_ms < ?1", [cutoff])?;

        let rotated_to = match self.store.path() {
            Some(path) if file_size(path)? > max_bytes => {
                Some(self.rotate(path.to_path_buf(), now_ms)?)
            }
            _ => None,
        };

        Ok(Retention {
            sightings_deleted: deleted as u64,
            rotated_to,
        })
    }

    /// Close the batch and the database.
    ///
    /// # Errors
    ///
    /// Returns an error if the pending batch could not be written or the
    /// database could not be closed.
    pub fn close(mut self) -> Result<(), StoreError> {
        self.flush()?;
        self.store.close()
    }

    /// Rotate the database.
    ///
    /// The old rows go into a new file next to the database, named
    /// `recon-YYYYMMDD.sqlite`, and the live database is left empty at the
    /// current schema version.
    fn rotate(&mut self, path: PathBuf, now_ms: i64) -> Result<PathBuf, StoreError> {
        let directory = path.parent().unwrap_or_else(|| Path::new("."));

        let (year, month, day) = civil_date(now_ms);
        let base = format!("recon-{year:04}{month:02}{day:02}.sqlite");
        let target = unique_path(directory, &base);

        // The old rows are copied into the new file, compacted.
        self.store.connection().execute_batch(&format!(
            "VACUUM INTO '{}'",
            quote(&target.to_string_lossy())
        ))?;

        // The live database is left empty, at the current schema version.
        clear_tables(self.store.connection())?;
        self.store.connection().execute_batch("VACUUM")?;

        Ok(target)
    }
}

/// What the retention pass did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Retention {
    /// How many sighting rows were deleted.
    pub sightings_deleted: u64,
    /// The rotated file, if the database was rotated.
    pub rotated_to: Option<PathBuf>,
}

/// Write a batch of observations, in one transaction.
fn write_batch(conn: &Connection, batch: &[Observation]) -> Result<(), StoreError> {
    let tx = conn.unchecked_transaction()?;
    for observation in batch {
        write_observation(&tx, observation)?;
    }
    tx.commit()?;
    Ok(())
}

/// The position a sighting may carry.
///
/// The Pager may have no GPS at all, so every field is optional.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct Position {
    /// The latitude in degrees.
    pub lat: Option<f64>,
    /// The longitude in degrees.
    pub lon: Option<f64>,
    /// The altitude in metres.
    pub alt: Option<f64>,
    /// The fix mode: 1 none, 2 two-dimensional, 3 three-dimensional.
    pub fix: Option<u8>,
}

/// A row for the `alerts` table.
///
/// The store owns the shape of the row, so the rules engine does not have to
/// be a dependency of this crate: the collector maps its alert onto one of
/// these.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlertRow {
    /// When it was raised, in unix epoch milliseconds.
    pub ts_ms: i64,
    /// Which rule raised it.
    pub rule: String,
    /// How serious it is: "info", "warning" or "critical".
    pub severity: String,
    /// The device it is about, when it is about one.
    pub mac: Option<[u8; 6]>,
    /// A short line for a human.
    pub summary: String,
    /// Anything else worth keeping, as JSON text.
    pub details: Option<String>,
}

/// Write one observation.
fn write_observation(conn: &Connection, observation: &Observation) -> Result<(), StoreError> {
    let ts_ms = observation_ts(observation);

    // The devices the observation is about.
    //
    // A signal level belongs to the device that was actually seen, so it
    // travels with the sighting: the other devices of the same observation
    // are mentioned, not measured.
    let mut devices: Vec<DeviceEntry> = Vec::new();
    if let Some(device) = &observation.device {
        devices.push(DeviceEntry {
            mac: device.mac,
            kind: device.kind,
            ts_ms,
            rssi: None,
        });
    }
    if let Some(access_point) = &observation.access_point {
        devices.push(DeviceEntry {
            mac: access_point.bssid,
            kind: "ap",
            ts_ms,
            rssi: None,
        });
    }
    if let Some(probe) = &observation.probe {
        devices.push(DeviceEntry {
            mac: probe.mac,
            kind: "client",
            ts_ms: probe.ts_ms,
            rssi: probe.rssi,
        });
    }
    if let Some(client) = &observation.client {
        devices.push(DeviceEntry {
            mac: client.mac,
            kind: "client",
            ts_ms: client.ts_ms,
            rssi: client.rssi,
        });
        devices.push(DeviceEntry {
            mac: client.bssid,
            kind: "ap",
            ts_ms: client.ts_ms,
            rssi: None,
        });
    }
    if let Some(sighting) = &observation.sighting {
        devices.push(DeviceEntry {
            mac: sighting.mac,
            kind: "unknown",
            ts_ms: sighting.ts_ms,
            rssi: sighting.rssi,
        });
    }

    // The SSIDs the observation is about.
    let mut ssids: Vec<(&[u8], bool)> = Vec::new();
    if let Some(access_point) = &observation.access_point
        && let Some(ssid) = &access_point.ssid
    {
        ssids.push((ssid.as_slice(), access_point.ssid_hidden));
    }
    if let Some(probe) = &observation.probe {
        ssids.push((probe.ssid.as_slice(), false));
    }

    // The devices are resolved first: everything else refers to them. The
    // same MAC can show up more than once, so the entries are merged per MAC:
    // the more specific kind wins, and a signal level is kept if there is one.
    let mut device_ids: Vec<([u8; 6], &'static str, i64)> = Vec::new();
    for entry in devices {
        let merged = match device_ids.iter_mut().find(|(mac, _, _)| *mac == entry.mac) {
            Some((_, existing, _)) => {
                if kind_rank(entry.kind) > kind_rank(existing) {
                    *existing = entry.kind;
                }
                *existing
            }
            None => entry.kind,
        };
        let id = resolve_device(conn, entry.mac, merged, entry.ts_ms, entry.rssi)?;
        match device_ids.iter_mut().find(|(mac, _, _)| *mac == entry.mac) {
            Some(found) => found.2 = id,
            None => device_ids.push((entry.mac, merged, id)),
        }
    }

    let mut ssid_ids: Vec<(&[u8], bool, i64)> = Vec::new();
    for (ssid, hidden) in ssids {
        let id = resolve_ssid(conn, ssid, hidden)?;
        ssid_ids.push((ssid, hidden, id));
    }

    let device_id = |mac: [u8; 6]| -> Option<i64> {
        device_ids
            .iter()
            .find(|(entry, _, _)| *entry == mac)
            .map(|(_, _, id)| *id)
    };
    let ssid_id = |ssid: &[u8]| -> Option<i64> {
        ssid_ids
            .iter()
            .find(|(entry, _, _)| *entry == ssid)
            .map(|(_, _, id)| *id)
    };

    if let Some(access_point) = &observation.access_point
        && let Some(device_id) = device_id(access_point.bssid)
    {
        let ssid_id = access_point
            .ssid
            .as_ref()
            .and_then(|ssid| ssid_id(ssid.as_slice()));
        upsert_access_point(conn, device_id, ssid_id, access_point, ts_ms)?;
    }

    if let Some(probe) = &observation.probe
        && let (Some(device_id), Some(ssid_id)) = (device_id(probe.mac), ssid_id(&probe.ssid))
    {
        upsert_probe(conn, device_id, ssid_id, probe.ts_ms)?;
    }

    if let Some(client) = &observation.client
        && let (Some(device_id), Some(bssid_id)) = (device_id(client.mac), device_id(client.bssid))
    {
        upsert_client(conn, device_id, bssid_id, client.ts_ms)?;
    }

    if let Some(sighting) = &observation.sighting
        && let Some(device_id) = device_id(sighting.mac)
    {
        let source_id = resolve_source(conn, sighting.source, sighting.ts_ms)?;
        upsert_sighting(
            conn,
            device_id,
            source_id,
            sighting.ts_ms,
            sighting.rssi,
            sighting.channel,
            Position {
                lat: sighting.lat,
                lon: sighting.lon,
                alt: sighting.alt,
                fix: sighting.fix,
            },
        )?;
        count_source_frame(conn, source_id, sighting.ts_ms)?;
    }

    Ok(())
}

/// The time an observation was made.
fn observation_ts(observation: &Observation) -> i64 {
    if let Some(sighting) = &observation.sighting {
        return sighting.ts_ms;
    }
    if let Some(probe) = &observation.probe {
        return probe.ts_ms;
    }
    if let Some(client) = &observation.client {
        return client.ts_ms;
    }
    0
}

/// One device an observation mentions, with the signal level of it, if the
/// observation measured that device.
struct DeviceEntry {
    /// The six byte MAC address.
    mac: [u8; 6],
    /// The kind of device.
    kind: &'static str,
    /// When it was seen, in unix epoch milliseconds.
    ts_ms: i64,
    /// The signal level in dBm, if the device was measured.
    rssi: Option<i8>,
}

/// How specific a device kind is.
fn kind_rank(kind: &str) -> u8 {
    match kind {
        "ap" => 3,
        "ble" => 2,
        "client" => 1,
        _ => 0,
    }
}

/// Write one alert row.
fn write_alert_row(conn: &Connection, alert: &AlertRow) -> Result<i64, StoreError> {
    let device_id = match alert.mac {
        Some(mac) => Some(resolve_device(conn, mac, "unknown", alert.ts_ms, None)?),
        None => None,
    };

    conn.execute(
        "INSERT INTO alerts (ts_ms, rule, severity, device_id, summary, details)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        rusqlite::params![
            alert.ts_ms,
            alert.rule,
            alert.severity,
            device_id,
            alert.summary,
            alert.details,
        ],
    )?;

    let id: i64 = conn.query_row("SELECT last_insert_rowid()", [], |row| row.get(0))?;
    Ok(id)
}

/// Resolve a MAC address to its row id, inserting the device if it is new.
fn resolve_device(
    conn: &Connection,
    mac: [u8; 6],
    kind: &str,
    ts_ms: i64,
    rssi: Option<i8>,
) -> Result<i64, StoreError> {
    let text = mac_to_text(mac);
    let oui = format!("{:02x}:{:02x}:{:02x}", mac[0], mac[1], mac[2]);
    let randomized = i64::from(mac[0] & 0b1100_0000 == 0b1100_0000);
    let rssi_value = rssi.map(i64::from);

    conn.execute(
        "INSERT INTO devices (mac, oui, kind, randomized, first_seen_ms, last_seen_ms, max_rssi, last_rssi)
         VALUES (?1, ?2, ?3, ?4, ?5, ?5, ?6, ?6)
         ON CONFLICT(mac) DO UPDATE SET
           last_seen_ms = MAX(devices.last_seen_ms, excluded.last_seen_ms),
           max_rssi = MAX(COALESCE(devices.max_rssi, excluded.max_rssi), COALESCE(excluded.max_rssi, devices.max_rssi)),
           last_rssi = COALESCE(excluded.last_rssi, devices.last_rssi),
           kind = CASE
             WHEN excluded.kind = 'ap' AND devices.kind IN ('unknown', 'client', 'ble') THEN 'ap'
             WHEN excluded.kind = 'ble' AND devices.kind IN ('unknown', 'client') THEN 'ble'
             WHEN excluded.kind = 'client' AND devices.kind = 'unknown' THEN 'client'
             ELSE devices.kind END",
        rusqlite::params![text, oui, kind, randomized, ts_ms, rssi_value],
    )?;

    let id: i64 = conn.query_row("SELECT id FROM devices WHERE mac = ?1", [text], |row| {
        row.get(0)
    })?;
    Ok(id)
}

/// Resolve an SSID to its row id, inserting it if it is new.
fn resolve_ssid(conn: &Connection, ssid: &[u8], hidden: bool) -> Result<i64, StoreError> {
    conn.execute(
        "INSERT INTO ssids (ssid, hidden) VALUES (?1, ?2) ON CONFLICT(ssid) DO NOTHING",
        rusqlite::params![ssid, i64::from(hidden)],
    )?;

    let id: i64 = conn.query_row("SELECT id FROM ssids WHERE ssid = ?1", [ssid], |row| {
        row.get(0)
    })?;
    Ok(id)
}

/// Resolve a source name to its row id, inserting it if it is new.
fn resolve_source(conn: &Connection, name: &str, ts_ms: i64) -> Result<i64, StoreError> {
    conn.execute(
        "INSERT INTO sources (name, kind, last_seen_ms, frames) VALUES (?1, ?2, ?3, 0)
         ON CONFLICT(name) DO NOTHING",
        rusqlite::params![name, SOURCE_KIND, ts_ms],
    )?;

    let id: i64 = conn.query_row("SELECT id FROM sources WHERE name = ?1", [name], |row| {
        row.get(0)
    })?;
    Ok(id)
}

/// Count one more frame on a source.
fn count_source_frame(conn: &Connection, source_id: i64, ts_ms: i64) -> Result<(), StoreError> {
    conn.execute(
        "UPDATE sources SET frames = frames + 1, last_seen_ms = MAX(last_seen_ms, ?2) WHERE id = ?1",
        rusqlite::params![source_id, ts_ms],
    )?;
    Ok(())
}

/// Write the row of an access point.
fn upsert_access_point(
    conn: &Connection,
    device_id: i64,
    ssid_id: Option<i64>,
    access_point: &crate::aggregator::AccessPoint,
    ts_ms: i64,
) -> Result<(), StoreError> {
    let pmf = if access_point.pmf_required {
        "required"
    } else {
        "optional"
    };

    conn.execute(
        "INSERT INTO access_points
           (device_id, ssid_id, channel, freq_mhz, band, security, akm, pairwise, group_cipher,
            pmf, wps, ht, vht, he, vendor_ies, beacon_int, last_beacon_ms)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, NULL, ?15, ?16)
         ON CONFLICT(device_id) DO UPDATE SET
           ssid_id = COALESCE(excluded.ssid_id, access_points.ssid_id),
           channel = COALESCE(excluded.channel, access_points.channel),
           freq_mhz = COALESCE(excluded.freq_mhz, access_points.freq_mhz),
           band = COALESCE(excluded.band, access_points.band),
           security = COALESCE(excluded.security, access_points.security),
           akm = COALESCE(excluded.akm, access_points.akm),
           pairwise = COALESCE(excluded.pairwise, access_points.pairwise),
           group_cipher = COALESCE(excluded.group_cipher, access_points.group_cipher),
           pmf = COALESCE(excluded.pmf, access_points.pmf),
           wps = MAX(access_points.wps, excluded.wps),
           ht = MAX(access_points.ht, excluded.ht),
           vht = MAX(access_points.vht, excluded.vht),
           he = MAX(access_points.he, excluded.he),
           beacon_int = COALESCE(excluded.beacon_int, access_points.beacon_int),
           last_beacon_ms = MAX(access_points.last_beacon_ms, excluded.last_beacon_ms)",
        rusqlite::params![
            device_id,
            ssid_id,
            access_point.channel.map(i64::from),
            access_point.freq_mhz.map(i64::from),
            access_point.band,
            access_point.security,
            access_point.akm,
            access_point.pairwise,
            access_point.group_cipher,
            pmf,
            i64::from(access_point.wps),
            i64::from(access_point.ht),
            i64::from(access_point.vht),
            i64::from(access_point.he),
            access_point.beacon_interval.map(i64::from),
            ts_ms,
        ],
    )?;
    Ok(())
}

/// Write the row of a client of an access point.
fn upsert_client(
    conn: &Connection,
    device_id: i64,
    bssid_id: i64,
    ts_ms: i64,
) -> Result<(), StoreError> {
    conn.execute(
        "INSERT INTO clients (device_id, bssid_device_id, first_seen_ms, last_seen_ms)
         VALUES (?1, ?2, ?3, ?3)
         ON CONFLICT(device_id, bssid_device_id) DO UPDATE SET
           last_seen_ms = MAX(clients.last_seen_ms, excluded.last_seen_ms)",
        rusqlite::params![device_id, bssid_id, ts_ms],
    )?;
    Ok(())
}

/// Write the row of a probe.
fn upsert_probe(
    conn: &Connection,
    device_id: i64,
    ssid_id: i64,
    ts_ms: i64,
) -> Result<(), StoreError> {
    conn.execute(
        "INSERT INTO probes (device_id, ssid_id, first_seen_ms, last_seen_ms, count)
         VALUES (?1, ?2, ?3, ?3, 1)
         ON CONFLICT(device_id, ssid_id) DO UPDATE SET
           last_seen_ms = MAX(probes.last_seen_ms, excluded.last_seen_ms),
           count = probes.count + 1",
        rusqlite::params![device_id, ssid_id, ts_ms],
    )?;
    Ok(())
}

/// Write the row of a sighting.
fn upsert_sighting(
    conn: &Connection,
    device_id: i64,
    source_id: i64,
    ts_ms: i64,
    rssi: Option<i8>,
    channel: Option<u16>,
    position: Position,
) -> Result<(), StoreError> {
    let Position { lat, lon, alt, fix } = position;
    let bucket_ms = ts_ms.div_euclid(SIGHTING_BUCKET_MS) * SIGHTING_BUCKET_MS;
    let rssi_value = rssi.map(i64::from);

    conn.execute(
        "INSERT INTO sightings (device_id, source_id, bucket_ms, n, rssi_min, rssi_max, rssi_avg, channel, lat, lon, alt, fix)
         VALUES (?1, ?2, ?3, 1, ?4, ?4, ?4, ?5, ?6, ?7, ?8, ?9)
         ON CONFLICT(device_id, source_id, bucket_ms) DO UPDATE SET
           n = sightings.n + 1,
           rssi_min = MIN(COALESCE(sightings.rssi_min, excluded.rssi_min), COALESCE(excluded.rssi_min, sightings.rssi_min)),
           rssi_max = MAX(COALESCE(sightings.rssi_max, excluded.rssi_max), COALESCE(excluded.rssi_max, sightings.rssi_max)),
           rssi_avg = CASE
             WHEN sightings.rssi_avg IS NULL THEN excluded.rssi_avg
             WHEN excluded.rssi_avg IS NULL THEN sightings.rssi_avg
             ELSE (sightings.rssi_avg * sightings.n + excluded.rssi_avg) / (sightings.n + 1) END,
           channel = COALESCE(excluded.channel, sightings.channel),
           lat = COALESCE(excluded.lat, sightings.lat),
           lon = COALESCE(excluded.lon, sightings.lon),
           alt = COALESCE(excluded.alt, sightings.alt),
           fix = COALESCE(excluded.fix, sightings.fix)",
        rusqlite::params![
            device_id,
            source_id,
            bucket_ms,
            rssi_value,
            channel.map(i64::from),
            lat,
            lon,
            alt,
            fix.map(i64::from),
        ],
    )?;
    Ok(())
}

/// Empty every table of the database, except the schema itself.
///
/// The order matters: the tables that refer to other tables go first.
fn clear_tables(conn: &Connection) -> Result<(), StoreError> {
    conn.execute_batch(
        "DELETE FROM sightings;
         DELETE FROM probes;
         DELETE FROM clients;
         DELETE FROM access_points;
         DELETE FROM ble_devices;
         DELETE FROM alerts;
         DELETE FROM devices;
         DELETE FROM ssids;",
    )?;
    Ok(())
}

/// The size of a database file, with its write-ahead log.
fn file_size(path: &Path) -> Result<u64, StoreError> {
    let mut size = std::fs::metadata(path).map(|meta| meta.len()).unwrap_or(0);

    let mut wal = path.as_os_str().to_os_string();
    wal.push("-wal");
    if let Ok(meta) = std::fs::metadata(PathBuf::from(wal)) {
        size += meta.len();
    }

    Ok(size)
}

/// A path next to the database that does not exist yet.
///
/// The rotation file is named `recon-YYYYMMDD.sqlite`. A second rotation on
/// the same day gets a number, so that the first one is not overwritten.
fn unique_path(directory: &Path, base: &str) -> PathBuf {
    let candidate = directory.join(base);
    if !candidate.exists() {
        return candidate;
    }

    let stem = base.strip_suffix(".sqlite").unwrap_or(base);
    for index in 1..1000 {
        let candidate = directory.join(format!("{stem}-{index}.sqlite"));
        if !candidate.exists() {
            return candidate;
        }
    }

    directory.join(format!("{stem}-999.sqlite"))
}

/// Quote a string for a SQL statement.
fn quote(value: &str) -> String {
    value.replace('\'', "''")
}

/// The UTC date of a unix epoch millisecond stamp.
fn civil_date(now_ms: i64) -> (i64, u32, u32) {
    let days = now_ms.div_euclid(MS_PER_DAY);

    // The days-from-civil algorithm, in reverse.
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let day_of_era = (z - era * 146_097) as u64;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era as i64 + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = (day_of_year - (153 * month_prime + 2) / 5 + 1) as u32;
    let month = if month_prime < 10 {
        month_prime + 3
    } else {
        month_prime - 9
    } as u32;

    (if month <= 2 { year + 1 } else { year }, month, day)
}

/// A MAC address as the schema stores it: `aa:bb:cc:dd:ee:ff`.
fn mac_to_text(mac: [u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The UTC date of a stamp is the one the rotation file is named after.
    #[test]
    fn the_civil_date_is_the_utc_date() {
        // 2023-11-14T22:13:20Z, the epoch of the synthetic fixtures.
        assert_eq!(civil_date(1_700_000_000_000), (2023, 11, 14));
        // The epoch itself.
        assert_eq!(civil_date(0), (1970, 1, 1));
        // A leap day.
        assert_eq!(civil_date(1_709_164_800_000), (2024, 2, 29));
        // The first of a month.
        assert_eq!(civil_date(1_700_035_200_000), (2023, 11, 15));
    }
}
