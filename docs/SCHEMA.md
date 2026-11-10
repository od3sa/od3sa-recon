# SQLite schema (schema_version 1)

Implemented in `crates/od3sa-store`; the file `migrations/001_schema_v1.sql` is this schema, verbatim.

The database is in WAL mode, `PRAGMA foreign_keys=ON`. Times are unix epoch ms (UTC). MACs are stored as TEXT `aa:bb:cc:dd:ee:ff`. Examples use dummy values only.

The `band` column holds `2.4`, `5` or `6`. The `security` column holds a short label: `open`, `WEP`, `WPA-PSK`, `WPA2-PSK`, `WPA2-ENTERPRISE`, `WPA3-SAE`, `WPA2-PSK+WPA3-SAE` for a network in transition mode, and the like.

```sql
CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT);          -- schema_version, created_at
CREATE TABLE sessions (id INTEGER PRIMARY KEY, started_ms INT, ended_ms INT, host TEXT, fw TEXT, notes TEXT);
CREATE TABLE sources (id INTEGER PRIMARY KEY, name TEXT UNIQUE, kind TEXT,  -- 'pcap','blue5','pineapd','gps'
  iface TEXT, status TEXT, last_seen_ms INT, frames INT DEFAULT 0, errors INT DEFAULT 0);
CREATE TABLE devices (id INTEGER PRIMARY KEY, mac TEXT UNIQUE, oui TEXT, kind TEXT,  -- 'ap','client','ble','unknown'
  randomized INT, first_seen_ms INT, last_seen_ms INT, max_rssi INT, last_rssi INT, label TEXT);
CREATE TABLE ssids (id INTEGER PRIMARY KEY, ssid BLOB UNIQUE, hidden INT);
CREATE TABLE access_points (device_id INT PRIMARY KEY REFERENCES devices(id), ssid_id INT REFERENCES ssids(id),
  channel INT, freq_mhz INT, band TEXT, security TEXT, akm TEXT, pairwise TEXT, group_cipher TEXT, pmf TEXT,
  wps INT, ht INT, vht INT, he INT, vendor_ies TEXT, beacon_int INT, last_beacon_ms INT);
CREATE TABLE clients (device_id INT REFERENCES devices(id), bssid_device_id INT REFERENCES devices(id),
  first_seen_ms INT, last_seen_ms INT, PRIMARY KEY (device_id, bssid_device_id));
CREATE TABLE probes (device_id INT REFERENCES devices(id), ssid_id INT REFERENCES ssids(id),
  first_seen_ms INT, last_seen_ms INT, count INT, PRIMARY KEY (device_id, ssid_id));
CREATE TABLE ble_devices (device_id INT PRIMARY KEY REFERENCES devices(id), name TEXT, addr_type TEXT,
  manufacturer_id INT, services TEXT, tx_power INT, source TEXT);           -- from blue5 ingest
CREATE TABLE sightings (device_id INT REFERENCES devices(id), source_id INT REFERENCES sources(id),
  bucket_ms INT, n INT, rssi_min INT, rssi_max INT, rssi_avg REAL, channel INT,
  lat REAL, lon REAL, alt REAL, fix INT, PRIMARY KEY (device_id, source_id, bucket_ms));
CREATE TABLE alerts (id INTEGER PRIMARY KEY, ts_ms INT, rule TEXT, severity TEXT, device_id INT, summary TEXT, details TEXT);
CREATE INDEX sightings_bucket ON sightings(bucket_ms);
CREATE INDEX devices_last_seen ON devices(last_seen_ms);
```

## Retention
- The size cap (default 512 MB) is checked hourly.
- Sightings older than 30 days are deleted first (configurable), then `VACUUM INTO` a rotated file.
- Migrations live in `migrations/NNNN_*.sql`, and `meta.schema_version` is bumped with each one.
- Nothing stores frame payloads or EAPOL.
