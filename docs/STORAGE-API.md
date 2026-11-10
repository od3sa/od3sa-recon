# Storage API contract

The contract the aggregator and the batched writer are written against. They
live in `crates/od3sa-store`, which already holds the schema and the migration
machinery from.

## What the aggregator is for

The daemon sees frames. The database holds *devices*, *access points*,
*clients*, *probes* and *sightings*. The aggregator is the thing in between:
it turns one parsed frame into the rows that frame implies, and it keeps a
bounded in-memory table of the devices it has seen so the same device does not
become a new row every time it is seen.

It is a pure function of the frame plus the aggregator's own state. It does
not touch the database; the writer does that.

## `crates/od3sa-store/src/aggregator.rs`

```rust
/// What kind of link layer a captured frame has.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LinkLayer {
    /// 802.11 frames with a radiotap header in front of them.
    #[default]
    Radiotap,
    /// 802.11 frames with no radiotap header.
    Ieee80211,
}

/// A device the aggregator has seen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Device {
    /// The six byte MAC address.
    pub mac: [u8; 6],
    /// The first three bytes of the address.
    pub oui: [u8; 3],
    /// "ap", "client", "ble" or "unknown".
    pub kind: &'static str,
    /// True when the address is a locally administered one: the top two bits
    /// of the first octet are set.
    pub randomized: bool,
}

/// An access point, as far as a frame reveals one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessPoint {
    /// The BSSID.
    pub bssid: [u8; 6],
    /// The SSID bytes, if the frame carried one.
    pub ssid: Option<Vec<u8>>,
    /// True when the SSID element was empty.
    pub ssid_hidden: bool,
    /// The channel, from the radiotap header.
    pub channel: Option<u16>,
    /// The centre frequency in MHz.
    pub freq_mhz: Option<u16>,
    /// "2.4", "5" or "6".
    pub band: Option<&'static str>,
    /// A short security label: "WPA2-PSK", "WPA3-SAE", "WEP", "open".
    pub security: Option<String>,
    /// The AKM suite names, comma separated.
    pub akm: Option<String>,
    /// The pairwise cipher names, comma separated.
    pub pairwise: Option<String>,
    /// The group cipher name.
    pub group_cipher: Option<String>,
    /// True when the RSN capabilities say PMF is required.
    pub pmf_required: bool,
    /// True when the frame carried WPS information.
    pub wps: bool,
    /// True when the frame carried HT, VHT or HE information.
    pub ht: bool,
    pub vht: bool,
    pub he: bool,
    /// The beacon interval, in TU.
    pub beacon_interval: Option<u16>,
}

/// A sighting of a device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sighting {
    /// The device that was seen.
    pub mac: [u8; 6],
    /// When it was seen, in unix epoch milliseconds.
    pub ts_ms: i64,
    /// The signal level in dBm, if the frame carried one.
    pub rssi: Option<i8>,
    /// The channel it was seen on.
    pub channel: Option<u16>,
    /// The source that saw it. The writer maps this to a `sources` row.
    pub source: &'static str,
}

/// A probe request: a station looking for a network.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Probe {
    /// The station that probed.
    pub mac: [u8; 6],
    /// The SSID it asked for.
    pub ssid: Vec<u8>,
    pub ts_ms: i64,
    pub rssi: Option<i8>,
}

/// A client seen associated with an access point.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientLink {
    /// The station.
    pub mac: [u8; 6],
    /// The access point.
    pub bssid: [u8; 6],
    pub ts_ms: i64,
    pub rssi: Option<i8>,
}

/// What one frame turned into.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Observation {
    /// The device the frame was about, if any.
    pub device: Option<Device>,
    /// The access point the frame was about, if any.
    pub access_point: Option<AccessPoint>,
    /// The sighting of the device.
    pub sighting: Option<Sighting>,
    /// The probe, for a probe request.
    pub probe: Option<Probe>,
    /// The client-to-AP link, for a data frame or an association.
    pub client: Option<ClientLink>,
}

/// A bounded table of the devices seen recently.
pub struct Aggregator {
    /* the device table and the per-device state */
}

impl Aggregator {
    /// A new aggregator whose device table holds at most `capacity` devices.
    /// The oldest device is dropped when the table is full.
    pub fn new(capacity: usize) -> Aggregator;

    /// How many devices the table currently holds.
    pub fn len(&self) -> usize;

    /// True when the table holds no devices.
    pub fn is_empty(&self) -> bool;

    /// Turn one captured frame into what it says.
    pub fn observe(&mut self, frame: &[u8], link: LinkLayer, ts_ms: i64, source: &str)
        -> Result<Observation, StoreError>;
}
```

### The rules the aggregator follows

- **The frame is parsed by `od3sa-parse`**, not here. The aggregator calls
  `od3sa_parse::frame::dispatch`, and for management frames it reads the
  information elements with `od3sa_parse::ie::parse_ies` and
  `od3sa_parse::ie::summarize`, using
  `od3sa_parse::ieee80211::management_ie_offset` to find where the elements
  start.
- **A malformed frame is not an error.** The daemon must not stop because one
  frame is odd. A frame that cannot be parsed yields an empty `Observation`
  and no error. Only a genuinely broken argument (a frame that is not bytes)
  is an error.
- **A beacon gives an access point.** The BSSID is the frame's addr3, the
  SSID and the security come from the elements, and the beacon interval comes
  from the beacon's fixed fields.
- **A data frame gives a client and a sighting.** The client-to-AP mapping
  comes from `od3sa_parse::frame::map_data_addresses`.
- **A probe request gives a probe** and a sighting of the probing station.
- **Nothing is stored that identifies a payload.** The aggregator keeps the
  MAC, the SSID, the security and the signal level. It never keeps a frame
  body, and it never keeps an EAPOL body. A test must assert this.
- **The device table is bounded.** A long run on a busy channel sees a lot of
  random MACs; the table is capped and the oldest entries are dropped. The
  database is the memory of everything, the table is the working set.
- **A randomised address is one whose first octet has the top two bits set**
  (`0b11`). The `randomized` flag says so.

## `crates/od3sa-store/src/writer.rs`

```rust
/// Writes observations to the database, in batches.
pub struct Writer {
    /* the store and the pending batch */
}

impl Writer {
    /// A writer over `store` that flushes at most every `flush_interval_ms`
    /// and at most every `batch_size` observations.
    pub fn new(store: Store, flush_interval_ms: u64, batch_size: usize) -> Writer;

    /// Add one observation to the batch.
    pub fn write(&mut self, observation: &Observation) -> Result<(), StoreError>;

    /// Write everything pending, in one transaction.
    pub fn flush(&mut self) -> Result<usize, StoreError>;

    /// How many observations are waiting to be written.
    pub fn pending(&self) -> usize;

    /// Apply the retention rules: delete sightings older than `max_age_days`,
    /// and rotate the database if it is over `max_bytes`.
    pub fn apply_retention(&mut self, now_ms: i64, max_age_days: i64, max_bytes: u64)
        -> Result<Retention, StoreError>;

    /// Close the batch and the database.
    pub fn close(self) -> Result<(), StoreError>;
}

/// What the retention pass did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Retention {
    /// How many sighting rows were deleted.
    pub sightings_deleted: u64,
    /// The rotated file, if the database was rotated.
    pub rotated_to: Option<std::path::PathBuf>,
}
```

### The rules the writer follows

- **Writes are batched.** The observations wait in memory and are written in
  one transaction, so a busy channel does not mean a transaction per frame.
  The batch is flushed when it is full or when the interval has passed.
- **Every write is in the schema of `docs/SCHEMA.md`** and nowhere else. The
  writer must not need a column the schema does not have.
- **Devices and SSIDs are looked up, not duplicated.** The `devices` table
  has `mac TEXT UNIQUE` and the `ssids` table has `ssid BLOB UNIQUE`; the
  writer resolves a MAC to its row id and an SSID to its row id before
  inserting the rows that refer to it.
- **Retention follows SCHEMA.md:** the size cap is checked periodically, the
  sightings older than the age limit are deleted first, and then the
  database is rotated with `VACUUM INTO` to a file named
  `recon-YYYYMMDD.sqlite`. The rotation is what `rotated_to` reports.
- **A rotated database is a fresh one** at the current schema version, and
  the old rows are in the rotated file.
- **Nothing stores a payload.** No column of the schema holds one, and the
  writer must not invent a side table.

## Tests

In `crates/od3sa-store/src/tests.rs` (or a new test module):

1. A synthetic beacon produces an access point with the right SSID, security,
   channel and band, and a sighting of the BSSID.
2. A synthetic data frame produces a client-to-AP link and a sighting of the
   client.
3. A synthetic probe request produces a probe.
4. **No payload is kept:** a frame whose payload carries a distinctive marker
   must leave no trace of it in the `Observation`, in its `Debug` output.
5. **The device table is bounded:** observing more devices than the capacity
   keeps the table at the capacity, and the devices it drops are the oldest.
6. The writer writes an observation and the rows appear in the database, with
   the device and SSID rows resolved rather than duplicated: observing the
   same beacon twice leaves one device row and one SSID row.
7. **Batching:** a hundred observations with a batch size of ten produce ten
   flushes, and the database has every row at the end.
8. **Retention:** sightings older than the age limit are deleted and the
   newer ones are kept.
9. **Rotation:** a database over the size cap is rotated, the rotated file
   holds the old rows, and the live database is at the current schema
   version.

Use the synthetic frame builders from `crates/od3sa-fixtures` if they help —
that crate is a workspace member and produces exactly the kind of frame these
tests need.

## Constraints

- The dependencies are `rusqlite` (MIT, with SQLite itself public domain),
  `od3sa-parse` and `od3sa-fixtures`. A new dependency has to be
  MIT-compatible: no GPL, LGPL or AGPL.
- No `unwrap` or `expect` outside the tests.
- No real data. Only the synthetic address family and `example-*` SSIDs.
- The database holds metadata only. There is no column for a frame body or
  an EAPOL body, and none may be added.
