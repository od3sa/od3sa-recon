# Collector contract

The contract for the collector mode: the daemon actually collecting into the
database and publishing the events the plugins consume.

## What this is

The collector is the piece that connects the rest: the capture crate, the
aggregator, the batched writer, the event bus, the gpsd client and the
alerts engine. The daemon can count frames (`--dry-run`) and it can serve a
query socket over a database, but neither *collects into* one. That is what
this does.

## Where it lives

`crates/od3sa-collector`, its own crate: it is the composition layer, and
keeping it out of the daemon crate keeps the daemon small.

It depends on `od3sa-capture` (the frames), `od3sa-store` (the aggregator and
the writer), `od3sa-events` (the bus), `od3sa-gps` (the position) and
`od3sa-alerts` (the rules). All are first-party.

## The pipeline

For every captured frame:

1. **capture** — `od3sa_capture::Capture` gives the bytes.
2. **aggregate** — `od3sa_store::Aggregator::observe` turns the frame into an
   `Observation`: the device, the access point, the client link, the probe, the
   sighting, and the deauthentication.
3. **alerts** — `od3sa_alerts::AlertEngine::observe` returns the alerts the
   observation raised.
4. **write** — `od3sa_store::Writer::write` puts the observation in the batch.
   The alerts go to the `alerts` table.
5. **publish** — the events go to the bus.

## The API

```rust
/// How the collector is set up.
#[derive(Debug, Clone)]
pub struct CollectorConfig {
    /// The interface to read.
    pub interface: String,
    /// The database to write to.
    pub database: std::path::PathBuf,
    /// The event bus socket, if the events are to be published.
    pub events_socket: Option<std::path::PathBuf>,
    /// The query socket the plugins use, if there is one.
    pub query_socket: Option<std::path::PathBuf>,
    /// Where gpsd is, if a position is wanted.
    pub gpsd_address: Option<String>,
    /// How often the batch is written, in milliseconds.
    pub flush_interval_ms: u64,
    /// How many observations are written in one batch.
    pub batch_size: usize,
    /// How many devices the aggregator's table holds.
    pub device_capacity: usize,
    /// How long to run, in seconds. Zero means until stopped.
    pub seconds: u64,
}

/// The collector.
pub struct Collector { /* the pieces */ }

impl Collector {
    /// A collector with the given configuration.
    pub fn new(config: CollectorConfig) -> Collector;

    /// Open the interface, open the database, and collect until the time is up
    /// or the collector is stopped.
    pub fn run(&mut self) -> Result<(), CollectorError>;

    /// Ask the collector to stop. It finishes the batch and closes cleanly.
    pub fn stop(&self);

    /// What the collector has seen, for the daemon's own status output.
    pub fn stats(&self) -> CollectorStats;
}

/// What the collector has done.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CollectorStats {
    /// How many frames were read.
    pub frames: u64,
    /// How many observations were written.
    pub observations: u64,
    /// How many alerts were raised.
    pub alerts: u64,
    /// How many events were published.
    pub events: u64,
    /// How many frames could not be parsed. Not an error: one odd frame in a
    /// million is normal.
    pub unparsed: u64,
}
```

## The events it publishes

The topics from `docs/api/events.md`:

| Topic | When |
|---|---|
| `device.new` | the aggregator saw a device it had not seen |
| `ap.new` | the aggregator saw an access point it had not seen |
| `client.assoc` | the aggregator saw a client link |
| `probe.seen` | the aggregator saw a probe request |
| `alert.raised` | the alerts engine raised an alert |
| `source.status` | the capture source changed state, and on a timer |

The `data` of each is the shape in `docs/api/events.md`. The envelope is the
bus's own: `{"v":0,"type":...,"ts_ms":...,"seq":...,"data":{...}}`.

**A `device.new` is published when the device is new, not every time it is
seen.** The aggregator knows which devices are new ✓ — it is the thing that
decides what is new ✓. The same for `ap.new`.

## The rules the collector follows

- **It never writes a payload.** The observation carries the MAC, the SSID,
  the security, the channel and the signal level, and the schema has nowhere
  to put a frame body. The aggregator already guarantees this ✓ — the
  collector must not add a side table either.
- **A frame that cannot be parsed is counted, not an error.** One odd frame
  in a million is normal, and the daemon must not stop for it.
- **A database error stops the collector** — that is different from a bad
  frame. The daemon has to know that it is not collecting.
- **The batch is flushed on the interval and at the end**, so a run that is
  interrupted still leaves most of its data in the database.
- **The retention pass runs hourly.** It is what stops the database from
  growing for ever, so it has to run even on a quiet channel, where the
  only thing that happens is the read timing out. A pass that fails is
  logged and the collector carries on: a database that could not be
  trimmed is a smaller problem than a collector that stopped.
- **The position is tagged when there is one.** The gpsd client is optional:
  the Pager may have no GPS, and that is not an error. A sighting with no
  position has `lat`, `lon`, `alt` and `fix` as null ✓.
- **The bus is optional too.** Without an events socket, the collector simply
  does not publish, and everything else works.
- **The collector stops on SIGINT or SIGTERM** and finishes the batch. The
  daemon already has the signal handling for the dry run ✓ — reuse it.
- **Nothing here touches a radio beyond reading it.**

## The daemon's side

The daemon gets a `--collect` mode:

```
od3sa-recond --collect --interface wlan1mon --db /mmc/od3sa-recon/recon.sqlite
             [--events-socket /tmp/od3sa-recon/events.sock]
             [--query-socket /tmp/od3sa-recon/query.sock]
             [--gpsd 127.0.0.1:2947] [--seconds N] [--flush-interval-ms N]
             [--batch-size N] [--retention-days N] [--max-db-mb N]
             [--config <path>]
```

**`--config <path>` reads the settings from a TOML file**, because on the Pager
the configuration has to live on the SD card where the owner can edit it:

```toml
interface = "wlan1mon"
database = "/mmc/od3sa-recon/recon.sqlite"
events_socket = "/tmp/od3sa-recon/events.sock"
query_socket = "/tmp/od3sa-recon/query.sock"
gpsd = "127.0.0.1:2947"

# How long the data is kept, and how much disk it may take.
retention_days = 30
max_db_mb = 512

[alerts]
enabled = true
new_device = { enabled = true, severity = "info" }
```

**Any option given on the command line overrides the file.** The keys in the
file are snake_case and the options are kebab-case; that is deliberate. A
config file that was asked for and is not there is an error; no `--config` at
all is simply "no file", and the options and the defaults apply.

**An option that was not given does not override the file.** This matters:
the file is what the owner edits on the device, so a default that
overwrote it would make the file useless. An option is therefore "not
given" when it is absent, not when it holds its default.

The defaults for the database, the event socket and the query socket are the
ones the rest of the project already uses ✓ (`/tmp/od3sa-recon/…`, and the
database on `/mmc/od3sa-recon/recon.sqlite` when it is there ✓).

The daemon prints a status line every second: the frames seen, the
observations written, the alerts raised and the events published ✓.

## The tests

1. **A frame becomes rows.** Feed a synthetic beacon through the collector
   against a temporary database, and check that the database has the device,
   the access point, the SSID and the sighting ✓.
2. **A frame becomes an event.** The same beacon, with a bus attached, and
   check that `ap.new` was published ✓.
3. **An alert becomes a row and an event.** A frame that trips a rule — a
   beacon on a watchlisted SSID — and check the `alerts` table and the
   `alert.raised` event ✓.
4. **The batch is flushed at the end**, so the rows are there even without
   waiting for the interval ✓.
5. **A frame that cannot be parsed is counted and does not stop the
   collector** ✓.
6. **Nothing stores a payload.** A frame carrying a marker leaves no trace of
   it in the database ✓ — check every table.
7. **The collector works without gpsd and without the bus** ✓ — no position,
   no events, and the rows are still there ✓.
8. **A sighting with a position carries it**, using the fake gpsd from
   `od3sa-gps` — or, if that is not reachable, by checking that the columns
   are null without one ✓.

Use `od3sa-fixtures` for the frames and `od3sa-store`'s `Store::open_in_memory`
where a file is not needed.

## Constraints

- The dependencies are the first-party crates and `toml` and `serde_json`.
  A new dependency has to be MIT-compatible.
- No `unwrap` or `expect` outside the tests.
- No real data.
- Nothing that touches a radio beyond reading it, and nothing that
  transmits.
