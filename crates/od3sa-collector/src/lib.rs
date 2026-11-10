//! The collector: capture, aggregate, write and publish.
//!
//! Everything else in the project already exists and is tested: the capture
//! crate reads a monitor interface, the aggregator turns a frame into the rows
//! it implies, the writer puts those rows into the database in batches, the
//! event bus carries the events to the plugins, the gpsd client gives a
//! position and the alerts engine raises the awareness rules. **This crate is
//! the wiring between them.**
//!
//! # The pipeline
//!
//! For every captured frame:
//!
//! 1. **capture** — the bytes and the time;
//! 2. **aggregate** — the device, the access point, the client link, the
//!    probe, the sighting and the deauthentication the frame implies;
//! 3. **alerts** — the rules that the observation raises;
//! 4. **write** — the observation into the batch, and the alerts into the
//!    `alerts` table;
//! 5. **publish** — the events to the bus.
//!
//! # What it does not do
//!
//! - **It never stores a payload.** The observation carries the MAC, the
//!   SSID, the security, the channel and the signal level, and the schema
//!   has nowhere to put a frame body. This crate does not add a side table
//!   either.
//! - **It never touches a radio beyond reading it.** The interface is
//!   expected to be in monitor mode already, and owned by another service.
//! - **It never transmits anything.**
//!
//! # The rules
//!
//! - A frame that cannot be parsed is **counted, not an error**. One odd
//!   frame in a million is normal, and the daemon must not stop for it. A
//!   *database* error is different: that stops the collector, because the
//!   daemon has to know it is not collecting.
//! - The bus and gpsd are both **optional**. Without an events socket the
//!   collector does not publish; without gpsd the sightings have no
//!   position. Neither is an error: the Pager may have no GPS at all.
//! - The batch is flushed on the interval and **at the end**, so a run that
//!   is interrupted still leaves most of its data in the database.

#![forbid(unsafe_code)]

mod config;
mod events;
#[cfg(test)]
mod tests;

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use od3sa_alerts::{Alert, AlertEngine};
use od3sa_capture::{Capture, CaptureError, CaptureOptions, DataLink};
use od3sa_events::EventBus;
use od3sa_gps::GpsdClient;
use od3sa_store::{Aggregator, AlertRow, LinkLayer, Observation, Store, StoreError, Writer};

pub use config::CollectorConfig;

/// Why the collector stopped.
#[derive(Debug)]
pub enum CollectorError {
    /// The interface could not be opened.
    Capture(CaptureError),
    /// The database could not be opened or written.
    Store(StoreError),
    /// The configuration could not be read.
    Config(String),
}

impl std::fmt::Display for CollectorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Capture(error) => write!(f, "capture: {error}"),
            Self::Store(error) => write!(f, "database: {error}"),
            Self::Config(reason) => write!(f, "configuration: {reason}"),
        }
    }
}

impl std::error::Error for CollectorError {}

impl From<CaptureError> for CollectorError {
    fn from(error: CaptureError) -> Self {
        Self::Capture(error)
    }
}

impl From<StoreError> for CollectorError {
    fn from(error: StoreError) -> Self {
        Self::Store(error)
    }
}

/// What the collector has done.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
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

/// The collector.
pub struct Collector {
    config: CollectorConfig,
    engine: AlertEngine,
    bus: Option<EventBus>,
    gps: Option<GpsdClient>,
    aggregator: Aggregator,
    writer: Option<Writer>,
    stopping: AtomicBool,
    frames: AtomicUsize,
    observations: AtomicUsize,
    alerts: AtomicUsize,
    events: AtomicUsize,
    unparsed: AtomicUsize,
}

impl std::fmt::Debug for Collector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Collector")
            .field("interface", &self.config.interface)
            .field("database", &self.config.database)
            .field("stats", &self.stats())
            .finish_non_exhaustive()
    }
}

impl Collector {
    /// A collector with the given configuration.
    pub fn new(config: CollectorConfig) -> Collector {
        let engine = AlertEngine::new(config.alerts_rules());
        let aggregator = Aggregator::new(config.device_capacity);
        Collector {
            config,
            engine,
            bus: None,
            gps: None,
            aggregator,
            writer: None,
            stopping: AtomicBool::new(false),
            frames: AtomicUsize::new(0),
            observations: AtomicUsize::new(0),
            alerts: AtomicUsize::new(0),
            events: AtomicUsize::new(0),
            unparsed: AtomicUsize::new(0),
        }
    }

    /// Give the collector the event bus to publish to.
    pub fn with_bus(mut self, bus: EventBus) -> Collector {
        self.bus = Some(bus);
        self
    }

    /// Give the collector a gpsd client to take the position from.
    pub fn with_gpsd(mut self, gps: GpsdClient) -> Collector {
        self.gps = Some(gps);
        self
    }

    /// Open the interface, open the database, and collect until the time is
    /// up or the collector is stopped.
    pub fn run(&mut self) -> Result<(), CollectorError> {
        let options = CaptureOptions {
            snaplen: self.config.snaplen,
            promiscuous: self.config.promiscuous,
            timeout_ms: self.config.timeout_ms,
            immediate: true,
        };

        let mut capture = Capture::open(&self.config.interface, &options)?;
        let link = link_layer(capture.datalink());

        self.open_database()?;

        let mut gps = self.gps.take();
        let started = Instant::now();
        let mut last_flush = Instant::now();

        while !self.stopping.load(Ordering::SeqCst) {
            if self.config.seconds > 0 && started.elapsed().as_secs() >= self.config.seconds {
                break;
            }

            // A read that failed means the interface went away. That is
            // worth stopping for: the daemon has to know it is not
            // collecting.
            let packet = capture.next_packet()?;
            let Some(packet) = packet else {
                // A read timeout: nothing arrived.
                if last_flush.elapsed() >= Duration::from_millis(self.config.flush_interval_ms) {
                    self.flush()?;
                    last_flush = Instant::now();
                }
                continue;
            };

            let ts_ms = packet.ts_sec * 1000 + packet.ts_usec / 1000;
            self.process(packet.data, link, ts_ms, gps.as_mut())?;

            if last_flush.elapsed() >= Duration::from_millis(self.config.flush_interval_ms) {
                self.flush()?;
                last_flush = Instant::now();
            }
        }

        self.flush()?;
        if let Some(writer) = self.writer.take() {
            writer.close()?;
        }
        Ok(())
    }

    /// Process one frame: aggregate it, raise the alerts it raises, write
    /// it, and publish the events.
    ///
    /// This is the pipeline without the capture around it, so that it can be
    /// driven by a test with synthetic frames.
    pub fn process(
        &mut self,
        frame: &[u8],
        link: LinkLayer,
        ts_ms: i64,
        gps: Option<&mut GpsdClient>,
    ) -> Result<(), CollectorError> {
        self.frames.fetch_add(1, Ordering::Relaxed);

        let source = self.config.source_name();
        let source = source.as_str();

        let mut observation = match self.aggregator.observe(frame, link, ts_ms, source) {
            Ok(observation) => observation,
            Err(_) => {
                // A frame that cannot be parsed is counted, not fatal.
                self.unparsed.fetch_add(1, Ordering::Relaxed);
                return Ok(());
            }
        };
        if !observation.parsed {
            // The frame could not be parsed. That is not an error — one odd
            // frame in a million is normal — but it is counted, and there is
            // nothing in it to write.
            self.unparsed.fetch_add(1, Ordering::Relaxed);
            return Ok(());
        }

        // The position, when there is one. A gpsd that is not there is not
        // an error: the sighting simply carries no position.
        let position = gps.and_then(|client| {
            let _ = client.poll();
            client.last_fix()
        });
        if let (Some(position), Some(sighting)) = (position, observation.sighting.as_mut()) {
            sighting.lat = Some(position.lat);
            sighting.lon = Some(position.lon);
            sighting.alt = Some(position.alt);
            sighting.fix = Some(position.mode);
        }

        let alerts = self.engine.observe(&observation, ts_ms);

        if let Some(writer) = self.writer.as_mut() {
            writer.write(&observation)?;
            self.observations.fetch_add(1, Ordering::Relaxed);
            for alert in &alerts {
                let row = AlertRow {
                    ts_ms,
                    rule: alert.rule.clone(),
                    severity: alert.severity.as_str().to_string(),
                    mac: alert.mac,
                    summary: alert.summary.clone(),
                    details: Some(alert.details.to_string()),
                };
                writer.write_alert(&row)?;
            }
        }
        self.alerts.fetch_add(alerts.len(), Ordering::Relaxed);

        self.publish(&observation, &alerts, ts_ms);
        Ok(())
    }

    /// Open the database and start the batch.
    ///
    /// The capture loop does this for itself. It is here so that a test can
    /// drive the pipeline with synthetic frames.
    pub fn open_database(&mut self) -> Result<(), CollectorError> {
        let store = Store::open(&self.config.database)?;
        self.writer = Some(Writer::new(
            store,
            self.config.flush_interval_ms,
            self.config.batch_size,
        ));
        Ok(())
    }

    /// Write the pending batch.
    ///
    /// The daemon does not need this — the collector flushes on its interval
    /// and at the end — but a test that has no capture loop around it does.
    #[cfg(test)]
    pub fn flush_for_test(&mut self) {
        let _ = self.flush();
    }

    /// Ask the collector to stop. It finishes the batch and closes cleanly.
    pub fn stop(&self) {
        self.stopping.store(true, Ordering::SeqCst);
    }

    /// What the collector has seen.
    pub fn stats(&self) -> CollectorStats {
        CollectorStats {
            frames: self.frames.load(Ordering::Relaxed) as u64,
            observations: self.observations.load(Ordering::Relaxed) as u64,
            alerts: self.alerts.load(Ordering::Relaxed) as u64,
            events: self.events.load(Ordering::Relaxed) as u64,
            unparsed: self.unparsed.load(Ordering::Relaxed) as u64,
        }
    }

    /// Write the pending batch.
    fn flush(&mut self) -> Result<(), CollectorError> {
        if let Some(writer) = self.writer.as_mut() {
            writer.flush()?;
        }
        Ok(())
    }

    /// Publish the events the observation and the alerts call for.
    fn publish(&mut self, observation: &Observation, alerts: &[Alert], ts_ms: i64) {
        let Some(bus) = self.bus.as_ref() else {
            return;
        };
        for event in events::events_for(observation, alerts, ts_ms) {
            bus.publish(&event);
            self.events.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// The link layer the capture delivers.
fn link_layer(datalink: DataLink) -> LinkLayer {
    match datalink {
        DataLink::Ieee80211RadioTap | DataLink::Ieee80211 => LinkLayer::Radiotap,
        _ => LinkLayer::Radiotap,
    }
}

/// Where the database lives when nothing says otherwise.
pub const DEFAULT_DATABASE: &str = "/mmc/od3sa-recon/recon.sqlite";

/// The event bus socket, when nothing says otherwise.
pub const DEFAULT_EVENTS_SOCKET: &str = "/tmp/od3sa-recon/events.sock";

/// The query socket, when nothing says otherwise.
pub const DEFAULT_QUERY_SOCKET: &str = "/tmp/od3sa-recon/query.sock";

/// The path of the database, for the daemon.
pub fn default_database() -> PathBuf {
    PathBuf::from(DEFAULT_DATABASE)
}
