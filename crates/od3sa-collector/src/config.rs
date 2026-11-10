//! The collector's configuration, and how it is read from a file.
//!
//! On the Pager the configuration lives on the SD card, where the owner can
//! edit it, so the daemon can be pointed at a TOML file:
//!
//! ```toml
//! interface = "wlan1mon"
//! database = "/mmc/od3sa-recon/recon.sqlite"
//! events_socket = "/tmp/od3sa-recon/events.sock"
//! query_socket = "/tmp/od3sa-recon/query.sock"
//! gpsd = "127.0.0.1:2947"
//!
//! [alerts]
//! enabled = true
//! new_device = { enabled = true, severity = "info" }
//! ```
//!
//! **Any option given on the command line overrides the file.** The keys in
//! the file are snake_case and the options are kebab-case; that is deliberate.

use std::path::PathBuf;

use od3sa_alerts::Rules;

/// Why the configuration could not be read.
#[derive(Debug)]
pub enum ConfigError {
    /// The file is not valid TOML.
    Toml(String),
    /// A key holds the wrong kind of value.
    Wrong(String),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Toml(reason) => write!(f, "the configuration is not valid TOML: {reason}"),
            Self::Wrong(reason) => write!(f, "the configuration is wrong: {reason}"),
        }
    }
}

impl std::error::Error for ConfigError {}

/// How the collector is set up.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CollectorConfig {
    /// The interface to read.
    pub interface: String,
    /// The database to write to.
    pub database: PathBuf,
    /// The event bus socket, if the events are to be published.
    pub events_socket: Option<PathBuf>,
    /// The query socket the plugins use, if there is one.
    pub query_socket: Option<PathBuf>,
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
    /// How many bytes of each frame to keep. Headers only.
    pub snaplen: u32,
    /// Whether to see frames that are not addressed to this host.
    pub promiscuous: bool,
    /// How long a read may block, in milliseconds.
    pub timeout_ms: i32,
    /// The alert rules, as the TOML the rules engine reads.
    pub alerts: Option<String>,
}

impl Default for CollectorConfig {
    fn default() -> Self {
        CollectorConfig {
            interface: "wlan1mon".to_string(),
            database: PathBuf::from("/mmc/od3sa-recon/recon.sqlite"),
            events_socket: Some(PathBuf::from("/tmp/od3sa-recon/events.sock")),
            query_socket: Some(PathBuf::from("/tmp/od3sa-recon/query.sock")),
            gpsd_address: Some("127.0.0.1:2947".to_string()),
            flush_interval_ms: 5_000,
            batch_size: 64,
            device_capacity: 1024,
            seconds: 0,
            snaplen: 256,
            promiscuous: true,
            timeout_ms: 100,
            alerts: None,
        }
    }
}

impl CollectorConfig {
    /// Read the configuration from a TOML document.
    ///
    /// A document that is not valid TOML is an error. A key that is not
    /// there keeps its default.
    pub fn from_toml(text: &str) -> Result<CollectorConfig, ConfigError> {
        let value: toml::Value =
            toml::from_str(text).map_err(|error| ConfigError::Toml(error.to_string()))?;
        let table = value
            .as_table()
            .ok_or_else(|| ConfigError::Wrong("the configuration is not a table".to_string()))?;

        let mut config = CollectorConfig::default();

        if let Some(interface) = table.get("interface") {
            config.interface = interface
                .as_str()
                .ok_or_else(|| ConfigError::Wrong("interface must be a string".to_string()))?
                .to_string();
        }
        if let Some(database) = table.get("database") {
            config.database = PathBuf::from(
                database
                    .as_str()
                    .ok_or_else(|| ConfigError::Wrong("database must be a string".to_string()))?,
            );
        }
        if let Some(socket) = table.get("events_socket") {
            config.events_socket = socket.as_str().map(PathBuf::from);
        }
        if let Some(socket) = table.get("query_socket") {
            config.query_socket = socket.as_str().map(PathBuf::from);
        }
        if let Some(address) = table.get("gpsd") {
            config.gpsd_address = address.as_str().map(str::to_string);
        }
        if let Some(seconds) = table.get("seconds") {
            config.seconds = seconds
                .as_integer()
                .ok_or_else(|| ConfigError::Wrong("seconds must be a number".to_string()))?
                as u64;
        }
        if let Some(interval) = table.get("flush_interval_ms") {
            config.flush_interval_ms = interval.as_integer().ok_or_else(|| {
                ConfigError::Wrong("flush_interval_ms must be a number".to_string())
            })? as u64;
        }
        if let Some(size) = table.get("batch_size") {
            config.batch_size = size
                .as_integer()
                .ok_or_else(|| ConfigError::Wrong("batch_size must be a number".to_string()))?
                as usize;
        }
        if let Some(capacity) = table.get("device_capacity") {
            config.device_capacity = capacity
                .as_integer()
                .ok_or_else(|| ConfigError::Wrong("device_capacity must be a number".to_string()))?
                as usize;
        }
        if let Some(snaplen) = table.get("snaplen") {
            config.snaplen = snaplen
                .as_integer()
                .ok_or_else(|| ConfigError::Wrong("snaplen must be a number".to_string()))?
                as u32;
        }
        if let Some(promiscuous) = table.get("promiscuous") {
            config.promiscuous = promiscuous.as_bool().ok_or_else(|| {
                ConfigError::Wrong("promiscuous must be true or false".to_string())
            })?;
        }
        if let Some(timeout) = table.get("timeout_ms") {
            config.timeout_ms = timeout
                .as_integer()
                .ok_or_else(|| ConfigError::Wrong("timeout_ms must be a number".to_string()))?
                as i32;
        }
        if let Some(alerts) = table.get("alerts") {
            // The rules engine reads a TOML document, and the file has the
            // rules in a table of their own.
            config.alerts = Some(alerts.to_string());
        }

        Ok(config)
    }

    /// The rules, as the alerts engine wants them.
    ///
    /// A configuration with no rules means every rule is off, which is what
    /// the rules engine does with an empty document.
    pub fn alerts_rules(&self) -> Rules {
        match self.alerts.as_deref() {
            Some(toml) => Rules::parse(toml).unwrap_or_default(),
            None => Rules::default(),
        }
    }

    /// The name the frames are recorded under.
    pub fn source_name(&self) -> String {
        format!("pcap:{}", self.interface)
    }
}
