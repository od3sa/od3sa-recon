//! The export plugins for od3sa-recon.
//!
//! Every plugin here reads the data through the daemon's read-only query
//! socket, using the token the host gives it. A plugin never opens the
//! database, and it never writes to the radio.

#![forbid(unsafe_code)]

pub mod client;
pub mod kismet;
pub mod ndjson;
pub mod pager_ui;
pub mod pcapng;
pub mod wigle;

pub use client::{PluginError, QueryClient};
