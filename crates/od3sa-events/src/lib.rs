//! The NDJSON event bus of `od3sa-recon`.
//!
//! The daemon is the server and the plugins are the clients. A plugin
//! connects to the Unix socket, sends one subscribe line and reads the
//! events it asked for, one JSON object per line.
//!
//! ```text
//! {"op":"subscribe","token":"<token>","topics":["ap.*","alert.raised"]}
//! {"type":"bus.ready","data":{"topics":["ap.*","alert.raised"]}}
//! {"v":0,"type":"ap.new","ts_ms":1762300000000,"seq":42,"data":{...}}
//! ```
//!
//! The wire format, the API and the backpressure policy are the contract
//! in `docs/EVENTS-API.md`. The topics themselves are listed in
//! `docs/api/events.md`.
//!
//! # The backpressure policy
//!
//! A slow subscriber must never slow the daemon down, and must never make
//! it grow without bound. Every subscriber has a **bounded queue** of
//! `queue_len` events. When the queue is full the **newest** event is
//! dropped and the subscriber is told, with
//! `{"type":"bus.dropped","data":{"n":N}}`, where `N` is the number of
//! events dropped since the last notice.
//!
//! Publishing never blocks: the publisher takes the subscriber's lock,
//! and if the queue is full it drops rather than waits.
//!
//! # The token
//!
//! A subscribe request carries a token. The bus checks it **before** the
//! topics are looked at, so a subscriber that cannot authenticate learns
//! nothing about what is on the bus.
//!
//! # Read-only
//!
//! The bus carries information about frames that were heard. It never
//! makes a frame, it never opens a radio, and it has no call that could.
//! There is nothing in this crate that transmits.

#![forbid(unsafe_code)]

mod bus;
mod error;
mod event;
mod wire;

#[cfg(test)]
mod tests;

pub use bus::{DEFAULT_QUEUE_LEN, DEFAULT_SOCKET_PATH, EventBus};
pub use error::EventError;
pub use event::{Event, TopicPattern};
