//! Read-only ingest adapters.
//!
//! These read what other services on the Pager have already written — the
//! Bluetooth scanner's output, the recon database — and put it into our own
//! database. They **only read**: they open their source for reading, they
//! never write to it, they never move it, and they never touch the service
//! that writes it.

#![forbid(unsafe_code)]

pub mod blue5;
#[cfg(test)]
mod tests;

pub use blue5::{IngestError, Network};
