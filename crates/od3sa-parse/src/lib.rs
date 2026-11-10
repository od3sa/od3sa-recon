//! Metadata-only parsers for 802.11 frames and radiotap headers.
//!
//! # Scope
//!
//! This crate turns raw capture bytes into *metadata*: who was seen, on which
//! channel, with what security, and how strong the signal was. It deliberately
//! does **not** retain frame payloads or EAPOL bodies; those are counted at
//! most. See `docs/DESIGN.md` for the reasoning.
//!
//! # Invariants
//!
//! * The parsers never panic. Every input is either parsed or reported as an
//!   error; lengths are always bounds-checked against the buffer.
//! * The parsers never allocate unbounded memory: an information element
//!   longer than the remaining buffer is an error, not an allocation.
//! * Nothing in this crate touches a radio. It is a pure function library over
//!   byte slices, so it is safe to run in tests, on the device, or anywhere
//!   else.
//!
//! The module layout mirrors the capture path:
//!
//! | Module | Contents |
//! |---|---|
//! | [`radiotap`] | radiotap header: RSSI, channel/frequency, rate, flags |
//! | [`ieee80211`] | MAC header and frame control |
//! | [`ie`] | information elements: SSID, RSN, HT/VHT/HE, vendor, WPS |
//! | [`frame`] | top-level dispatch over management, control and data frames |
//! | [`error`] | the shared error type |

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used)]

pub mod error;
pub mod frame;
pub mod ie;
pub mod ieee80211;
pub mod radiotap;

pub use error::{ParseError, Result};

/// The crate version, as reported by the daemon's `--version` output.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_is_not_empty() {
        assert!(!VERSION.is_empty());
    }

    #[test]
    fn error_messages_are_readable() {
        let err = ParseError::Truncated {
            needed: 16,
            available: 4,
        };
        assert!(err.to_string().contains("truncated"));
    }
}
