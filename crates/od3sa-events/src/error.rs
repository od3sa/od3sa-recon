//! What went wrong.

use std::fmt;
use std::io;

/// Something went wrong in the event bus.
#[derive(Debug)]
#[non_exhaustive]
pub enum EventError {
    /// The socket or the file behind it could not be used.
    Io(io::Error),
    /// A topic pattern could not be parsed.
    BadPattern {
        /// The pattern as it was written.
        pattern: String,
        /// Why it was refused.
        reason: &'static str,
    },
}

impl fmt::Display for EventError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(source) => write!(f, "event bus error: {source}"),
            Self::BadPattern { pattern, reason } => {
                write!(
                    f,
                    "event bus error: bad topic pattern '{pattern}': {reason}"
                )
            }
        }
    }
}

impl std::error::Error for EventError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(source) => Some(source),
            Self::BadPattern { .. } => None,
        }
    }
}

impl From<io::Error> for EventError {
    fn from(source: io::Error) -> EventError {
        EventError::Io(source)
    }
}
