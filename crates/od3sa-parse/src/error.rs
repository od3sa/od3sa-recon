//! The shared parse error type.

use core::fmt;

/// A parse failure.
///
/// Every variant carries enough context to debug a malformed frame from a log
/// line alone, and nothing that could leak payload bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    /// The buffer ended before the requested number of bytes was available.
    Truncated {
        /// Bytes the parser needed.
        needed: usize,
        /// Bytes actually available.
        available: usize,
    },
    /// A fixed-size structure did not fit in the buffer.
    TooShort {
        /// Minimum size the structure requires.
        expected: usize,
        /// Size of the buffer.
        available: usize,
    },
    /// The bytes were long enough but not valid for this field.
    Invalid(&'static str),
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated { needed, available } => {
                write!(f, "truncated: needed {needed} bytes, {available} available")
            }
            Self::TooShort {
                expected,
                available,
            } => write!(
                f,
                "too short: expected at least {expected} bytes, {available} available"
            ),
            Self::Invalid(reason) => write!(f, "invalid: {reason}"),
        }
    }
}

impl core::error::Error for ParseError {}

/// The result type used throughout the crate.
pub type Result<T> = core::result::Result<T, ParseError>;

/// Borrow `len` bytes from the front of `buf`, or fail with
/// [`ParseError::Truncated`].
///
/// This is the single bounds-checking primitive every parser in the crate is
/// built on. The radiotap and 802.11 parsers use it in OR-101 and OR-102.
#[allow(dead_code)]
pub(crate) fn take(buf: &[u8], len: usize) -> Result<&[u8]> {
    buf.get(..len).ok_or(ParseError::Truncated {
        needed: len,
        available: buf.len(),
    })
}
