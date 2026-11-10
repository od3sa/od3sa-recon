//! The capabilities: what a plugin may see, and what it may not.
//!
//! A capability is not a promise the plugin makes. It is what the host
//! does:
//!
//! | Capability | What the host does |
//! |---|---|
//! | `events:ap.*` | the plugin's event token only receives the topics that match |
//! | `query:devices` | the plugin's query token may call that method and no other |
//! | `fs:write:/mmc/od3sa-recon/export` | the plugin is allowed to write there |
//! | `network` | the plugin may open sockets |
//!
//! **There are no capabilities for radios, channels, transmission, `pineapd`
//! or `blue5`.** They do not exist, and the host does not offer them. A
//! manifest that asks for one is an error, and the plugin is not started.

use std::fmt;
use std::path::{Path, PathBuf};

/// A capability, parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Capability {
    /// Events of the topics that match the pattern.
    Events(String),
    /// The named query method.
    Query(String),
    /// Writing under the path.
    Write(PathBuf),
    /// Opening sockets.
    Network,
}

/// Why a capability was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CapabilityError {
    /// There is no such capability.
    Unknown {
        /// The capability as it was written.
        capability: String,
    },
    /// The capability is one the host knows, but it was written wrongly.
    Malformed {
        /// The capability as it was written.
        capability: String,
        /// Why it was refused.
        reason: &'static str,
    },
}

impl fmt::Display for CapabilityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unknown { capability } => {
                write!(f, "there is no capability '{capability}'")
            }
            Self::Malformed { capability, reason } => {
                write!(f, "the capability '{capability}' is wrong: {reason}")
            }
        }
    }
}

impl std::error::Error for CapabilityError {}

impl Capability {
    /// Read a capability out of the string the manifest wrote.
    ///
    /// The four forms are `events:<pattern>`, `query:<method>`,
    /// `fs:write:<path>` and `network`. Everything else is refused.
    ///
    /// # Errors
    ///
    /// Returns an error when there is no such capability, and when one of
    /// the four forms is written wrongly.
    pub fn parse(text: &str) -> Result<Capability, CapabilityError> {
        let trimmed = text.trim();

        if let Some(pattern) = trimmed.strip_prefix("events:") {
            if pattern.is_empty() {
                return Err(CapabilityError::Malformed {
                    capability: trimmed.to_string(),
                    reason: "the topic pattern is empty",
                });
            }
            if pattern.contains('*') && !pattern.ends_with(".*") {
                return Err(CapabilityError::Malformed {
                    capability: trimmed.to_string(),
                    reason: "the only wildcard is a `.*` at the end",
                });
            }
            return Ok(Capability::Events(pattern.to_string()));
        }

        if let Some(method) = trimmed.strip_prefix("query:") {
            if method.is_empty() {
                return Err(CapabilityError::Malformed {
                    capability: trimmed.to_string(),
                    reason: "the method name is empty",
                });
            }
            if method.chars().any(char::is_whitespace) {
                return Err(CapabilityError::Malformed {
                    capability: trimmed.to_string(),
                    reason: "the method name holds a space",
                });
            }
            return Ok(Capability::Query(method.to_string()));
        }

        if let Some(path) = trimmed.strip_prefix("fs:write:") {
            if path.is_empty() {
                return Err(CapabilityError::Malformed {
                    capability: trimmed.to_string(),
                    reason: "the path is empty",
                });
            }
            let path = PathBuf::from(path);
            if !path.is_absolute() {
                return Err(CapabilityError::Malformed {
                    capability: trimmed.to_string(),
                    reason: "the path is not absolute",
                });
            }
            return Ok(Capability::Write(path));
        }

        if trimmed == "network" {
            return Ok(Capability::Network);
        }

        Err(CapabilityError::Unknown {
            capability: trimmed.to_string(),
        })
    }

    /// The capability as it was written.
    pub fn as_str(&self) -> String {
        match self {
            Self::Events(pattern) => format!("events:{pattern}"),
            Self::Query(method) => format!("query:{method}"),
            Self::Write(path) => format!("fs:write:{}", path.display()),
            Self::Network => "network".to_string(),
        }
    }
}

impl fmt::Display for Capability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.as_str())
    }
}

/// Whether a topic pattern matches a topic.
///
/// The rule is the bus's rule: `ap.*` matches `ap.new` and every other
/// `ap.` topic, and a pattern without a wildcard matches exactly one
/// topic.
pub fn topic_matches(pattern: &str, topic: &str) -> bool {
    let trimmed = pattern.trim();
    match trimmed.strip_suffix(".*") {
        Some(prefix) => {
            let prefix = format!("{prefix}.");
            topic.strip_prefix(prefix.as_str()).is_some_and(|_| {
                // The dot belongs to the prefix, so `ap.*` matches `ap.new`
                // and not `apple.new`.
                prefix.ends_with('.')
            })
        }
        None => trimmed == topic,
    }
}

/// Whether a path is under a root, the way a write path works.
///
/// The comparison is by path component, so `/mmc/od3sa-recon/export2` is
/// not under `/mmc/od3sa-recon/export`.
pub fn path_is_under(root: &Path, path: &Path) -> bool {
    path.starts_with(root)
}
