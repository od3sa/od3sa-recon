//! The manifest: what a plugin says about itself.
//!
//! The manifest is `plugin.toml`, in the plugin's directory, as
//! `docs/PLUGINS.md` gives it:
//!
//! ```toml
//! name = "wigle-export"
//! version = "0.1.0"
//! api = 0                         # major API version
//! exec = "bin/wigle-export"       # relative to the plugin dir
//! run = "daemon"                  # "daemon" | "external"
//! capabilities = ["events:ap.*", "query:devices", "fs:write:/mmc/od3sa-recon/export"]
//! memory_mb = 8                   # budget; the host kills the plugin above 1.5x
//! network = false                 # true only for feed plugins
//! ```
//!
//! The manifest is read with `toml`, and it is read strictly: a field that
//! is missing, or a field that holds the wrong kind of thing, is an error
//! for that plugin and does not stop the others.

use std::fmt;
use std::path::PathBuf;

/// The major API version this host speaks.
///
/// A plugin whose manifest asks for another major version is refused.
pub const API_VERSION: u32 = 0;

/// The memory budget a plugin gets when the manifest does not say.
pub const DEFAULT_MEMORY_MB: u64 = 8;

/// The name of the manifest file, inside a plugin's directory.
pub const MANIFEST_NAME: &str = "plugin.toml";

/// What a manifest says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Manifest {
    /// The name of the plugin. It is what the host calls it in a log line
    /// and in a status reply.
    pub name: String,
    /// The version of the plugin, as the plugin's author wrote it.
    pub version: String,
    /// The major version of the API the plugin is built for.
    pub api: u32,
    /// The executable, relative to the plugin's directory.
    pub exec: PathBuf,
    /// How the plugin is run.
    pub run: Run,
    /// The capabilities, as they were written.
    ///
    /// They are parsed into [`Capability`](crate::Capability) values by the
    /// host, and a capability that does not exist is an error.
    pub capabilities: Vec<String>,
    /// The memory budget, in megabytes. The host kills the plugin when it
    /// is over one and a half times this.
    pub memory_mb: u64,
    /// Whether the plugin may open sockets.
    pub network: bool,
}

/// How the plugin is run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Run {
    /// The host starts it and supervises it.
    Daemon,
    /// It runs itself and connects to the host.
    External,
}

impl Run {
    /// The word the manifest uses for this.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Daemon => "daemon",
            Self::External => "external",
        }
    }

    /// Read the word the manifest uses.
    ///
    /// Returns `None` for a word that is neither `daemon` nor `external`.
    pub fn parse(text: &str) -> Option<Run> {
        match text.trim() {
            "daemon" => Some(Run::Daemon),
            "external" => Some(Run::External),
            _ => None,
        }
    }
}

impl fmt::Display for Run {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Why a manifest was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManifestError {
    /// The file is not TOML, or not a TOML table.
    Syntax(String),
    /// A field the manifest must have is not there.
    Missing {
        /// The field that is missing.
        field: &'static str,
    },
    /// A field holds something the host cannot use.
    Bad {
        /// The field that is wrong.
        field: &'static str,
        /// Why it was refused.
        reason: String,
    },
}

impl fmt::Display for ManifestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Syntax(reason) => write!(f, "it is not a valid manifest: {reason}"),
            Self::Missing { field } => write!(f, "the field '{field}' is missing"),
            Self::Bad { field, reason } => write!(f, "the field '{field}' is wrong: {reason}"),
        }
    }
}

impl std::error::Error for ManifestError {}

impl Manifest {
    /// Read a manifest out of TOML text.
    ///
    /// # Errors
    ///
    /// Returns an error when the text is not a TOML table, when a field the
    /// manifest must have is missing, or when a field holds something the
    /// host cannot use.
    pub fn parse(text: &str) -> Result<Manifest, ManifestError> {
        let value: toml::Value =
            toml::from_str(text).map_err(|error| ManifestError::Syntax(error.to_string()))?;
        let table = value
            .as_table()
            .ok_or_else(|| ManifestError::Syntax("it is not a table".to_string()))?;

        let name = required_string(table, "name")?.to_string();
        let version = required_string(table, "version")?.to_string();
        let api = required_integer(table, "api")? as u32;
        let exec = PathBuf::from(required_string(table, "exec")?);

        let run = match required_string(table, "run")? {
            "daemon" => Run::Daemon,
            "external" => Run::External,
            other => {
                return Err(ManifestError::Bad {
                    field: "run",
                    reason: format!("'{other}' is neither 'daemon' nor 'external'"),
                });
            }
        };

        let capabilities = string_list(table, "capabilities")?;
        let memory_mb = match table.get("memory_mb") {
            Some(toml::Value::Integer(value)) if *value >= 0 => *value as u64,
            Some(toml::Value::Integer(_)) => {
                return Err(ManifestError::Bad {
                    field: "memory_mb",
                    reason: "the budget cannot be negative".to_string(),
                });
            }
            Some(_) => {
                return Err(ManifestError::Bad {
                    field: "memory_mb",
                    reason: "the budget is not a whole number of megabytes".to_string(),
                });
            }
            None => DEFAULT_MEMORY_MB,
        };

        let network = match table.get("network") {
            Some(toml::Value::Boolean(value)) => *value,
            Some(_) => {
                return Err(ManifestError::Bad {
                    field: "network",
                    reason: "it is not true or false".to_string(),
                });
            }
            None => false,
        };

        Ok(Manifest {
            name,
            version,
            api,
            exec,
            run,
            capabilities,
            memory_mb,
            network,
        })
    }
}

/// Read a field that must be there and must be a string.
fn required_string<'a>(
    table: &'a toml::Table,
    field: &'static str,
) -> Result<&'a str, ManifestError> {
    match table.get(field) {
        Some(toml::Value::String(value)) => Ok(value),
        Some(_) => Err(ManifestError::Bad {
            field,
            reason: "it is not a string".to_string(),
        }),
        None => Err(ManifestError::Missing { field }),
    }
}

/// Read a field that must be there and must be a whole number.
fn required_integer(table: &toml::Table, field: &'static str) -> Result<i64, ManifestError> {
    match table.get(field) {
        Some(toml::Value::Integer(value)) => Ok(*value),
        Some(_) => Err(ManifestError::Bad {
            field,
            reason: "it is not a whole number".to_string(),
        }),
        None => Err(ManifestError::Missing { field }),
    }
}

/// Read a field that holds a list of strings. A field that is not there is
/// an empty list.
fn string_list(table: &toml::Table, field: &'static str) -> Result<Vec<String>, ManifestError> {
    match table.get(field) {
        None => Ok(Vec::new()),
        Some(toml::Value::Array(items)) => {
            let mut values = Vec::with_capacity(items.len());
            for item in items {
                match item.as_str() {
                    Some(text) => values.push(text.to_string()),
                    None => {
                        return Err(ManifestError::Bad {
                            field,
                            reason: "one of the items is not a string".to_string(),
                        });
                    }
                }
            }
            Ok(values)
        }
        Some(_) => Err(ManifestError::Bad {
            field,
            reason: "it is not a list of strings".to_string(),
        }),
    }
}
