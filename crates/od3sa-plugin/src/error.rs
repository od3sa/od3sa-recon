//! What went wrong in the plugin host.

use std::fmt;
use std::io;
use std::path::PathBuf;

/// Something went wrong with a plugin, or with the host itself.
///
/// Most of these are errors for **one plugin**: a manifest that cannot be
/// read, a capability that does not exist, an API version that does not
/// match. The host records them and carries on with the other plugins.
#[derive(Debug)]
#[non_exhaustive]
pub enum HostError {
    /// The plugins directory, or a file in it, could not be used.
    Io(io::Error),
    /// A manifest could not be read or parsed.
    Manifest {
        /// The plugin the manifest belongs to.
        plugin: String,
        /// Why the manifest was refused.
        reason: String,
    },
    /// A manifest asked for a capability that does not exist.
    ///
    /// There is no capability for a radio, a channel, a transmission, or
    /// `pineapd` or `blue5`. A manifest that asks for one is refused, not
    /// quietly ignored.
    UnknownCapability {
        /// The plugin the manifest belongs to.
        plugin: String,
        /// The capability as it was written.
        capability: String,
    },
    /// The plugin is built for another major version of the API.
    ApiVersion {
        /// The plugin the manifest belongs to.
        plugin: String,
        /// The major version the plugin asks for.
        found: u32,
        /// The major version this host speaks.
        expected: u32,
    },
    /// The plugin's executable is not there.
    MissingExecutable {
        /// The plugin the manifest belongs to.
        plugin: String,
        /// Where the executable was looked for.
        path: PathBuf,
        /// Why it was not found.
        reason: String,
    },
    /// The plugin could not be started.
    Spawn {
        /// The plugin the manifest belongs to.
        plugin: String,
        /// Why the start failed.
        reason: String,
    },
}

impl HostError {
    /// The plugin the error is about, when it is about one plugin.
    pub fn plugin(&self) -> Option<&str> {
        match self {
            Self::Io(_) => None,
            Self::Manifest { plugin, .. }
            | Self::UnknownCapability { plugin, .. }
            | Self::ApiVersion { plugin, .. }
            | Self::MissingExecutable { plugin, .. }
            | Self::Spawn { plugin, .. } => Some(plugin),
        }
    }
}

impl fmt::Display for HostError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(source) => write!(f, "plugin host error: {source}"),
            Self::Manifest { plugin, reason } => {
                write!(f, "plugin '{plugin}': bad manifest: {reason}")
            }
            Self::UnknownCapability { plugin, capability } => write!(
                f,
                "plugin '{plugin}': there is no capability '{capability}'"
            ),
            Self::ApiVersion {
                plugin,
                found,
                expected,
            } => write!(
                f,
                "plugin '{plugin}': API version {found} does not match the host's {expected}"
            ),
            Self::MissingExecutable {
                plugin,
                path,
                reason,
            } => write!(
                f,
                "plugin '{plugin}': the executable '{}' is not there: {reason}",
                path.display()
            ),
            Self::Spawn { plugin, reason } => {
                write!(f, "plugin '{plugin}': it could not be started: {reason}")
            }
        }
    }
}

impl std::error::Error for HostError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(source) => Some(source),
            _ => None,
        }
    }
}

impl From<io::Error> for HostError {
    fn from(source: io::Error) -> HostError {
        HostError::Io(source)
    }
}
