//! The plugin host of `od3sa-recon`.
//!
//! The host is the boundary between the daemon and code the user wrote.
//! It reads the manifests, works out what each plugin may see, hands out
//! the token that says so, starts the plugins that run as daemons and
//! keeps them inside their memory budget.
//!
//! It is the implementation of `docs/PLUGIN-HOST.md`, which is the
//! contract, and it extends `docs/PLUGINS.md`, which describes the
//! manifest and the lifecycle.
//!
//! # The manifest
//!
//! `plugin.toml`, in the plugin's directory:
//!
//! ```toml
//! name = "wigle-export"
//! version = "0.1.0"
//! api = "0"                       # major API version
//! exec = "bin/wigle-export"       # relative to the plugin dir
//! run = "daemon"                  # "daemon" | "external"
//! capabilities = ["events:ap.*", "query:devices", "fs:write:/mmc/od3sa-recon/export"]
//! memory_mb = 8                   # budget; the host kills the plugin above 1.5x
//! network = false                 # true only for feed plugins
//! ```
//!
//! # The capabilities are the host's, not the plugin's
//!
//! A capability is not a promise the plugin makes. It is what the host
//! does:
//!
//! | Capability | What the host does |
//! |---|---|
//! | `events:ap.*` | the plugin's token only reaches the topics that match |
//! | `query:devices` | the plugin's token may call that method and no other |
//! | `fs:write:/mmc/od3sa-recon/export` | the plugin was allowed to write there |
//! | `network` | the plugin may open sockets |
//!
//! **There are no capabilities for radios, channels, transmission, `pineapd`
//! or `blue5`.** They do not exist, and the host does not offer them. A
//! manifest that asks for one is an error, and the plugin is not started.
//!
//! # The token
//!
//! Every plugin gets **its own** token, scoped to the capabilities its
//! manifest asked for. The secret goes into `OD3SA_TOKEN`; a server that
//! holds it asks [`PluginHost::authenticate`] and gets back the scopes it
//! may use. A plugin cannot read what it was not given, and it cannot use
//! another plugin's secret.
//!
//! The host **issues** the scope: it is what holds the token, what knows
//! what it may reach, and what says so. The event bus and the query
//! socket are the ones that check a request against the scope, and they
//! ask the host what a secret stands for. The host does not filter the
//! sockets itself, because the sockets are not its.
//!
//! # What the host does not do
//!
//! **The host does not sandbox the plugin's filesystem.** `fs:write:/path`
//! says where the plugin was *allowed* to write. The host has no way to
//! stop a plugin from writing elsewhere, and a plugin that writes outside
//! its path has broken its own rules. The same goes for the network: a
//! plugin whose manifest says `network = false` is not allowed to open
//! sockets, and the host does not stop it if it tries. A kernel-level
//! sandbox is out of scope, and nothing here pretends otherwise.
//!
//! # Nothing here touches a radio
//!
//! The host starts processes and watches their memory. There is no call in
//! this crate that opens a radio, changes a channel, stops a service, or
//! transmits anything. The plugins are read-only by design, and the API
//! has no call that touches radios.

#![forbid(unsafe_code)]

mod capability;
mod error;
mod host;
mod log;
mod manifest;
mod rss;
mod token;

#[cfg(test)]
mod tests;

pub use capability::{Capability, CapabilityError, path_is_under, topic_matches};
pub use error::HostError;
pub use host::{
    DEFAULT_EVENTS_SOCKET, DEFAULT_QUERY_SOCKET, ENV_EVENTS, ENV_QUERY, ENV_TOKEN, HostConfig,
    PING, PLUGIN_QUERY_SOCKET, PONG, PluginHost, PluginInfo, PluginState, PluginStatus,
    backoff_delay,
};
pub use log::LogDestination;
pub use manifest::{API_VERSION, DEFAULT_MEMORY_MB, MANIFEST_NAME, Manifest, ManifestError, Run};
pub use rss::resident_kb;
pub use token::{Scopes, Token};
