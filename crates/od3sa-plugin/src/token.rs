//! The token: what a plugin may reach, and nothing more.
//!
//! Every plugin gets **its own** token. The token is scoped to the
//! capabilities the plugin's manifest asked for: its event token reaches
//! the topics it asked for and no others, and its query token calls the
//! methods it asked for and no others. A plugin that has the secret of
//! another plugin learns nothing with it.
//!
//! The host keeps the token and hands the secret to the plugin in
//! `OD3SA_TOKEN`. A server that wants to check a token asks the host
//! [`PluginHost::authenticate`](crate::PluginHost::authenticate), which
//! gives back the scopes it may use. The host issues the scope; the event
//! bus and the query socket are the ones that check a request against it.

use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::capability::{Capability, path_is_under, topic_matches};

/// What a token allows.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Scopes {
    /// The topic patterns the plugin may receive events of.
    pub events: Vec<String>,
    /// The query methods the plugin may call.
    pub query: Vec<String>,
    /// The paths the plugin is allowed to write under.
    pub write: Vec<PathBuf>,
    /// Whether the plugin may open sockets.
    pub network: bool,
}

/// A plugin's token: the secret it presents and what that secret may do.
///
/// The secret is the string that goes into `OD3SA_TOKEN`. The scopes are
/// what the secret stands for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Token {
    /// The plugin the token belongs to.
    plugin: String,
    /// The secret the plugin presents.
    secret: String,
    /// What the secret may do.
    scopes: Scopes,
}

impl Token {
    /// Make a token for a plugin, with the scopes its capabilities ask for.
    ///
    /// The secret is fresh: two plugins never share one, and a token that
    /// is made again for the same plugin is a different secret.
    pub fn new(plugin: &str, capabilities: &[Capability]) -> Token {
        let mut scopes = Scopes::default();

        for capability in capabilities {
            match capability {
                Capability::Events(pattern) => scopes.events.push(pattern.clone()),
                Capability::Query(method) => scopes.query.push(method.clone()),
                Capability::Write(path) => scopes.write.push(path.clone()),
                Capability::Network => scopes.network = true,
            }
        }

        Token {
            plugin: plugin.to_string(),
            secret: generate_secret(),
            scopes,
        }
    }

    /// The plugin the token belongs to.
    pub fn plugin(&self) -> &str {
        &self.plugin
    }

    /// The secret the plugin presents.
    pub fn secret(&self) -> &str {
        &self.secret
    }

    /// What the secret may do.
    pub fn scopes(&self) -> &Scopes {
        &self.scopes
    }

    /// Whether the token may receive an event of this topic.
    pub fn allows_topic(&self, topic: &str) -> bool {
        self.scopes
            .events
            .iter()
            .any(|pattern| topic_matches(pattern, topic))
    }

    /// Whether the token may call this query method.
    pub fn allows_method(&self, method: &str) -> bool {
        self.scopes.query.iter().any(|name| name == method)
    }

    /// Whether the token may write under this path.
    ///
    /// The host does not stop a plugin from writing elsewhere: it has no
    /// sandbox. What it does is say, in the token, where the plugin was
    /// allowed to write.
    pub fn allows_write(&self, path: &Path) -> bool {
        self.scopes
            .write
            .iter()
            .any(|root| path_is_under(root, path))
    }

    /// Whether the token may open sockets.
    pub fn allows_network(&self) -> bool {
        self.scopes.network
    }
}

/// Whether two secrets are the same, without leaking how much of them
/// matched.
pub(crate) fn same_secret(left: &str, right: &str) -> bool {
    let left = left.as_bytes();
    let right = right.as_bytes();
    if left.len() != right.len() {
        return false;
    }
    let mut difference = 0u8;
    for (a, b) in left.iter().zip(right.iter()) {
        difference |= a ^ b;
    }
    difference == 0
}

/// Make a fresh secret.
///
/// The secret is 32 bytes from `/dev/urandom`, written out as hex. When
/// `/dev/urandom` is not there the secret falls back to a mix of the
/// clock, the process id and a counter, which is weaker and is only good
/// enough to tell two plugins apart on one machine.
fn generate_secret() -> String {
    let mut bytes = [0u8; 32];
    if let Ok(mut file) = File::open("/dev/urandom")
        && file.read_exact(&mut bytes).is_ok()
    {
        return hex(&bytes);
    }
    hex(&fallback_bytes())
}

/// The weaker secret, for a machine without `/dev/urandom`.
fn fallback_bytes() -> [u8; 32] {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|since| since.as_nanos() as u64)
        .unwrap_or(0);
    let pid = u64::from(std::process::id());

    let mut bytes = [0u8; 32];
    let mut state = nanos ^ (pid << 32);
    for chunk in bytes.chunks_mut(8) {
        state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut mixed = state;
        mixed = (mixed ^ (mixed >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        mixed = (mixed ^ (mixed >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        mixed ^= mixed >> 31;
        chunk.copy_from_slice(&mixed.to_le_bytes());
    }
    bytes
}

/// Write bytes out as hex.
fn hex(bytes: &[u8]) -> String {
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        text.push(char::from_digit(u32::from(byte >> 4), 16).unwrap_or('0'));
        text.push(char::from_digit(u32::from(byte & 0x0f), 16).unwrap_or('0'));
    }
    text
}
