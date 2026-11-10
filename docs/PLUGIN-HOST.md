# Plugin host contract

The contract for the plugin host: manifests, capabilities, tokens,
supervision and memory budgets. It extends `docs/PLUGINS.md`, which describes
the manifest and the lifecycle; this document gives the API and the rules.

## Where it lives

`crates/od3sa-plugin`, its own crate: the plugin host is the boundary between
the daemon and code the user wrote, so it deserves to be its own thing with
its own tests.

## The manifest

`plugin.toml`, in the plugin's directory, as `docs/PLUGINS.md` gives it:

```toml
name = "wigle-export"
version = "0.1.0"
api = "0"                       # major API version
exec = "bin/wigle-export"       # relative to the plugin dir
run = "daemon"                  # "daemon" | "external"
capabilities = ["events:ap.*", "query:devices", "fs:write:/mmc/od3sa-recon/export"]
memory_mb = 8                   # budget; the host kills the plugin above 1.5x
network = false                 # true only for feed plugins
```

**The host enforces the capabilities.** They are not a promise the plugin
makes; they are what the host does:

| Capability | What the host does |
|---|---|
| `events:ap.*` | the plugin's event token only receives the topics that match |
| `query:devices` | the plugin's query token may call that method and no other |
| `fs:write:/mmc/od3sa-recon/export` | the plugin may write there and nowhere else |
| `network = true` | the plugin may open sockets; otherwise it may not |

**There are no capabilities for radios, channels, TX, `pineapd` or `blue5`.**
They do not exist, and the host does not offer them. A manifest that asks for
one is an error, not a request that is ignored.

## The API

```rust
/// What a manifest says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Manifest {
    pub name: String,
    pub version: String,
    pub api: u32,
    pub exec: std::path::PathBuf,
    pub run: Run,
    pub capabilities: Vec<String>,
    pub memory_mb: u64,
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

/// A capability, parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Capability {
    /// Events of the topics that match the pattern.
    Events(String),
    /// The named query method.
    Query(String),
    /// Writing under the path.
    Write(std::path::PathBuf),
    /// Opening sockets.
    Network,
}

/// The plugin host.
pub struct PluginHost { /* the plugins */ }

impl PluginHost {
    /// A host for the plugins in `dir`.
    pub fn new(dir: &Path) -> PluginHost;

    /// Read every manifest in the directory.
    ///
    /// A manifest that cannot be parsed, or that asks for a capability that
    /// does not exist, is an error for that plugin and does not stop the
    /// others.
    pub fn load(&mut self) -> Result<Vec<PluginInfo>, HostError>;

    /// Start the plugins that are `run = "daemon"`.
    pub fn start(&mut self) -> Result<(), HostError>;

    /// Stop every plugin.
    pub fn stop(&mut self);

    /// Check the plugins: are they alive, are they within their budget.
    pub fn check(&mut self) -> Vec<PluginStatus>;

    /// The plugins and their states.
    pub fn statuses(&self) -> &[PluginStatus];
}

/// What is known about one plugin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginInfo {
    pub manifest: Manifest,
    pub directory: std::path::PathBuf,
    pub capabilities: Vec<Capability>,
}

/// What a plugin is doing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginStatus {
    pub name: String,
    /// Running, stopped, restarting, or over its budget.
    pub state: PluginState,
    /// How many times it has been restarted.
    pub restarts: u32,
    /// Its resident set in kilobytes, when it is running.
    pub rss_kb: Option<u64>,
}

/// The state of a plugin.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PluginState {
    Running,
    Stopped,
    /// Restarting after a failure; the count of attempts so far.
    Restarting(u32),
    /// It was killed for exceeding its memory budget.
    OverBudget,
}
```

## The supervision

- **A plugin that exits is restarted**, with a backoff: the first restart
  after a second, then two, four, up to a minute between attempts. A plugin
  that keeps failing is left alone rather than restarted forever ✓.
- **A plugin that exceeds its budget is killed.** The budget is
  `memory_mb`; the host kills the plugin at 1.5 times that. Its resident set
  is read from `/proc/<pid>/status` (`VmRSS`) ✓ — the same source the device
  test uses for the daemon's own RSS ✓.
- **A plugin that is killed for its memory is not restarted immediately**: it
  is marked `OverBudget` and left stopped, because a plugin that wants more
  memory than it was given will want it again ✓.
- **Health is a ping.** The host sends `ping` on the plugin's query socket
  and expects `pong` ✓. A plugin that does not answer is restarted ✓.
- **The plugin's environment** is `OD3SA_EVENTS`, `OD3SA_QUERY` and
  `OD3SA_TOKEN` ✓ — the paths of the two sockets and the token the plugin
  may use ✓. The token is **the plugin's own**: it is scoped to that
  plugin's capabilities, so a plugin cannot read what it was not given ✓.
- **A plugin cannot write outside its `fs:write` paths.** Enforcing that
  needs a sandbox; what the host does *is* give the plugin a token that does
  not open a write path ✓ — the capability list is enforced by the host
  handing out only what was allowed, and the host says plainly in the
  manifest and the docs that a plugin that writes elsewhere is a plugin that
  has broken its own rules ✓. (A kernel-level sandbox is out of scope; say so
  in the docs rather than implying otherwise ✓.)
- **The total plugin memory is capped** — 20 MB by default across all of
  them ✓ — because the device has about 104 MB free and the daemon itself has
  a 15 MB budget ✓.

## The rules the host follows

- **A manifest that asks for a capability that does not exist is an error**,
  and the plugin is not started ✓. There is no capability for a radio, a
  channel, a transmission, or `pineapd` or `blue5` ✓.
- **A plugin's `api` major version must match the host's** ✓. A plugin built
  for another major version is refused ✓ — that is what the version is for.
- **The host never starts a plugin whose executable is not there** ✓.
- **The host writes the plugin's stdout and stderr to logread** ✓ — on the
  device that is `/dev/log`; on the build machine, stderr ✓.
- **The host runs the plugin as the same user as the daemon** ✓ and says so
  ✓. On the device that is root; dropping a plugin to a lesser user is a
  bigger question than this project has answered, so it does not pretend
  to.

## The tests

1. A manifest is read, and its capabilities are parsed ✓.
2. **A manifest that asks for a capability that does not exist is an error**,
   and the plugin is not started ✓ — try `radio:tx` and `pineapd:control` ✓.
3. **A plugin whose API major version does not match is refused** ✓.
4. **A plugin that exits is restarted**, and the backoff grows ✓.
5. **A plugin that exceeds 1.5 times its budget is killed** and marked
   `OverBudget` ✓ — use a small script that allocates memory ✓.
6. **A plugin's token is its own**: a plugin cannot read a query method its
   manifest did not ask for ✓. (This is about the token the host hands out ✓
   — the host must scope it ✓.)
7. A plugin that does not answer the ping is restarted ✓.
8. The plugin's environment carries the two socket paths and its token ✓.
9. A manifest that cannot be parsed does not stop the other plugins ✓.

For the tests, a plugin can be a shell script or a small binary written into
a temporary directory ✓ — the host does not care what a plugin is ✓.

## Constraints

- No `unwrap` or `expect` outside the tests: a plugin that misbehaves must
  not take the host down with it.
- The manifest is TOML and `toml` is already in the workspace. A new
  dependency has to be MIT-compatible.
- Nothing that touches a radio, and nothing that transmits.
- The plugin API has no call that reaches a radio, a channel or a service,
  and there is no capability that would allow one.
