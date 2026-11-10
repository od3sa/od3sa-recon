//! The host: the plugins, their supervision and their budgets.
//!
//! The host reads the manifests, hands out the tokens, starts the plugins
//! that run as daemons and keeps an eye on them: are they alive, do they
//! answer, are they inside their memory budget.
//!
//! # The rules
//!
//! - **A manifest that asks for a capability that does not exist is an
//!   error**, and the plugin is not started. There is no capability for a
//!   radio, a channel, a transmission, or `pineapd` or `blue5`.
//! - **A plugin's `api` major version must match the host's.** A plugin
//!   built for another major version is refused.
//! - **The host never starts a plugin whose executable is not there.**
//! - **A plugin that exits is restarted**, with a backoff: the first
//!   restart after a second, then two, four, up to a minute. A plugin that
//!   keeps failing is left alone rather than restarted forever.
//! - **A plugin that exceeds its budget is killed**, at one and a half
//!   times its `memory_mb`. Its resident set is read from
//!   `/proc/<pid>/status`, the `VmRSS` line.
//! - **A plugin that is killed for its memory is not restarted**: it is
//!   marked `OverBudget` and left stopped, because a plugin that wants
//!   more memory than it was given will want it again.
//! - **Health is a ping.** The host sends `ping` and expects `pong`; a
//!   plugin that does not answer is restarted.
//! - **The host runs the plugin as the same user as the daemon.** On the
//!   device the daemon runs as root, so the plugin runs as root too; the
//!   host does not drop privileges, and the manifest has no field that
//!   asks it to.
//! - **The host kills the plugin's process, not its process group.** A
//!   plugin that leaves processes behind keeps them: killing a group
//!   needs a signal call the standard library does not make, and the host
//!   does not shell out to do it.
//!
//! # What the host does not do
//!
//! **The host does not sandbox the plugin's filesystem.** `fs:write:/path`
//! says where the plugin was *allowed* to write. The host has no way to
//! stop a plugin from writing elsewhere, and a plugin that writes outside
//! its path has broken its own rules. The same goes for the network: a
//! plugin whose manifest says `network = false` is not allowed to open
//! sockets, and the host does not stop it if it tries. A kernel-level
//! sandbox is out of scope.
//!
//! Nothing in this crate opens a radio, changes a channel, or transmits.
//! The host starts processes and watches their memory.

use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::FileTypeExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::{Duration, Instant};

use crate::capability::Capability;
use crate::error::HostError;
use crate::log::{LogDestination, LogSink};
use crate::manifest::{API_VERSION, MANIFEST_NAME, Manifest, Run};
use crate::rss::resident_kb;
use crate::token::{Token, same_secret};

/// The default path of the event socket the plugins read.
pub const DEFAULT_EVENTS_SOCKET: &str = "/tmp/od3sa-recon/events.sock";

/// The default path of the query socket the plugins call.
pub const DEFAULT_QUERY_SOCKET: &str = "/tmp/od3sa-recon/query.sock";

/// The name of the socket a plugin serves for the host's pings, in the
/// plugin's own directory.
pub const PLUGIN_QUERY_SOCKET: &str = "query.sock";

/// The word the host sends when it pings a plugin.
pub const PING: &str = "ping";

/// The word a plugin answers a ping with.
pub const PONG: &str = "pong";

/// The environment variable that holds the path of the event socket.
pub const ENV_EVENTS: &str = "OD3SA_EVENTS";

/// The environment variable that holds the path of the query socket.
pub const ENV_QUERY: &str = "OD3SA_QUERY";

/// The environment variable that holds the plugin's own token.
pub const ENV_TOKEN: &str = "OD3SA_TOKEN";

/// How much over its budget a plugin is allowed to go before it is killed:
/// one and a half times `memory_mb`.
const MEMORY_KILL_NUMERATOR: u64 = 3;

/// And the denominator of the same factor: one and a half.
const MEMORY_KILL_DENOMINATOR: u64 = 2;

/// How the host is set up.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostConfig {
    /// The path of the event socket the plugins are told about.
    pub events_socket: PathBuf,
    /// The path of the query socket the plugins are told about.
    pub query_socket: PathBuf,
    /// How long between two pings.
    pub ping_interval: Duration,
    /// How long a plugin has to answer a ping before it is restarted.
    pub pong_timeout: Duration,
    /// How long the host waits before the first restart.
    pub restart_backoff: Duration,
    /// The longest the host waits between two restart attempts.
    pub max_backoff: Duration,
    /// How many times a plugin is restarted before the host leaves it
    /// alone.
    pub max_restarts: u32,
    /// The memory budget of all the plugins together, in megabytes.
    pub total_memory_mb: u64,
    /// Where the plugin output goes.
    pub log: LogDestination,
}

impl Default for HostConfig {
    fn default() -> HostConfig {
        HostConfig {
            events_socket: PathBuf::from(DEFAULT_EVENTS_SOCKET),
            query_socket: PathBuf::from(DEFAULT_QUERY_SOCKET),
            ping_interval: Duration::from_secs(30),
            pong_timeout: Duration::from_secs(10),
            restart_backoff: Duration::from_secs(1),
            max_backoff: Duration::from_secs(60),
            max_restarts: 5,
            total_memory_mb: 20,
            log: LogDestination::default(),
        }
    }
}

/// What is known about one plugin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginInfo {
    /// What the manifest said.
    pub manifest: Manifest,
    /// The directory the plugin lives in.
    pub directory: PathBuf,
    /// The capabilities, parsed.
    pub capabilities: Vec<Capability>,
}

/// What a plugin is doing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginStatus {
    /// The name of the plugin.
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
    /// It is running.
    Running,
    /// It is not running.
    Stopped,
    /// Restarting after a failure; the count of attempts so far.
    Restarting(u32),
    /// It was killed for exceeding its memory budget.
    OverBudget,
}

/// The plugin host.
///
/// The host owns the plugins in one directory: it reads their manifests,
/// hands out their tokens, starts them and watches them.
#[derive(Debug)]
pub struct PluginHost {
    /// Where the plugins live.
    dir: PathBuf,
    /// How the host is set up.
    config: HostConfig,
    /// The plugins.
    plugins: Vec<Plugin>,
    /// The errors of the plugins that did not load, or did not start.
    failures: Vec<HostError>,
    /// The last statuses the host worked out.
    statuses: Vec<PluginStatus>,
    /// Where the plugin output goes.
    log: LogSink,
}

/// One plugin, and what the host knows about it right now.
#[derive(Debug)]
struct Plugin {
    /// The manifest, the directory and the capabilities.
    info: PluginInfo,
    /// The plugin's own token.
    token: Token,
    /// What it is doing.
    state: PluginState,
    /// How many times it has been restarted.
    restarts: u32,
    /// How many times in a row the host has tried to bring it back.
    ///
    /// It is the count the backoff grows with, and it is reset when the
    /// plugin has stayed up long enough to be called steady.
    attempts: u32,
    /// When the next restart attempt is due.
    next_attempt: Option<Instant>,
    /// The process, while it runs.
    child: Option<Child>,
    /// When the process was started.
    started_at: Option<Instant>,
    /// The plugin's standard input, so that the host can ping it.
    stdin: Option<ChildStdin>,
    /// The pongs the plugin has sent.
    pongs: Receiver<Instant>,
    /// When the host last pinged.
    last_ping: Option<Instant>,
    /// Whether a ping is still unanswered.
    awaiting_pong: bool,
    /// When the unanswered ping runs out.
    pong_deadline: Option<Instant>,
    /// The resident set, as it was last read.
    rss_kb: Option<u64>,
    /// Whether the plugin was killed for its memory.
    over_budget: bool,
}

impl PluginHost {
    /// A host for the plugins in `dir`.
    ///
    /// The plugins are in the subdirectories of `dir`, each with a
    /// `plugin.toml` in it. When `dir` itself holds a `plugin.toml`, the
    /// directory is one plugin.
    pub fn new(dir: &Path) -> PluginHost {
        PluginHost::with_config(dir, HostConfig::default())
    }

    /// A host for the plugins in `dir`, set up as told.
    pub fn with_config(dir: &Path, config: HostConfig) -> PluginHost {
        PluginHost {
            dir: dir.to_path_buf(),
            log: LogSink::new(config.log),
            config,
            plugins: Vec::new(),
            failures: Vec::new(),
            statuses: Vec::new(),
        }
    }

    /// How the host is set up.
    pub fn config(&self) -> &HostConfig {
        &self.config
    }

    /// Read every manifest in the directory.
    ///
    /// A manifest that cannot be parsed, that asks for a capability that
    /// does not exist, or that is built for another major version of the
    /// API, is an error for that plugin and does not stop the others. The
    /// errors are in [`failures`](PluginHost::failures).
    ///
    /// # Errors
    ///
    /// Returns an error when the directory cannot be read.
    pub fn load(&mut self) -> Result<Vec<PluginInfo>, HostError> {
        self.plugins.clear();
        self.failures.clear();
        self.statuses.clear();

        let directories = self.plugin_directories()?;
        for directory in directories {
            match self.load_one(&directory) {
                Ok(plugin) => self.plugins.push(plugin),
                Err(error) => {
                    self.log_line(format!("{error}"));
                    self.failures.push(error);
                }
            }
        }

        self.refresh_statuses();
        Ok(self
            .plugins
            .iter()
            .map(|plugin| plugin.info.clone())
            .collect())
    }

    /// Start the plugins that are `run = "daemon"`.
    ///
    /// A plugin whose executable is not there, or that cannot be started,
    /// is an error for that plugin and does not stop the others. The
    /// errors are in [`failures`](PluginHost::failures).
    ///
    /// # Errors
    ///
    /// Returns an error only when the host itself cannot work; the errors
    /// of the plugins are recorded and returned by
    /// [`failures`](PluginHost::failures).
    pub fn start(&mut self) -> Result<(), HostError> {
        for index in 0..self.plugins.len() {
            if self.plugins[index].info.manifest.run != Run::Daemon {
                continue;
            }
            if let Err(error) = self.spawn(index) {
                self.log_line(format!("{error}"));
                self.failures.push(error);
                self.plugins[index].state = PluginState::Stopped;
            }
        }
        self.refresh_statuses();
        Ok(())
    }

    /// Stop every plugin.
    ///
    /// The plugins are killed, and their state becomes `Stopped`. A
    /// plugin that was over its budget stays over its budget: the host
    /// does not forget why it was killed.
    pub fn stop(&mut self) {
        for index in 0..self.plugins.len() {
            self.kill(index);
            if !self.plugins[index].over_budget {
                self.plugins[index].state = PluginState::Stopped;
            }
        }
        self.refresh_statuses();
    }

    /// Check the plugins: are they alive, are they within their budget.
    ///
    /// A plugin that has exited is scheduled for a restart, with the
    /// backoff the host keeps for it. A plugin that is over its memory
    /// budget is killed and marked `OverBudget`, and is not restarted. A
    /// plugin that does not answer the ping is killed and restarted.
    pub fn check(&mut self) -> Vec<PluginStatus> {
        let now = Instant::now();
        for index in 0..self.plugins.len() {
            self.check_one(index, now);
        }
        self.enforce_total_memory();
        self.refresh_statuses();
        self.statuses.clone()
    }

    /// The plugins and their states.
    pub fn statuses(&self) -> &[PluginStatus] {
        &self.statuses
    }

    /// The errors of the plugins that did not load, or did not start.
    pub fn failures(&self) -> &[HostError] {
        &self.failures
    }

    /// What is known about one plugin.
    pub fn info(&self, name: &str) -> Option<&PluginInfo> {
        self.plugins
            .iter()
            .find(|plugin| plugin.info.manifest.name == name)
            .map(|plugin| &plugin.info)
    }

    /// The token of one plugin.
    ///
    /// The token is the plugin's own: it is scoped to the capabilities the
    /// plugin's manifest asked for.
    pub fn token_for(&self, name: &str) -> Option<&Token> {
        self.plugins
            .iter()
            .find(|plugin| plugin.info.manifest.name == name)
            .map(|plugin| &plugin.token)
    }

    /// The token a secret stands for.
    ///
    /// A server that holds a plugin's secret asks the host this, and gets
    /// back the scopes the secret may use. A secret that is not the host's
    /// is refused.
    pub fn authenticate(&self, secret: &str) -> Option<&Token> {
        self.plugins
            .iter()
            .find(|plugin| same_secret(plugin.token.secret(), secret))
            .map(|plugin| &plugin.token)
    }

    /// How long the host will wait before it tries to restart a plugin.
    ///
    /// It is `None` when the plugin is not waiting for a restart.
    pub fn restart_delay(&self, name: &str) -> Option<Duration> {
        let plugin = self
            .plugins
            .iter()
            .find(|plugin| plugin.info.manifest.name == name)?;
        let due = plugin.next_attempt?;
        Some(due.saturating_duration_since(Instant::now()))
    }

    /// The directories the plugins live in.
    fn plugin_directories(&self) -> Result<Vec<PathBuf>, HostError> {
        if self.dir.join(MANIFEST_NAME).is_file() {
            return Ok(vec![self.dir.clone()]);
        }

        let mut directories = Vec::new();
        for entry in fs::read_dir(&self.dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() && path.join(MANIFEST_NAME).is_file() {
                directories.push(path);
            }
        }
        directories.sort();
        Ok(directories)
    }

    /// Read the manifest of one plugin and make its token.
    fn load_one(&self, directory: &Path) -> Result<Plugin, HostError> {
        let path = directory.join(MANIFEST_NAME);
        let text = fs::read_to_string(&path).map_err(|error| HostError::Manifest {
            plugin: directory.display().to_string(),
            reason: format!("it could not be read: {error}"),
        })?;

        let manifest = Manifest::parse(&text).map_err(|error| HostError::Manifest {
            plugin: directory.display().to_string(),
            reason: error.to_string(),
        })?;

        if manifest.api != API_VERSION {
            return Err(HostError::ApiVersion {
                plugin: manifest.name.clone(),
                found: manifest.api,
                expected: API_VERSION,
            });
        }

        let mut capabilities = Vec::with_capacity(manifest.capabilities.len());
        for capability in &manifest.capabilities {
            match Capability::parse(capability) {
                Ok(parsed) => capabilities.push(parsed),
                Err(_) => {
                    return Err(HostError::UnknownCapability {
                        plugin: manifest.name.clone(),
                        capability: capability.clone(),
                    });
                }
            }
        }

        if manifest.network && !capabilities.contains(&Capability::Network) {
            capabilities.push(Capability::Network);
        }

        let token = Token::new(&manifest.name, &capabilities);
        let (_sender, receiver) = mpsc::channel();

        Ok(Plugin {
            info: PluginInfo {
                manifest,
                directory: directory.to_path_buf(),
                capabilities,
            },
            token,
            state: PluginState::Stopped,
            restarts: 0,
            attempts: 0,
            next_attempt: None,
            child: None,
            started_at: None,
            stdin: None,
            pongs: receiver,
            last_ping: None,
            awaiting_pong: false,
            pong_deadline: None,
            rss_kb: None,
            over_budget: false,
        })
    }

    /// Start one plugin.
    fn spawn(&mut self, index: usize) -> Result<(), HostError> {
        let name = self.plugins[index].info.manifest.name.clone();
        let directory = self.plugins[index].info.directory.clone();
        let exec = directory.join(&self.plugins[index].info.manifest.exec);

        let metadata = match fs::metadata(&exec) {
            Ok(metadata) => metadata,
            Err(error) => {
                return Err(HostError::MissingExecutable {
                    plugin: name,
                    path: exec,
                    reason: error.to_string(),
                });
            }
        };
        if !metadata.is_file() {
            return Err(HostError::MissingExecutable {
                plugin: name,
                path: exec,
                reason: "it is not a file".to_string(),
            });
        }

        // A socket left over from an earlier run would be a socket nobody
        // answers on. Only a socket is removed: the host does not delete
        // files it does not own.
        let query_socket = directory.join(PLUGIN_QUERY_SOCKET);
        if let Ok(metadata) = fs::symlink_metadata(&query_socket)
            && metadata.file_type().is_socket()
        {
            let _ = fs::remove_file(&query_socket);
        }

        let mut command = Command::new(&exec);
        command.current_dir(&directory);
        command.env(ENV_EVENTS, &self.config.events_socket);
        command.env(ENV_QUERY, &self.config.query_socket);
        command.env(ENV_TOKEN, self.plugins[index].token.secret());
        command.stdin(Stdio::piped());
        command.stdout(Stdio::piped());
        command.stderr(Stdio::piped());

        let mut child = command.spawn().map_err(|error| HostError::Spawn {
            plugin: name.clone(),
            reason: error.to_string(),
        })?;

        let stdin = child.stdin.take();
        let stdout = child.stdout.take();
        let stderr = child.stderr.take();

        let (sender, receiver) = mpsc::channel();

        if let Some(stdout) = stdout {
            let sink = self.log.clone();
            let sender = sender.clone();
            let _ = thread::Builder::new()
                .name("od3sa-plugin-out".to_string())
                .spawn(move || {
                    for line in BufReader::new(stdout).lines() {
                        let Ok(line) = line else { break };
                        if line.trim() == PONG {
                            let _ = sender.send(Instant::now());
                        }
                        sink.write_line(&line);
                    }
                });
        }

        if let Some(stderr) = stderr {
            let sink = self.log.clone();
            let _ = thread::Builder::new()
                .name("od3sa-plugin-err".to_string())
                .spawn(move || {
                    for line in BufReader::new(stderr).lines() {
                        let Ok(line) = line else { break };
                        sink.write_line(&line);
                    }
                });
        }

        let plugin = &mut self.plugins[index];
        plugin.child = Some(child);
        plugin.started_at = Some(Instant::now());
        plugin.stdin = stdin;
        plugin.pongs = receiver;
        plugin.last_ping = None;
        plugin.awaiting_pong = false;
        plugin.pong_deadline = None;
        plugin.rss_kb = None;
        plugin.over_budget = false;
        plugin.state = PluginState::Running;

        Ok(())
    }

    /// Check one plugin.
    fn check_one(&mut self, index: usize, now: Instant) {
        match self.plugins[index].state {
            PluginState::Running => self.check_running(index, now),
            PluginState::Restarting(_) => self.check_restarting(index, now),
            PluginState::Stopped | PluginState::OverBudget => {}
        }
    }

    /// Check a plugin that should be running.
    fn check_running(&mut self, index: usize, now: Instant) {
        let pid = self.plugins[index].child.as_ref().map(|child| child.id());

        // Has it gone?
        let exited = match self.plugins[index].child.as_mut() {
            Some(child) => match child.try_wait() {
                Ok(Some(_)) => true,
                Ok(None) => false,
                Err(_) => true,
            },
            None => true,
        };
        if exited {
            self.plugins[index].child = None;
            self.plugins[index].stdin = None;
            self.on_exit(index);
            return;
        }

        // Is it inside its budget?
        if let Some(pid) = pid {
            let rss = resident_kb(pid);
            self.plugins[index].rss_kb = rss;
            if let Some(rss) = rss {
                let budget = kill_budget_kb(self.plugins[index].info.manifest.memory_mb);
                if rss > budget {
                    self.kill(index);
                    self.plugins[index].state = PluginState::OverBudget;
                    self.plugins[index].over_budget = true;
                    self.log_line(format!(
                        "plugin '{}' used {} kB, over its budget of {} kB: killed",
                        self.plugins[index].info.manifest.name, rss, budget
                    ));
                    return;
                }
            }
        }

        // Does it answer?
        if let Some(reason) = self.health(index, now) {
            self.log_line(format!(
                "plugin '{}': {reason}: restarted",
                self.plugins[index].info.manifest.name
            ));
            self.kill(index);
            self.on_exit(index);
        }
    }

    /// Check a plugin that is waiting for a restart.
    fn check_restarting(&mut self, index: usize, now: Instant) {
        let due = self.plugins[index]
            .next_attempt
            .is_none_or(|attempt| now >= attempt);
        if !due {
            return;
        }

        match self.spawn(index) {
            Ok(()) => {
                self.plugins[index].restarts += 1;
                self.plugins[index].next_attempt = None;
                self.log_line(format!(
                    "plugin '{}' was restarted",
                    self.plugins[index].info.manifest.name
                ));
            }
            Err(error) => {
                self.log_line(format!("{error}"));
                self.failures.push(error);
                self.plugins[index].state = PluginState::Stopped;
                self.plugins[index].next_attempt = None;
            }
        }
    }

    /// What the plugin has exited, and what the host does about it.
    fn on_exit(&mut self, index: usize) {
        // A plugin that stayed up long enough is not a plugin that keeps
        // failing: it starts over with a short backoff.
        let steady = self.plugins[index]
            .started_at
            .is_some_and(|started| started.elapsed() >= self.config.max_backoff);
        if steady {
            self.plugins[index].attempts = 0;
        }
        self.plugins[index].started_at = None;

        let plugin = &mut self.plugins[index];

        if plugin.over_budget {
            plugin.state = PluginState::OverBudget;
            return;
        }

        plugin.attempts += 1;

        if plugin.attempts > self.config.max_restarts {
            plugin.state = PluginState::Stopped;
            plugin.next_attempt = None;
            let name = plugin.info.manifest.name.clone();
            let attempts = plugin.attempts;
            self.log_line(format!(
                "plugin '{name}' failed {attempts} times: left alone"
            ));
            return;
        }

        plugin.state = PluginState::Restarting(plugin.attempts);
        plugin.next_attempt = Some(
            Instant::now()
                + backoff_delay(
                    self.config.restart_backoff,
                    plugin.attempts,
                    self.config.max_backoff,
                ),
        );
    }

    /// Ping the plugin and say whether it answered.
    ///
    /// The host pings on the plugin's own query socket when the plugin
    /// serves one, and on the plugin's standard input otherwise. A plugin
    /// that answers neither is restarted.
    fn health(&mut self, index: usize, now: Instant) -> Option<String> {
        // A pong that came in clears the ping that was waiting for it.
        {
            let plugin = &mut self.plugins[index];
            let mut answered = false;
            while plugin.pongs.try_recv().is_ok() {
                answered = true;
            }
            if answered {
                plugin.awaiting_pong = false;
                plugin.pong_deadline = None;
            }
        }

        let socket = self.plugins[index].info.directory.join(PLUGIN_QUERY_SOCKET);

        let due = self.plugins[index]
            .last_ping
            .is_none_or(|last| now.duration_since(last) >= self.config.ping_interval);

        if socket.exists() {
            // The plugin serves its own socket: the ping goes there. The
            // answer comes back at once, so there is nothing to wait for.
            self.plugins[index].awaiting_pong = false;
            self.plugins[index].pong_deadline = None;
            if !due {
                return None;
            }
            self.plugins[index].last_ping = Some(now);
            if socket_ping(&socket, self.config.pong_timeout) {
                return None;
            }
            return Some(format!(
                "it did not answer the ping on {}",
                socket.display()
            ));
        }

        if due && !self.plugins[index].awaiting_pong {
            self.plugins[index].last_ping = Some(now);
            self.plugins[index].awaiting_pong = true;
            self.plugins[index].pong_deadline = Some(now + self.config.pong_timeout);
            write_ping(&mut self.plugins[index].stdin);
        }

        if self.plugins[index].awaiting_pong {
            let expired = self.plugins[index]
                .pong_deadline
                .is_some_and(|deadline| now >= deadline);
            if expired {
                return Some("it did not answer the ping".to_string());
            }
        }

        None
    }

    /// Kill the plugin, if it runs.
    fn kill(&mut self, index: usize) {
        if let Some(mut child) = self.plugins[index].child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        self.plugins[index].stdin = None;
        self.plugins[index].rss_kb = None;
    }

    /// Keep all the plugins inside the budget they share.
    ///
    /// The device has about 104 MB free and the daemon has a 15 MB budget
    /// of its own, so all the plugins together may not use more than
    /// `total_memory_mb`. When they do, the biggest one is killed.
    fn enforce_total_memory(&mut self) {
        let cap = self.config.total_memory_mb * 1024;
        let mut total = 0u64;
        let mut biggest: Option<(usize, u64)> = None;

        for (index, plugin) in self.plugins.iter().enumerate() {
            if plugin.state != PluginState::Running {
                continue;
            }
            let Some(rss) = plugin.rss_kb else { continue };
            total += rss;
            if biggest.is_none_or(|(_, other)| rss > other) {
                biggest = Some((index, rss));
            }
        }

        if total <= cap {
            return;
        }

        if let Some((index, rss)) = biggest {
            let name = self.plugins[index].info.manifest.name.clone();
            self.kill(index);
            self.plugins[index].state = PluginState::OverBudget;
            self.plugins[index].over_budget = true;
            self.log_line(format!(
                "plugin '{name}' used {rss} kB and the plugins together are over their budget: killed"
            ));
        }
    }

    /// Write out the statuses.
    fn refresh_statuses(&mut self) {
        self.statuses = self
            .plugins
            .iter()
            .map(|plugin| PluginStatus {
                name: plugin.info.manifest.name.clone(),
                state: plugin.state,
                restarts: plugin.restarts,
                rss_kb: if plugin.state == PluginState::Running {
                    plugin.rss_kb
                } else {
                    None
                },
            })
            .collect();
    }

    /// Write a line to the log.
    fn log_line(&self, line: String) {
        self.log.write_line(&line);
    }
}

/// The resident set, in kilobytes, at which a plugin is killed: one and a
/// half times its budget.
fn kill_budget_kb(memory_mb: u64) -> u64 {
    memory_mb * 1024 * MEMORY_KILL_NUMERATOR / MEMORY_KILL_DENOMINATOR
}

/// How long the host waits before the `attempt`th restart.
///
/// The first restart waits `base`, the next twice as long, and so on, up
/// to `max`.
pub fn backoff_delay(base: Duration, attempt: u32, max: Duration) -> Duration {
    if attempt == 0 {
        return base.min(max);
    }
    let factor = 1u64 << (attempt - 1).min(32);
    base.saturating_mul(u32::try_from(factor).unwrap_or(u32::MAX))
        .min(max)
}

/// Ping a plugin on the socket it serves and wait for the answer.
fn socket_ping(path: &Path, timeout: Duration) -> bool {
    let (sender, receiver) = mpsc::channel();
    let path = path.to_path_buf();

    let _ = thread::Builder::new()
        .name("od3sa-plugin-ping".to_string())
        .spawn(move || {
            let _ = sender.send(ping_over_socket(&path));
        });

    receiver.recv_timeout(timeout).unwrap_or(false)
}

/// Ask a plugin, over its own socket, whether it is there.
fn ping_over_socket(path: &Path) -> bool {
    let Ok(mut stream) = UnixStream::connect(path) else {
        return false;
    };
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));

    if stream.write_all(b"ping\n").is_err() {
        return false;
    }
    let _ = stream.flush();

    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    match reader.read_line(&mut line) {
        Ok(0) => false,
        Ok(_) => line.trim() == PONG,
        Err(_) => false,
    }
}

/// Write the ping on the plugin's standard input.
fn write_ping(stdin: &mut Option<ChildStdin>) {
    let Some(stdin) = stdin.as_mut() else {
        return;
    };
    let _ = stdin.write_all(b"ping\n");
    let _ = stdin.flush();
}
