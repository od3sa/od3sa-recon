//! The tests of the plugin host.
//!
//! A plugin in a test is a small shell script written into a temporary
//! directory: the host does not care what a plugin is.
//!
//! One test needs a plugin that serves a socket, and a shell script cannot
//! serve one. That test starts this very test binary as the plugin: the
//! environment variable [`FIXTURE_ENV`] tells it to be a plugin instead of
//! a test run.

use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use super::*;

/// The environment variable that turns this test binary into a plugin.
const FIXTURE_ENV: &str = "OD3SA_TEST_PLUGIN_FIXTURE";

/// The mode this test binary runs in, when it was started as a plugin.
fn fixture_mode() -> Option<String> {
    std::env::var(FIXTURE_ENV).ok()
}

/// A directory that goes away with the test.
struct TempDir {
    path: PathBuf,
}

impl TempDir {
    /// A new directory, with a name of its own.
    fn new(tag: &str) -> TempDir {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|since| since.as_nanos())
            .unwrap_or(0);
        let path =
            std::env::temp_dir().join(format!("od3sa-plugin-{tag}-{}-{nanos}", std::process::id()));
        fs::create_dir_all(&path).expect("the temporary directory is made");
        TempDir { path }
    }

    /// The directory itself.
    fn path(&self) -> &Path {
        &self.path
    }

    /// A plugin in a directory of its own: a manifest and a script.
    fn plugin(&self, name: &str, manifest: &str, script: &str) -> PathBuf {
        let directory = self.path.join(name);
        fs::create_dir_all(&directory).expect("the plugin directory is made");
        fs::write(directory.join(MANIFEST_NAME), manifest).expect("the manifest is written");
        self.script(&directory, script);
        directory
    }

    /// The script of a plugin.
    fn script(&self, directory: &Path, script: &str) {
        let path = directory.join("run.sh");
        fs::write(&path, script).expect("the script is written");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755))
            .expect("the script is made executable");
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

/// A manifest with the given capabilities.
fn manifest(name: &str, capabilities: &str, memory_mb: u64) -> String {
    format!(
        "name = \"{name}\"\n\
         version = \"0.1.0\"\n\
         api = 0\n\
         exec = \"run.sh\"\n\
         run = \"daemon\"\n\
         capabilities = [{capabilities}]\n\
         memory_mb = {memory_mb}\n\
         network = false\n"
    )
}

/// A script that leaves a mark, so that the test can see it ran.
fn marker_script() -> String {
    "#!/bin/sh\ntouch ran\nexec sleep 30\n".to_string()
}

/// Whether the plugin ran.
fn ran(directory: &Path) -> bool {
    directory.join("ran").exists()
}

/// A host that is quick about the pings and the backoff.
fn config() -> HostConfig {
    HostConfig {
        ping_interval: Duration::from_millis(100),
        pong_timeout: Duration::from_millis(300),
        restart_backoff: Duration::from_millis(100),
        max_backoff: Duration::from_secs(1),
        max_restarts: 3,
        total_memory_mb: 20,
        log: LogDestination::Stderr,
        ..HostConfig::default()
    }
}

/// A host that leaves the plugins alone for a while.
fn quiet_config() -> HostConfig {
    HostConfig {
        ping_interval: Duration::from_secs(300),
        pong_timeout: Duration::from_secs(300),
        restart_backoff: Duration::from_millis(100),
        max_backoff: Duration::from_secs(1),
        max_restarts: 3,
        total_memory_mb: 20,
        log: LogDestination::Stderr,
        ..HostConfig::default()
    }
}

/// Wait for a condition, up to a limit.
fn wait_for(mut condition: impl FnMut() -> bool, limit: Duration) -> bool {
    let start = Instant::now();
    while start.elapsed() < limit {
        if condition() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    condition()
}

/// The state of one plugin.
fn state_of(host: &PluginHost, name: &str) -> Option<PluginState> {
    host.statuses()
        .iter()
        .find(|status| status.name == name)
        .map(|status| status.state)
}

/// The restarts of one plugin.
fn restarts_of(host: &PluginHost, name: &str) -> u32 {
    host.statuses()
        .iter()
        .find(|status| status.name == name)
        .map(|status| status.restarts)
        .unwrap_or(0)
}

/// Test 1: a manifest is read, and its capabilities are parsed.
#[test]
fn a_manifest_is_read_and_its_capabilities_are_parsed() {
    if fixture_mode().is_some() {
        return;
    }

    let dir = TempDir::new("read");
    dir.plugin(
        "exporter",
        &manifest(
            "exporter",
            "\"events:ap.*\", \"query:devices\", \"fs:write:/tmp/od3sa-export\"",
            8,
        ),
        &marker_script(),
    );

    let mut host = PluginHost::with_config(dir.path(), config());
    let loaded = host.load().expect("the manifests are read");

    assert_eq!(loaded.len(), 1);
    let info = &loaded[0];
    assert_eq!(info.manifest.name, "exporter");
    assert_eq!(info.manifest.version, "0.1.0");
    assert_eq!(info.manifest.api, 0);
    assert_eq!(info.manifest.exec, PathBuf::from("run.sh"));
    assert_eq!(info.manifest.run, Run::Daemon);
    assert_eq!(info.manifest.memory_mb, 8);
    assert!(!info.manifest.network);
    assert_eq!(
        info.capabilities,
        vec![
            Capability::Events("ap.*".to_string()),
            Capability::Query("devices".to_string()),
            Capability::Write(PathBuf::from("/tmp/od3sa-export")),
        ]
    );

    host.stop();
}

/// Test 2: a manifest that asks for a capability that does not exist is an
/// error, and the plugin is not started.
#[test]
fn a_capability_that_does_not_exist_is_refused_and_the_plugin_is_not_started() {
    if fixture_mode().is_some() {
        return;
    }

    let dir = TempDir::new("refused");
    let radio = dir.plugin(
        "radio",
        &manifest("radio", "\"radio:tx\"", 8),
        &marker_script(),
    );
    let pineapd = dir.plugin(
        "pineapd",
        &manifest("pineapd", "\"pineapd:control\"", 8),
        &marker_script(),
    );
    let blue5 = dir.plugin(
        "blue5",
        &manifest("blue5", "\"blue5:control\"", 8),
        &marker_script(),
    );
    dir.plugin(
        "good",
        &manifest("good", "\"query:devices\"", 8),
        &marker_script(),
    );

    let mut host = PluginHost::with_config(dir.path(), config());
    let loaded = host.load().expect("the manifests are read");

    // The plugins that asked for something that does not exist are gone.
    assert_eq!(loaded.len(), 1);
    assert_eq!(loaded[0].manifest.name, "good");

    // The errors say what was refused.
    let errors: Vec<String> = host
        .failures()
        .iter()
        .map(|error| error.to_string())
        .collect();
    assert!(
        errors.iter().any(|error| error.contains("radio:tx")),
        "the radio capability is refused: {errors:?}"
    );
    assert!(
        errors.iter().any(|error| error.contains("pineapd:control")),
        "the pineapd capability is refused: {errors:?}"
    );
    assert!(
        errors.iter().any(|error| error.contains("blue5:control")),
        "the blue5 capability is refused: {errors:?}"
    );

    // And they are not started.
    host.start().expect("the plugins are started");
    assert!(!ran(&radio), "the radio plugin did not run");
    assert!(!ran(&pineapd), "the pineapd plugin did not run");
    assert!(!ran(&blue5), "the blue5 plugin did not run");

    host.stop();
}

/// Test 3: a plugin whose API major version does not match is refused.
#[test]
fn a_plugin_for_another_api_version_is_refused() {
    if fixture_mode().is_some() {
        return;
    }

    let dir = TempDir::new("api");
    let old = dir.plugin(
        "old",
        "name = \"old\"\n\
         version = \"0.1.0\"\n\
         api = 1\n\
         exec = \"run.sh\"\n\
         run = \"daemon\"\n\
         capabilities = []\n\
         memory_mb = 8\n\
         network = false\n",
        &marker_script(),
    );
    dir.plugin(
        "new",
        &manifest("new", "\"query:devices\"", 8),
        &marker_script(),
    );

    let mut host = PluginHost::with_config(dir.path(), config());
    let loaded = host.load().expect("the manifests are read");

    assert_eq!(loaded.len(), 1);
    assert_eq!(loaded[0].manifest.name, "new");

    let errors: Vec<String> = host
        .failures()
        .iter()
        .map(|error| error.to_string())
        .collect();
    assert!(
        errors.iter().any(|error| error.contains("API version 1")),
        "the version mismatch is reported: {errors:?}"
    );

    host.start().expect("the plugins are started");
    assert!(!ran(&old), "the plugin for another version did not run");

    host.stop();
}

/// Test 4: a plugin that exits is restarted, and the backoff grows.
#[test]
fn a_plugin_that_exits_is_restarted_and_the_backoff_grows() {
    if fixture_mode().is_some() {
        return;
    }

    // The backoff itself: a second, then two, then four, up to a minute.
    assert_eq!(
        backoff_delay(Duration::from_secs(1), 1, Duration::from_secs(60)),
        Duration::from_secs(1)
    );
    assert_eq!(
        backoff_delay(Duration::from_secs(1), 2, Duration::from_secs(60)),
        Duration::from_secs(2)
    );
    assert_eq!(
        backoff_delay(Duration::from_secs(1), 3, Duration::from_secs(60)),
        Duration::from_secs(4)
    );
    assert_eq!(
        backoff_delay(Duration::from_secs(1), 30, Duration::from_secs(60)),
        Duration::from_secs(60)
    );

    let dir = TempDir::new("restart");
    dir.plugin(
        "quick",
        &manifest("quick", "\"query:devices\"", 8),
        "#!/bin/sh\nexit 0\n",
    );

    let mut host = PluginHost::with_config(dir.path(), config());
    host.load().expect("the manifests are read");
    host.start().expect("the plugins are started");

    // The plugin exits at once, and is brought back. The attempts are
    // counted from the first check, so that the growing wait is seen.
    let mut attempts: Vec<u32> = Vec::new();
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(20) {
        host.check();
        if let Some(PluginState::Restarting(attempt)) = state_of(&host, "quick")
            && attempts.last() != Some(&attempt)
        {
            attempts.push(attempt);
        }
        if restarts_of(&host, "quick") >= 2 {
            break;
        }
        std::thread::sleep(Duration::from_millis(5));
    }

    assert!(
        restarts_of(&host, "quick") >= 1,
        "the plugin was restarted: {attempts:?}"
    );
    assert!(
        attempts.len() >= 2,
        "the plugin was restarted more than once: {attempts:?}"
    );
    assert!(
        attempts[1] > attempts[0],
        "the attempt count grows: {attempts:?}"
    );

    // A plugin that keeps failing is left alone rather than restarted
    // forever.
    assert!(
        wait_for(
            || {
                host.check();
                state_of(&host, "quick") == Some(PluginState::Stopped)
            },
            Duration::from_secs(20)
        ),
        "the plugin that keeps failing is left alone"
    );
    assert!(restarts_of(&host, "quick") <= 3);

    host.stop();
}

/// Test 5: a plugin that exceeds 1.5 times its budget is killed and marked
/// `OverBudget`.
#[test]
fn a_plugin_over_its_memory_budget_is_killed_and_marked_over_budget() {
    if fixture_mode().is_some() {
        return;
    }

    let dir = TempDir::new("memory");
    // The script takes 64 MB, and the budget is 4 MB, so the host kills it
    // at 6 MB.
    dir.plugin(
        "hog",
        &manifest("hog", "\"query:devices\"", 4),
        "#!/bin/sh\ndata=$(head -c 67108864 /dev/zero | tr '\\0' 'x')\nsleep 30 &\nwait\n",
    );

    let mut host = PluginHost::with_config(dir.path(), quiet_config());
    host.load().expect("the manifests are read");
    host.start().expect("the plugins are started");

    assert!(
        wait_for(
            || {
                host.check();
                state_of(&host, "hog") == Some(PluginState::OverBudget)
            },
            Duration::from_secs(30)
        ),
        "the plugin was killed: {:?}",
        host.statuses()
    );

    // It is not restarted: a plugin that wants more memory than it was
    // given will want it again.
    assert_eq!(restarts_of(&host, "hog"), 0);

    // And it stays stopped.
    for _ in 0..10 {
        host.check();
        std::thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(state_of(&host, "hog"), Some(PluginState::OverBudget));

    host.stop();
}

/// Test 6: a plugin's token is its own: it cannot read a query method its
/// manifest did not ask for.
#[test]
fn a_plugins_token_is_its_own_and_scoped_to_its_manifest() {
    if fixture_mode().is_some() {
        return;
    }

    let dir = TempDir::new("token");
    dir.plugin(
        "first",
        &manifest(
            "first",
            "\"query:devices\", \"events:ap.*\", \"fs:write:/tmp/od3sa-first\"",
            8,
        ),
        &marker_script(),
    );
    dir.plugin(
        "second",
        &manifest("second", "\"query:sightings\", \"events:ble.seen\"", 8),
        &marker_script(),
    );

    let mut host = PluginHost::with_config(dir.path(), config());
    host.load().expect("the manifests are read");

    let first = host
        .token_for("first")
        .expect("the first plugin has a token");
    let second = host
        .token_for("second")
        .expect("the second plugin has a token");

    // The query methods are the ones the manifest asked for, and no
    // others.
    assert!(first.allows_method("devices"));
    assert!(!first.allows_method("sightings"));
    assert!(second.allows_method("sightings"));
    assert!(!second.allows_method("devices"));

    // The same for the event topics.
    assert!(first.allows_topic("ap.new"));
    assert!(!first.allows_topic("ble.seen"));
    assert!(second.allows_topic("ble.seen"));
    assert!(!second.allows_topic("ap.new"));

    // And for the write path.
    assert!(first.allows_write(Path::new("/tmp/od3sa-first/out.json")));
    assert!(!first.allows_write(Path::new("/tmp/od3sa-other/out.json")));
    assert!(!second.allows_write(Path::new("/tmp/od3sa-first/out.json")));

    // The network is off, because the manifest did not ask for it.
    assert!(!first.allows_network());
    assert!(!second.allows_network());

    // The secrets are not the same, and the host knows whose is whose.
    assert_ne!(first.secret(), second.secret());
    assert_eq!(
        host.authenticate(first.secret())
            .map(|token| token.plugin()),
        Some("first")
    );
    assert_eq!(
        host.authenticate(second.secret())
            .map(|token| token.plugin()),
        Some("second")
    );
    assert!(host.authenticate("not-a-token").is_none());

    host.stop();
}

/// Test 7: a plugin that does not answer the ping is restarted.
#[test]
fn a_plugin_that_does_not_answer_the_ping_is_restarted() {
    if fixture_mode().is_some() {
        return;
    }

    let dir = TempDir::new("ping");
    // The plugin sleeps and never answers.
    dir.plugin(
        "quiet",
        &manifest("quiet", "\"query:devices\"", 8),
        "#!/bin/sh\nexec sleep 30\n",
    );

    let mut host = PluginHost::with_config(dir.path(), config());
    host.load().expect("the manifests are read");
    host.start().expect("the plugins are started");

    assert!(
        wait_for(
            || {
                host.check();
                restarts_of(&host, "quiet") >= 1
            },
            Duration::from_secs(20)
        ),
        "the plugin that did not answer was restarted: {:?}",
        host.statuses()
    );

    host.stop();
}

/// Test 8: the plugin's environment carries the two socket paths and its
/// token.
#[test]
fn the_plugins_environment_carries_the_sockets_and_its_token() {
    if fixture_mode().is_some() {
        return;
    }

    let dir = TempDir::new("environment");
    let plugin_dir = dir.plugin(
        "envplug",
        &manifest("envplug", "\"query:devices\"", 8),
        "#!/bin/sh\nenv > environment.txt\nexec sleep 30\n",
    );

    let mut settings = config();
    settings.events_socket = PathBuf::from("/tmp/od3sa-recon/events.sock");
    settings.query_socket = PathBuf::from("/tmp/od3sa-recon/query.sock");

    let mut host = PluginHost::with_config(dir.path(), settings);
    host.load().expect("the manifests are read");
    host.start().expect("the plugins are started");

    let environment = plugin_dir.join("environment.txt");
    // The file is written while the plugin runs, so the test waits for
    // the whole of it and not only for the file to be there.
    assert!(
        wait_for(
            || {
                let text = fs::read_to_string(&environment).unwrap_or_default();
                text.ends_with('\n')
                    && text.contains(ENV_EVENTS)
                    && text.contains(ENV_QUERY)
                    && text.contains(ENV_TOKEN)
            },
            Duration::from_secs(20)
        ),
        "the plugin wrote its environment"
    );

    let text = fs::read_to_string(&environment).expect("the environment is read");
    let mut variables = std::collections::HashMap::new();
    for line in text.lines() {
        if let Some((name, value)) = line.split_once('=') {
            variables.insert(name.to_string(), value.to_string());
        }
    }

    assert_eq!(
        variables.get(ENV_EVENTS).map(String::as_str),
        Some("/tmp/od3sa-recon/events.sock")
    );
    assert_eq!(
        variables.get(ENV_QUERY).map(String::as_str),
        Some("/tmp/od3sa-recon/query.sock")
    );

    let token = host
        .token_for("envplug")
        .expect("the plugin has a token")
        .secret()
        .to_string();
    assert_eq!(
        variables.get(ENV_TOKEN).map(String::as_str),
        Some(token.as_str())
    );

    host.stop();
}

/// Test 9: a manifest that cannot be parsed does not stop the other
/// plugins.
#[test]
fn a_manifest_that_cannot_be_parsed_does_not_stop_the_other_plugins() {
    if fixture_mode().is_some() {
        return;
    }

    let dir = TempDir::new("broken");
    dir.plugin("broken", "this is not a manifest [[[", &marker_script());
    let good = dir.plugin(
        "good",
        &manifest("good", "\"query:devices\"", 8),
        &marker_script(),
    );

    let mut host = PluginHost::with_config(dir.path(), config());
    let loaded = host.load().expect("the manifests are read");

    assert_eq!(loaded.len(), 1);
    assert_eq!(loaded[0].manifest.name, "good");
    assert_eq!(host.failures().len(), 1);

    host.start().expect("the plugins are started");
    assert!(
        wait_for(|| ran(&good), Duration::from_secs(20)),
        "the plugin with the good manifest ran"
    );

    host.stop();
}

/// The host pings the plugin on the socket the plugin serves.
#[test]
fn the_host_pings_the_plugin_on_the_socket_it_serves() {
    if fixture_mode().is_some() {
        return;
    }

    let dir = TempDir::new("socket");
    let binary = std::env::current_exe().expect("the test binary is found");
    let script = format!(
        "#!/bin/sh\nexport {FIXTURE_ENV}=health\nexec \"{}\"\n",
        binary.display()
    );
    let plugin_dir = dir.plugin("sock", &manifest("sock", "", 8), &script);

    let mut host = PluginHost::with_config(dir.path(), config());
    host.load().expect("the manifests are read");
    host.start().expect("the plugins are started");

    let socket = plugin_dir.join(PLUGIN_QUERY_SOCKET);
    assert!(
        wait_for(|| socket.exists(), Duration::from_secs(20)),
        "the plugin served its socket"
    );

    // The plugin answers the ping on its own socket, so it is left alone.
    for _ in 0..10 {
        host.check();
        std::thread::sleep(Duration::from_millis(50));
    }

    assert_eq!(state_of(&host, "sock"), Some(PluginState::Running));
    assert_eq!(restarts_of(&host, "sock"), 0);

    host.stop();
}

/// The plugin part of the test binary: it serves a socket and answers the
/// ping on it.
///
/// It only does anything when the binary was started as a plugin.
#[test]
fn plugin_fixture() {
    let Some(mode) = fixture_mode() else {
        return;
    };
    if mode != "health" {
        return;
    }

    let Ok(directory) = std::env::current_dir() else {
        return;
    };
    let path = directory.join(PLUGIN_QUERY_SOCKET);
    let Ok(listener) = UnixListener::bind(&path) else {
        return;
    };

    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        let Ok(write_half) = stream.try_clone() else {
            continue;
        };
        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        if reader.read_line(&mut line).unwrap_or(0) == 0 {
            continue;
        }
        if line.trim() == PING {
            let mut write_half = write_half;
            let _ = write_half.write_all(b"pong\n");
            let _ = write_half.flush();
        }
    }
}

/// Every manifest that ships in the package is valid TOML and parses with
/// the host's own parser.
///
/// The plugin tests read their manifests as text and look for substrings,
/// which cannot tell that a manifest is *valid*. A manifest that does not
/// parse is refused by the host with a log line and the plugin never
/// starts, so the failure is silent from the outside: the package ships,
/// the daemon starts, and four of the five plugins do nothing.
///
/// This test parses each one for real, so a manifest that stops being
/// valid fails the build instead.
#[test]
fn every_shipped_manifest_parses() {
    if fixture_mode().is_some() {
        return;
    }

    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../plugins");
    let mut checked = 0;

    for entry in fs::read_dir(&root).expect("the plugins directory should be read") {
        let Ok(entry) = entry else { continue };
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let manifest_path = path.join(MANIFEST_NAME);
        if !manifest_path.is_file() {
            continue;
        }

        let text = fs::read_to_string(&manifest_path)
            .unwrap_or_else(|error| panic!("{}: {error}", manifest_path.display()));

        let parsed = Manifest::parse(&text).unwrap_or_else(|error| {
            panic!(
                "{} is not a valid manifest: {error}",
                manifest_path.display()
            )
        });

        // The name in the manifest has to be the name of the directory it
        // is in, because that is how the host finds it.
        assert_eq!(
            parsed.name,
            path.file_name()
                .and_then(|name| name.to_str())
                .unwrap_or_default(),
            "{}: the manifest's name must match its directory",
            manifest_path.display()
        );

        // And every capability has to be one the host knows, or the host
        // refuses the plugin.
        for capability in &parsed.capabilities {
            assert!(
                Capability::parse(capability).is_ok(),
                "{}: '{capability}' is not a capability the host knows",
                manifest_path.display()
            );
        }

        checked += 1;
    }

    assert!(
        checked >= 5,
        "the five shipped plugins' manifests should have been parsed, not {checked}"
    );
}
