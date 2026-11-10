//! `od3sa-recond`: the passive, listen-only recon collector for the WiFi
//! Pineapple Pager.
//!
//! The daemon reads monitor interfaces that `pineapd` already owns. It never
//! changes a channel, a mode, or the up/down state of an interface, it never
//! transmits a frame, and it never touches `pineapd` or `blue5`.
//!
//! # The `--dry-run` mode
//!
//! `--dry-run` opens an interface for reading, counts the frames it sees
//! and prints statistics: a one-line summary every second and a final
//! summary at the end. It stores nothing: the counters keep counts,
//! channel numbers and signal levels, and nothing else.
//!
//! ```text
//! od3sa-recond --dry-run --interface wlan1mon [--seconds N] [--snaplen N]
//!              [--promisc true|false] [--timeout-ms N] [--no-immediate]
//! ```
//!
//! The counting logic lives in [`counters`], and it depends on `od3sa-parse`
//! only: it takes the bytes of a frame and updates the counts, so it can be
//! tested on the build machine without a capture handle.
//!
//! # Capture, storage and plugins
//!
//! The capture path is OR-201 (`--dry-run`); the read-only query socket is
//! OR-302 (`--query-socket`); the plugin host comes later.
//!
//! # The `--query-socket` mode
//!
//! `--query-socket <path>` serves the read-only JSON-RPC 2.0 socket of
//! `docs/QUERY-API.md`: one request per line, one response per line. The
//! socket reads the database and nothing else: it cannot change the
//! database, a channel, an interface mode or a service.

#![deny(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used)]

mod args;
mod counters;
mod query;
mod signals;

use std::process::ExitCode;
use std::thread;
use std::time::{Duration, Instant};

use od3sa_capture::{Capture, CaptureError, CaptureOptions, DataLink};
use od3sa_collector::{Collector, CollectorConfig};
use od3sa_events::{EventBus, TopicPattern};
use od3sa_gps::GpsdClient;
use od3sa_plugin::{HostConfig, PluginHost};
use od3sa_store::Store;

use crate::args::{CollectOptions, Command, DryRunOptions, QueryOptions};
use crate::counters::{Counters, LinkLayer};

/// The daemon version, taken from the crate metadata.
const VERSION: &str = env!("CARGO_PKG_VERSION");

/// One-line statement of the design invariant, shown by `--help`.
const PASIVE_NOTICE: &str = "Passive and listen-only: no transmission, no radio configuration, \
                              no changes to pineapd or blue5.";

/// How often the running summary is printed.
const SUMMARY_INTERVAL: Duration = Duration::from_secs(1);

/// How many channels the running summary names.
const SUMMARY_TOP_CHANNELS: usize = 3;

fn main() -> ExitCode {
    let arguments: Vec<String> = std::env::args().skip(1).collect();

    match args::parse(arguments) {
        Ok(Command::Help) => {
            print_help();
            ExitCode::SUCCESS
        }
        Ok(Command::Version) => {
            println!("od3sa-recond {VERSION}");
            ExitCode::SUCCESS
        }
        Ok(Command::DryRun(options)) => run_dry_run(&options),
        Ok(Command::Query(options)) => run_query(&options),
        Ok(Command::Collect(options)) => run_collect(&options),
        Err(error) => {
            eprintln!("od3sa-recond: {error}");
            print_help();
            ExitCode::FAILURE
        }
    }
}

/// Open an interface for reading, count the frames and print the statistics.
///
/// The capture is opened for reading only. The daemon never changes a
/// channel, a mode or the up/down state of the interface, and it never
/// transmits anything.
fn run_dry_run(options: &DryRunOptions) -> ExitCode {
    // Install the interruption handler before anything else, so that a
    // Ctrl-C during the capture setup is noticed too.
    signals::install();

    println!("od3sa-recond {VERSION}");
    println!("{PASIVE_NOTICE}");

    // A read timeout of zero would make the capture return immediately on
    // every call, and the daemon would spin. One millisecond is the
    // smallest value that does not.
    let timeout_ms = options.timeout_ms.max(1);
    if timeout_ms != options.timeout_ms {
        eprintln!(
            "od3sa-recond: a read timeout of {}ms would spin the CPU: using {timeout_ms}ms",
            options.timeout_ms
        );
    }

    println!(
        "dry-run: interface={} snaplen={} promisc={} timeout_ms={} immediate={} seconds={}",
        options.interface,
        options.snaplen,
        options.promiscuous,
        timeout_ms,
        options.immediate,
        options.seconds
    );

    let capture_options = CaptureOptions {
        snaplen: options.snaplen,
        promiscuous: options.promiscuous,
        timeout_ms,
        immediate: options.immediate,
    };

    let mut capture = match Capture::open(&options.interface, &capture_options) {
        Ok(capture) => capture,
        Err(error) => {
            report_capture_error(&options.interface, &error);
            return ExitCode::FAILURE;
        }
    };

    // A monitor interface delivers 802.11 frames. Anything else is an
    // error, not a warning: the daemon would count frames it cannot
    // describe.
    let link_layer = match capture.datalink() {
        DataLink::Ieee80211RadioTap => LinkLayer::Radiotap,
        DataLink::Ieee80211 => LinkLayer::Ieee80211,
        other => {
            report_capture_error(&options.interface, &CaptureError::NotMonitor(other));
            return ExitCode::FAILURE;
        }
    };

    let started = Instant::now();
    let mut counters = Counters::with_link_layer(link_layer);
    let mut next_report = SUMMARY_INTERVAL;
    let mut failed = false;

    loop {
        match capture.next_packet() {
            Ok(Some(packet)) => counters.add(packet.data),
            // A read that timed out with nothing to read is not an error.
            Ok(None) => {}
            Err(error) => {
                // A read that was cut short by a signal is not a failure:
                // the operator asked for it.
                if signals::interrupted() {
                    break;
                }
                eprintln!(
                    "od3sa-recond: capture failed: {}",
                    capture_error_message(&error)
                );
                failed = true;
                break;
            }
        }

        // Ctrl-C: stop cleanly and print the final summary.
        if signals::interrupted() {
            break;
        }

        let elapsed = started.elapsed();
        if elapsed >= next_report {
            print_running_summary(&counters, elapsed);
            next_report = Duration::from_secs(elapsed.as_secs() + 1);
        }

        if options.seconds > 0 && elapsed.as_secs() >= options.seconds {
            break;
        }
    }

    print_final_summary(&counters, started.elapsed());

    if failed {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

/// Serve the read-only query socket.
///
/// The socket only reads: it cannot change the database, a channel, an
/// interface mode or a service. The token is generated here and written to
/// the log once; it is never stored in the database and never written to a
/// file that persists.
///
/// When a dry run was asked for as well, it runs in this thread while the
/// socket is served in another.
/// Serve the read-only query socket, with the daemon's token and the
/// plugins' own.
fn serve_query(
    path: &std::path::Path,
    database: &std::path::Path,
    tokens: &[od3sa_plugin::Token],
) -> Result<query::QueryServer, String> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        let _ = std::fs::create_dir_all(parent);
    }

    let store = Store::open(database).map_err(|error| error.to_string())?;
    let token = query::generate_token().map_err(|error| error.to_string())?;
    let server =
        query::QueryServer::bind(path, store, token.clone()).map_err(|error| error.to_string())?;

    for plugin in tokens {
        server.add_token(plugin.secret(), plugin.scopes().query.clone());
    }

    println!("query socket: {}", path.display());
    println!("query token: {token}");
    Ok(server)
}

/// Start the plugin host, and hand back the tokens the plugins get.
///
/// The host reads the manifests in the plugin directory and starts the
/// plugins that say they are daemons. Each plugin gets a token of its own,
/// scoped to what its manifest asked for; the caller registers those tokens
/// with the event bus and the query socket, which are the two places that
/// enforce them.
fn start_plugins(
    directory: Option<&std::path::Path>,
    config: &CollectorConfig,
) -> (Option<PluginHost>, Vec<od3sa_plugin::Token>) {
    let Some(directory) = directory else {
        return (None, Vec::new());
    };
    if !directory.is_dir() {
        println!("no plugins: '{}' does not exist", directory.display());
        return (None, Vec::new());
    }

    let host_config = HostConfig {
        events_socket: config
            .events_socket
            .clone()
            .unwrap_or_else(|| config.query_socket.clone().unwrap_or_default()),
        query_socket: config.query_socket.clone().unwrap_or_default(),
        ..HostConfig::default()
    };

    let mut host = PluginHost::with_config(directory, host_config);
    if let Err(error) = host.load() {
        eprintln!("od3sa-recond: cannot read the plugins: {error}");
    }
    for failure in host.failures() {
        eprintln!("od3sa-recond: a plugin was refused: {failure}");
    }

    let tokens: Vec<od3sa_plugin::Token> = host
        .statuses()
        .iter()
        .filter_map(|status| host.token_for(&status.name).cloned())
        .collect();

    if let Err(error) = host.start() {
        eprintln!("od3sa-recond: cannot start the plugins: {error}");
    } else {
        for status in host.statuses() {
            println!("plugin: {} ({:?})", status.name, status.state);
        }
    }

    // The tokens, printed once.
    //
    // A plugin the host starts gets its token in its environment. A
    // plugin that runs itself — `run = "external"` — has no other way to
    // learn it, so the daemon writes it here. The token is in the log
    // after this, so the log is sensitive: it is a credential that reaches
    // what the plugin's manifest asked for, and nothing more.
    for token in &tokens {
        println!("plugin token: {}: {}", token.plugin(), token.secret());
    }

    (Some(host), tokens)
}

/// Collect: capture, aggregate, write and publish.
fn run_collect(options: &CollectOptions) -> ExitCode {
    signals::install();

    // The configuration file, when one was given. The options on the command
    // line override it.
    let mut config = match options.config.as_ref() {
        Some(path) => match std::fs::read_to_string(path) {
            Ok(text) => match CollectorConfig::from_toml(&text) {
                Ok(config) => config,
                Err(error) => {
                    eprintln!("od3sa-recond: cannot read '{}': {error}", path.display());
                    return ExitCode::FAILURE;
                }
            },
            Err(error) => {
                eprintln!("od3sa-recond: cannot read '{}': {error}", path.display());
                return ExitCode::FAILURE;
            }
        },
        None => CollectorConfig::default(),
    };

    if !options.interface.is_empty() {
        config.interface = options.interface.clone();
    }
    config.database = options.database.clone();
    config.events_socket = options.events_socket.clone();
    config.query_socket = options.query_socket.clone();
    config.gpsd_address = options.gpsd.clone();
    config.seconds = options.seconds;

    println!("od3sa-recond {VERSION}");
    println!("{PASIVE_NOTICE}");
    println!(
        "collecting: interface={} database={}",
        config.interface,
        config.database.display()
    );

    // The plugin host, and the tokens the plugins get.
    // The host is kept for the life of the daemon: it supervises the
    // plugins, and it is stopped explicitly at the end.
    let (host, tokens) = start_plugins(options.plugins.as_deref(), &config);

    // The event bus, if the events are to be published.
    let bus = match config.events_socket.as_ref() {
        Some(path) => {
            if let Some(parent) = path.parent()
                && !parent.as_os_str().is_empty()
            {
                let _ = std::fs::create_dir_all(parent);
            }
            match EventBus::bind(path) {
                Ok(bus) => {
                    println!("event bus: {}", path.display());
                    for token in &tokens {
                        let topics: Vec<TopicPattern> = token
                            .scopes()
                            .events
                            .iter()
                            .filter_map(|pattern| TopicPattern::parse(pattern).ok())
                            .collect();
                        bus.add_token(token.secret(), topics);
                    }
                    Some(bus)
                }
                Err(error) => {
                    eprintln!("od3sa-recond: cannot serve '{}': {error}", path.display());
                    return ExitCode::FAILURE;
                }
            }
        }
        None => None,
    };

    // gpsd, if a position is wanted. A gpsd that is not there is not an
    // error: the Pager may have no GPS at all.
    let gps = config.gpsd_address.as_ref().map(|address| {
        let mut client = GpsdClient::with_address(address);
        if let Err(error) = client.connect() {
            eprintln!("od3sa-recond: no position from gpsd: {error}");
        }
        client
    });

    // The query socket, if one is to be served. The plugins read from it,
    // so it belongs with the collector rather than with the socket alone.
    let query_server = match config.query_socket.as_ref() {
        Some(path) => match serve_query(path, &config.database, &tokens) {
            Ok(server) => Some(server),
            Err(error) => {
                eprintln!("od3sa-recond: cannot serve '{path:?}': {error}");
                return ExitCode::FAILURE;
            }
        },
        None => None,
    };

    let mut collector = Collector::new(config.clone());
    if let Some(bus) = bus {
        collector = collector.with_bus(bus);
    }
    if let Some(gps) = gps {
        collector = collector.with_gpsd(gps);
    }

    let outcome = collector.run();

    if let Some(server) = query_server {
        server.stop();
    }
    if let Some(mut host) = host {
        // The host does not stop the plugins when it is dropped, so it is
        // stopped here: a plugin must not outlive the daemon.
        host.stop();
    }

    match outcome {
        Ok(()) => {
            let stats = collector.stats();
            println!("=== final ===");
            println!(
                "frames: {} (unparsed {}), observations: {}, alerts: {}, events: {}",
                stats.frames, stats.unparsed, stats.observations, stats.alerts, stats.events
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("od3sa-recond: the collector stopped: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run_query(options: &QueryOptions) -> ExitCode {
    signals::install();

    // The directory the socket and the database live in.
    if let Some(parent) = options.socket.parent()
        && !parent.as_os_str().is_empty()
        && let Err(error) = std::fs::create_dir_all(parent)
    {
        eprintln!(
            "od3sa-recond: cannot create '{}': {error}",
            parent.display()
        );
        return ExitCode::FAILURE;
    }

    let store = match Store::open(&options.database) {
        Ok(store) => store,
        Err(error) => {
            eprintln!(
                "od3sa-recond: cannot open '{}': {error}",
                options.database.display()
            );
            return ExitCode::FAILURE;
        }
    };

    let token = match query::generate_token() {
        Ok(token) => token,
        Err(error) => {
            eprintln!("od3sa-recond: cannot generate a token: {error}");
            return ExitCode::FAILURE;
        }
    };

    let server = match query::QueryServer::bind(&options.socket, store, token.clone()) {
        Ok(server) => server,
        Err(error) => {
            eprintln!(
                "od3sa-recond: cannot serve '{}': {error}",
                options.socket.display()
            );
            return ExitCode::FAILURE;
        }
    };

    if options.dry_run.is_none() {
        println!("od3sa-recond {VERSION}");
        println!("{PASIVE_NOTICE}");
    }
    println!("query socket: {}", options.socket.display());
    println!("query token: {token}");

    let worker = server.clone();
    let handle = thread::spawn(move || {
        if let Err(error) = worker.serve() {
            eprintln!("od3sa-recond: the query socket stopped: {error}");
        }
    });

    let exit = match &options.dry_run {
        Some(dry_run) => run_dry_run(dry_run),
        None => {
            // Only the socket: run until the operator stops the daemon.
            while !signals::interrupted() {
                thread::sleep(Duration::from_millis(100));
            }
            ExitCode::SUCCESS
        }
    };

    server.stop();
    let _ = handle.join();
    let _ = std::fs::remove_file(server.socket_path());

    exit
}

/// Report why an interface could not be opened.
///
/// The capture crate's error type is matched on its documented variants.
/// The catch-all arm keeps the daemon compiling if the crate grows one.
fn report_capture_error(interface: &str, error: &CaptureError) {
    match error {
        CaptureError::NotMonitor(link_type) => eprintln!(
            "od3sa-recond: '{interface}' is not a monitor interface (link type {link_type:?})"
        ),
        other => eprintln!(
            "od3sa-recond: cannot open '{interface}': {}",
            capture_error_message(other)
        ),
    }
}

/// The message of a capture error, without the `Debug` noise of the enum.
///
/// The capture crate's error type carries the message the C library left
/// behind, which is more useful to the operator than the enum's shape.
fn capture_error_message(error: &CaptureError) -> String {
    match error {
        CaptureError::Open(message) | CaptureError::Read(message) => message.clone(),
        CaptureError::NotMonitor(link_type) => {
            format!("not a monitor interface (link type {link_type:?})")
        }
    }
}

/// Print the one-line summary of the run so far.
///
/// The line holds the elapsed time, the total number of frames, the number
/// of frames per class and the busiest channels.
fn print_running_summary(counters: &Counters, elapsed: Duration) {
    let top = counters.top_channels(SUMMARY_TOP_CHANNELS);
    let channels = if top.is_empty() {
        "-".to_string()
    } else {
        top.iter()
            .map(|(number, stats)| format!("{number}={}", stats.frames))
            .collect::<Vec<_>>()
            .join(" ")
    };

    println!(
        "[{:>5}s] frames={} mgmt={} ctrl={} data={} other={} eapol={} bytes={} mean={:.1}B top: {channels}",
        elapsed.as_secs(),
        counters.total_frames(),
        counters.management_frames(),
        counters.control_frames(),
        counters.data_frames(),
        counters.other_frames(),
        counters.eapol_frames(),
        counters.total_bytes(),
        counters.mean_frame_size(),
    );
}

/// Print the totals of the run.
///
/// The summary holds the same numbers as the running summary, plus the
/// management subtypes and what was seen on each channel.
fn print_final_summary(counters: &Counters, elapsed: Duration) {
    let management = counters.management_counts();

    println!();
    println!("=== final summary ===");
    println!("elapsed:              {}s", elapsed.as_secs());
    println!(
        "frames:               {} (management {}, control {}, data {}, other {})",
        counters.total_frames(),
        counters.management_frames(),
        counters.control_frames(),
        counters.data_frames(),
        counters.other_frames()
    );
    println!(
        "management subtypes:  beacon {}, probe request {}, probe response {}, association {}, \
authentication {}, deauthentication {}, disassociation {}, other {} (total {})",
        management.beacon,
        management.probe_request,
        management.probe_response,
        management.association,
        management.authentication,
        management.deauthentication,
        management.disassociation,
        management.other,
        management.total()
    );
    println!(
        "eapol frames:         {} (counted only, never stored)",
        counters.eapol_frames()
    );
    println!(
        "bytes:                {} (mean {:.1} bytes per frame)",
        counters.total_bytes(),
        counters.mean_frame_size()
    );

    let mut channels: Vec<u16> = counters.channels().map(|(number, _)| number).collect();
    channels.sort_unstable();

    if channels.is_empty() {
        println!("channels:             none");
    } else {
        println!("channels:");
        for number in channels {
            let signal = match counters.strongest_signal(number) {
                Some(dbm) => format!("{dbm} dBm"),
                None => "unknown".to_string(),
            };
            println!(
                "  ch {number:<4} {:>10} frames, strongest {signal}",
                counters.channel_frames(number)
            );
        }
    }

    if counters.frames_without_channel() > 0 {
        println!(
            "frames with no channel: {}",
            counters.frames_without_channel()
        );
    }
}

/// Print the usage text.
fn print_help() {
    println!(
        "od3sa-recond {VERSION}\n\
         \n\
         {PASIVE_NOTICE}\n\
         \n\
         Usage: od3sa-recond [OPTIONS]\n\
         \n\
         Options:\n  \
             -h, --help       Print this help and exit\n  \
             -V, --version    Print the version and exit\n  \
             --dry-run        Count the frames on an interface and print statistics\n  \
             --interface <name>  The interface to read (required with --dry-run)\n  \
             --seconds <n>    Stop after n seconds (0: run until interrupted)\n  \
             --snaplen <n>    Keep n bytes of each frame (default 256)\n  \
             --promisc <bool> See frames not addressed to this host (default true)\n  \
             --timeout-ms <n> How long a read may block, in milliseconds (default 100)\n  \
             --no-immediate   Deliver packets in batches instead of one by one\n  \
             --query-socket <path>  Serve the read-only JSON-RPC query socket at path\n  \
             --db <path>      The database the query socket reads\n  \
             --collect        Capture, aggregate, write and publish\n  \
             --config <path>  Read the collector's settings from a TOML file\n  \
             --events-socket <path>  Publish the events here\n  \
             --gpsd <address> Take the position from gpsd (default 127.0.0.1:2947)\n  \
             --flush-interval-ms <n>  Write the batch every n ms (default 5000)\n  \
             --batch-size <n> Write the batch after n observations (default 64)\n  \
             --device-capacity <n>  How many devices to remember (default 1024)\n  \
             --plugins <path>  Load the plugins from this directory\n\
         \n\
         The query socket only reads: it cannot change the database, a channel,\n\
         an interface mode or a service."
    );
    println!("query methods: {}", query::METHODS.join(", "));
}
