//! Command-line parsing for `od3sa-recond`.
//!
//! The daemon has two modes: `--dry-run`, which opens a monitor interface
//! for reading, counts the frames it sees and prints statistics, and
//! `--query-socket`, which serves the read-only JSON-RPC query socket.
//!
//! ```text
//! od3sa-recond --dry-run --interface wlan1mon [--seconds N] [--snaplen N]
//!              [--promisc true|false] [--timeout-ms N] [--no-immediate]
//! od3sa-recond --query-socket <path> [--db <path>] [--dry-run --interface <name>]
//! ```
//!
//! The parser is deliberately hand-written: the daemon has no dependency
//! beyond `od3sa-parse`, `od3sa-capture` and `od3sa-store`, and an argument
//! parser for a handful of options does not justify one.
//!
//! # Options
//!
//! | Option | Default | Meaning |
//! |---|---|---|
//! | `--dry-run` | — | count frames and print statistics |
//! | `--interface <name>` | — | the interface to read; required with `--dry-run` |
//! | `--seconds <n>` | `0` | stop after `n` seconds; `0` means run until interrupted |
//! | `--snaplen <n>` | `256` | how many bytes of each frame to keep |
//! | `--promisc <bool>` | `true` | whether to see frames not addressed to this host |
//! | `--timeout-ms <n>` | `100` | how long a read may block, in milliseconds |
//! | `--no-immediate` | off | deliver packets in batches instead of one by one |
//! | `--query-socket <path>` | — | serve the read-only query socket at `path` |
//! | `--db <path>` | `/tmp/od3sa-recon/recon.sqlite` | the database to read |
//!
//! # Safety
//!
//! Parsing arguments never touches a radio. An interface name is only ever
//! handed to the capture crate, which opens it for reading. The query socket
//! reads the database and nothing else.

use std::fmt;
use std::path::PathBuf;

use crate::query::DEFAULT_SOCKET_PATH;

/// The default number of bytes of each frame that is kept.
///
/// Headers only: the daemon reads metadata, never payloads.
pub const DEFAULT_SNAPLEN: u32 = 256;

/// The default read timeout, in milliseconds.
pub const DEFAULT_TIMEOUT_MS: i32 = 100;

/// The default path of the database.
pub const DEFAULT_DATABASE_PATH: &str = "/tmp/od3sa-recon/recon.sqlite";

/// What the daemon was asked to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    /// Print the help text and exit.
    Help,
    /// Print the version and exit.
    Version,
    /// Count frames on an interface and print statistics.
    DryRun(DryRunOptions),
    /// Serve the read-only query socket.
    ///
    /// The dry run may run alongside it, when it was asked for as well.
    Query(QueryOptions),
    /// Collect: capture, aggregate, write and publish.
    Collect(CollectOptions),
}

/// The options of the collector.
///
/// Every setting that the configuration file can also set is an `Option`
/// here, and `None` means "not given on the command line". The
/// configuration file is the one an owner edits on the device, so an
/// option that was not asked for must not overwrite what the file says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CollectOptions {
    /// The interface to read from. Empty means "not given".
    pub interface: String,
    /// The database to write to.
    pub database: Option<PathBuf>,
    /// The event bus socket, if the events are to be published.
    pub events_socket: Option<PathBuf>,
    /// The query socket, if one is to be served.
    pub query_socket: Option<PathBuf>,
    /// Where gpsd is, if a position is wanted.
    pub gpsd: Option<String>,
    /// How long to run, in seconds. `0` means run until interrupted.
    pub seconds: Option<u64>,
    /// How often the batch is written, in milliseconds.
    pub flush_interval_ms: Option<u64>,
    /// How many observations are written in one batch.
    pub batch_size: Option<usize>,
    /// How many devices the aggregator's table holds.
    pub device_capacity: Option<usize>,
    /// How long the collected data is kept, in days.
    pub retention_days: Option<i64>,
    /// How much disk the database may take, in megabytes.
    pub max_db_mb: Option<u64>,
    /// The configuration file to read the settings from.
    pub config: Option<PathBuf>,
    /// Where the plugins live.
    pub plugins: Option<PathBuf>,
}

/// The options of the query socket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryOptions {
    /// Where the socket is created.
    pub socket: PathBuf,
    /// The database the socket reads.
    pub database: PathBuf,
    /// The dry run to run alongside the socket, if one was asked for.
    pub dry_run: Option<DryRunOptions>,
}

/// The options of a `--dry-run`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DryRunOptions {
    /// The interface to read from.
    pub interface: String,
    /// How long to run, in seconds. `0` means run until interrupted.
    pub seconds: u64,
    /// How many bytes of each frame to keep.
    pub snaplen: u32,
    /// Whether to see frames that are not addressed to this host.
    pub promiscuous: bool,
    /// How long a read may block, in milliseconds.
    pub timeout_ms: i32,
    /// Whether packets are delivered as they arrive rather than in a batch.
    pub immediate: bool,
}

impl Default for DryRunOptions {
    fn default() -> Self {
        DryRunOptions {
            interface: String::new(),
            seconds: 0,
            snaplen: DEFAULT_SNAPLEN,
            promiscuous: true,
            timeout_ms: DEFAULT_TIMEOUT_MS,
            immediate: true,
        }
    }
}

/// A problem with the command line.
///
/// The message is written for the operator: it names the option and says
/// what was wrong with its value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArgError {
    /// What is wrong.
    pub message: String,
}

impl ArgError {
    /// Build an error with the given message.
    fn new(message: impl Into<String>) -> ArgError {
        ArgError {
            message: message.into(),
        }
    }
}

impl fmt::Display for ArgError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for ArgError {}

/// Parse the command line.
///
/// The arguments are the ones after the program name. `--help` and
/// `--version` win over everything else, so `--dry-run --help` prints the
/// help rather than opening an interface.
pub fn parse<I>(args: I) -> Result<Command, ArgError>
where
    I: IntoIterator<Item = String>,
{
    let mut options = DryRunOptions::default();
    let mut dry_run = false;
    // Whether an option that only makes sense with `--dry-run` was given.
    let mut capture_option = false;
    let mut any_argument = false;

    let mut query_options = QueryOptions {
        socket: PathBuf::from(DEFAULT_SOCKET_PATH),
        database: PathBuf::from(DEFAULT_DATABASE_PATH),
        dry_run: None,
    };
    let mut query = false;
    // Whether `--db` was given, which only makes sense with the socket.
    let mut database_option = false;

    let mut collect_options = CollectOptions {
        interface: String::new(),
        database: None,
        events_socket: None,
        query_socket: None,
        gpsd: None,
        seconds: None,
        flush_interval_ms: None,
        batch_size: None,
        device_capacity: None,
        retention_days: None,
        max_db_mb: None,
        config: None,
        plugins: Some(PathBuf::from("/mmc/od3sa-recon/plugins")),
    };
    let mut collect = false;
    // Whether an option that only makes sense with the collector was given.
    let mut collect_option = false;

    let mut args = args.into_iter().peekable();
    while let Some(argument) = args.next() {
        any_argument = true;

        // `--option=value` is the same as `--option value`.
        let (name, inline) = match argument.split_once('=') {
            Some((name, value)) if name.starts_with("--") => {
                (name.to_string(), Some(value.to_string()))
            }
            _ => (argument.clone(), None),
        };

        match name.as_str() {
            "-h" | "--help" => return Ok(Command::Help),
            "-V" | "--version" => return Ok(Command::Version),
            "--dry-run" => dry_run = true,
            "--no-immediate" => {
                options.immediate = false;
                capture_option = true;
            }
            "--interface" => {
                options.interface = value(&name, inline, &mut args)?;
                capture_option = true;
            }
            "--seconds" => {
                let raw = value(&name, inline, &mut args)?;
                options.seconds = number(&name, &raw)?;
                capture_option = true;
            }
            "--snaplen" => {
                let raw = value(&name, inline, &mut args)?;
                options.snaplen = number(&name, &raw)?;
                capture_option = true;
            }
            "--promisc" => {
                let raw = value(&name, inline, &mut args)?;
                options.promiscuous = boolean(&name, &raw)?;
                capture_option = true;
            }
            "--timeout-ms" => {
                let raw = value(&name, inline, &mut args)?;
                options.timeout_ms = number(&name, &raw)?;
                capture_option = true;
            }
            "--collect" => collect = true,
            "--plugins" => {
                collect_options.plugins = Some(PathBuf::from(value(&name, inline, &mut args)?));
                collect_option = true;
            }
            "--config" => {
                collect_options.config = Some(PathBuf::from(value(&name, inline, &mut args)?));
                collect_option = true;
            }
            "--events-socket" => {
                collect_options.events_socket =
                    Some(PathBuf::from(value(&name, inline, &mut args)?));
                collect_option = true;
            }
            "--gpsd" => {
                collect_options.gpsd = Some(value(&name, inline, &mut args)?);
                collect_option = true;
            }
            "--flush-interval-ms" => {
                let raw = value(&name, inline, &mut args)?;
                collect_options.flush_interval_ms = optional_number(&name, &raw)?;
                collect_option = true;
            }
            "--batch-size" => {
                let raw = value(&name, inline, &mut args)?;
                collect_options.batch_size = optional_number(&name, &raw)?;
                collect_option = true;
            }
            "--device-capacity" => {
                let raw = value(&name, inline, &mut args)?;
                collect_options.device_capacity = optional_number(&name, &raw)?;
                collect_option = true;
            }
            "--retention-days" => {
                let raw = value(&name, inline, &mut args)?;
                collect_options.retention_days = optional_number(&name, &raw)?;
                collect_option = true;
            }
            "--max-db-mb" => {
                let raw = value(&name, inline, &mut args)?;
                collect_options.max_db_mb = optional_number(&name, &raw)?;
                collect_option = true;
            }
            "--query-socket" => {
                query_options.socket = PathBuf::from(value(&name, inline, &mut args)?);
                query = true;
                collect_options.query_socket = Some(query_options.socket.clone());
            }
            "--db" => {
                query_options.database = PathBuf::from(value(&name, inline, &mut args)?);
                database_option = true;
            }
            other => {
                return Err(ArgError::new(format!("unknown argument '{other}'")));
            }
        }
    }

    if collect_option && !collect {
        return Err(ArgError::new("the collector options need '--collect'"));
    }

    if collect {
        if !options.interface.is_empty() {
            collect_options.interface = options.interface.clone();
        }
        if database_option {
            collect_options.database = Some(query_options.database.clone());
        }
        if !collect_options.interface.is_empty() {
            options.interface = collect_options.interface.clone();
        }
        return Ok(Command::Collect(collect_options));
    }

    if !dry_run && !query {
        if capture_option {
            return Err(ArgError::new(
                "the capture options need '--dry-run' or '--collect': the daemon has no other mode",
            ));
        }
        if database_option {
            return Err(ArgError::new("'--db' needs '--query-socket'"));
        }
        if any_argument {
            return Err(ArgError::new(
                "no mode given: use '--dry-run' or '--query-socket'",
            ));
        }
        // No arguments at all: print the help, as the daemon always has.
        return Ok(Command::Help);
    }

    if dry_run && options.interface.is_empty() {
        return Err(ArgError::new(
            "'--dry-run' needs an interface: '--interface <name>'",
        ));
    }

    if query {
        query_options.dry_run = if dry_run { Some(options) } else { None };
        return Ok(Command::Query(query_options));
    }

    Ok(Command::DryRun(options))
}

/// The value of an option: the one written after `=`, or the next argument.
fn value<I>(name: &str, inline: Option<String>, args: &mut I) -> Result<String, ArgError>
where
    I: Iterator<Item = String>,
{
    match inline {
        Some(value) => Ok(value),
        None => args
            .next()
            .ok_or_else(|| ArgError::new(format!("'{name}' needs a value"))),
    }
}

/// Parse a number, naming the option in the error.
fn number<T>(name: &str, raw: &str) -> Result<T, ArgError>
where
    T: std::str::FromStr,
{
    raw.parse::<T>()
        .map_err(|_| ArgError::new(format!("'{name}' needs a number, not '{raw}'")))
}

/// Parse a number into an `Option`, for an option that may be left out.
fn optional_number<T>(name: &str, raw: &str) -> Result<Option<T>, ArgError>
where
    T: std::str::FromStr,
{
    number(name, raw).map(Some)
}

/// Parse a boolean, naming the option in the error.
fn boolean(name: &str, raw: &str) -> Result<bool, ArgError> {
    match raw.to_ascii_lowercase().as_str() {
        "true" | "yes" | "1" => Ok(true),
        "false" | "no" | "0" => Ok(false),
        _ => Err(ArgError::new(format!(
            "'{name}' needs 'true' or 'false', not '{raw}'"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Parse a command line given as a list of strings.
    fn parse_args(args: &[&str]) -> Result<Command, ArgError> {
        parse(args.iter().map(|arg| (*arg).to_string()))
    }

    /// The options of a parsed `--dry-run`.
    fn dry_run(args: &[&str]) -> DryRunOptions {
        match parse_args(args) {
            Ok(Command::DryRun(options)) => options,
            Ok(other) => panic!("expected a dry run, got {other:?}"),
            Err(err) => panic!("expected a dry run, got the error {err}"),
        }
    }

    #[test]
    fn a_dry_run_with_an_interface_parses() {
        let options = dry_run(&["--dry-run", "--interface", "wlan1mon"]);

        assert_eq!(options.interface, "wlan1mon");
        assert_eq!(options.seconds, 0);
        assert_eq!(options.snaplen, DEFAULT_SNAPLEN);
        assert!(options.promiscuous);
        assert_eq!(options.timeout_ms, DEFAULT_TIMEOUT_MS);
        assert!(options.immediate);
    }

    #[test]
    fn an_unknown_argument_is_an_error() {
        let error = parse_args(&["--dry-run", "--interface", "wlan1mon", "--wat"]).unwrap_err();

        assert!(
            error.message.contains("unknown argument '--wat'"),
            "unexpected message: {}",
            error.message
        );
    }

    #[test]
    fn a_dry_run_without_an_interface_is_an_error() {
        let error = parse_args(&["--dry-run"]).unwrap_err();

        assert!(
            error.message.contains("--interface"),
            "unexpected message: {}",
            error.message
        );
    }

    #[test]
    fn promisc_false_parses() {
        let options = dry_run(&["--dry-run", "--interface", "wlan1mon", "--promisc", "false"]);

        assert!(!options.promiscuous);
    }

    #[test]
    fn promisc_true_parses() {
        let options = dry_run(&["--dry-run", "--interface", "wlan1mon", "--promisc", "true"]);

        assert!(options.promiscuous);
    }

    #[test]
    fn a_promisc_value_that_is_not_a_boolean_is_an_error() {
        let error = parse_args(&["--dry-run", "--interface", "wlan1mon", "--promisc", "maybe"])
            .unwrap_err();

        assert!(
            error.message.contains("--promisc"),
            "unexpected message: {}",
            error.message
        );
    }

    #[test]
    fn the_remaining_options_parse() {
        let options = dry_run(&[
            "--dry-run",
            "--interface",
            "wlan1mon",
            "--seconds",
            "600",
            "--snaplen",
            "128",
            "--timeout-ms",
            "250",
            "--no-immediate",
        ]);

        assert_eq!(options.seconds, 600);
        assert_eq!(options.snaplen, 128);
        assert_eq!(options.timeout_ms, 250);
        assert!(!options.immediate);
    }

    #[test]
    fn an_option_value_may_be_written_with_an_equal_sign() {
        let options = dry_run(&["--dry-run", "--interface=wlan1mon", "--seconds=42"]);

        assert_eq!(options.interface, "wlan1mon");
        assert_eq!(options.seconds, 42);
    }

    #[test]
    fn an_option_without_a_value_is_an_error() {
        let error = parse_args(&["--dry-run", "--interface"]).unwrap_err();

        assert!(
            error.message.contains("--interface"),
            "unexpected message: {}",
            error.message
        );
    }

    #[test]
    fn a_number_that_is_not_a_number_is_an_error() {
        let error =
            parse_args(&["--dry-run", "--interface", "wlan1mon", "--seconds", "ten"]).unwrap_err();

        assert!(
            error.message.contains("--seconds"),
            "unexpected message: {}",
            error.message
        );
    }

    #[test]
    fn help_and_version_win_over_everything_else() {
        assert_eq!(parse_args(&["--help"]).unwrap(), Command::Help);
        assert_eq!(parse_args(&["-h"]).unwrap(), Command::Help);
        assert_eq!(parse_args(&["--version"]).unwrap(), Command::Version);
        assert_eq!(parse_args(&["-V"]).unwrap(), Command::Version);
        assert_eq!(parse_args(&["--dry-run", "--help"]).unwrap(), Command::Help);
        assert_eq!(
            parse_args(&["--dry-run", "--version"]).unwrap(),
            Command::Version
        );
    }

    #[test]
    fn no_arguments_at_all_asks_for_the_help() {
        assert_eq!(parse_args(&[]).unwrap(), Command::Help);
    }

    #[test]
    fn a_capture_option_without_a_dry_run_is_an_error() {
        let error = parse_args(&["--interface", "wlan1mon"]).unwrap_err();

        assert!(
            error.message.contains("--dry-run"),
            "unexpected message: {}",
            error.message
        );
    }

    /// The options of a parsed `--query-socket`.
    fn query(args: &[&str]) -> QueryOptions {
        match parse_args(args) {
            Ok(Command::Query(options)) => options,
            Ok(other) => panic!("expected the query socket, got {other:?}"),
            Err(err) => panic!("expected the query socket, got the error {err}"),
        }
    }

    #[test]
    fn a_query_socket_parses() {
        let options = query(&["--query-socket", "/tmp/od3sa-recon/query.sock"]);

        assert_eq!(options.socket, PathBuf::from("/tmp/od3sa-recon/query.sock"));
        assert_eq!(options.database, PathBuf::from(DEFAULT_DATABASE_PATH));
        assert!(options.dry_run.is_none());
    }

    #[test]
    fn a_query_socket_with_a_dry_run_parses() {
        let options = query(&[
            "--query-socket",
            "/tmp/od3sa-recon/query.sock",
            "--db",
            "/tmp/od3sa-recon/other.sqlite",
            "--dry-run",
            "--interface",
            "wlan1mon",
        ]);

        assert_eq!(
            options.database,
            PathBuf::from("/tmp/od3sa-recon/other.sqlite")
        );
        let dry_run = options.dry_run.expect("the dry run should be there");
        assert_eq!(dry_run.interface, "wlan1mon");
    }

    #[test]
    fn a_database_without_a_query_socket_is_an_error() {
        let error = parse_args(&["--db", "/tmp/od3sa-recon/other.sqlite"]).unwrap_err();
        assert!(
            error.message.contains("--query-socket"),
            "unexpected message: {}",
            error.message
        );
    }

    #[test]
    fn a_query_socket_with_an_equal_sign_parses() {
        let options = query(&["--query-socket=/tmp/od3sa-recon/query.sock"]);
        assert_eq!(options.socket, PathBuf::from("/tmp/od3sa-recon/query.sock"));
    }

    /// The collector's options.
    fn collect(args: &[&str]) -> CollectOptions {
        match parse_args(args) {
            Ok(Command::Collect(options)) => options,
            Ok(other) => panic!("expected the collector, got {other:?}"),
            Err(err) => panic!("expected the collector, got the error {err}"),
        }
    }

    #[test]
    fn the_retention_options_parse() {
        let options = collect(&["--collect", "--retention-days", "7", "--max-db-mb", "64"]);

        assert_eq!(options.retention_days, Some(7));
        assert_eq!(options.max_db_mb, Some(64));
    }

    #[test]
    fn an_option_that_was_not_given_is_none() {
        let options = collect(&["--collect"]);

        // The configuration file is the one an owner edits on the device,
        // so an option that was not given must not overwrite it.
        assert_eq!(options.retention_days, None);
        assert_eq!(options.max_db_mb, None);
        assert_eq!(options.database, None);
        assert_eq!(options.batch_size, None);
        assert_eq!(options.device_capacity, None);
        assert_eq!(options.flush_interval_ms, None);
        assert_eq!(options.seconds, None);
        assert_eq!(options.gpsd, None);
        assert_eq!(options.events_socket, None);
    }

    #[test]
    fn a_retention_option_that_is_not_a_number_is_an_error() {
        let error = parse_args(&["--collect", "--max-db-mb", "lots"]).unwrap_err();

        assert!(
            error.message.contains("--max-db-mb"),
            "unexpected message: {}",
            error.message
        );
    }
}
