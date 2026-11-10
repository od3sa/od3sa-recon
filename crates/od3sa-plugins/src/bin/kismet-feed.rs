//! The `kismet-feed` plugin: write the access points the daemon has seen
//! into a directory Kismet watches, as Kismet netspot files.
//!
//! The plugin is started by hand (`run = "external"`), so it takes the
//! directory to write into as its first argument:
//!
//! ```text
//! kismet-feed /tmp/od3sa-recon/netspot
//! ```
//!
//! It talks to the daemon through the read-only query socket, so it needs
//! the socket and the token the host would give it:
//!
//! ```text
//! OD3SA_QUERY=/tmp/od3sa-recon/query.sock OD3SA_TOKEN=... kismet-feed DIR
//! ```
//!
//! It writes **files**, not bytes over the network: nothing here opens a
//! socket to another machine, and nothing here touches a radio.

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

// The plugin's own module. It is included here rather than reached
// through the library so that this binary stands on its own; the module
// uses `crate::client`, which this import puts in reach.
use od3sa_plugins::client::QueryClient;
use od3sa_plugins::kismet;

/// The socket the daemon serves the query API on.
const DEFAULT_SOCKET: &str = "/tmp/od3sa-recon/query.sock";

/// How the plugin was asked to run.
#[derive(Debug)]
struct Options {
    /// The directory the netspot files are written into.
    directory: PathBuf,
    /// The socket to ask the daemon on.
    socket: PathBuf,
    /// The token to present.
    token: String,
    /// How often to write the files again, in seconds. Zero means once.
    interval: u64,
}

/// Parse the command line.
///
/// The arguments are read by hand: the plugin has one dependency
/// (`serde_json`) and a hand-written parser keeps it that way.
fn parse_arguments(arguments: &[String]) -> Result<Options, String> {
    let mut directory: Option<PathBuf> = None;
    let mut socket: Option<PathBuf> = None;
    let mut token: Option<String> = None;
    let mut interval: u64 = 0;

    let mut index = 0;
    while index < arguments.len() {
        let argument = arguments[index].as_str();
        match argument {
            "--socket" => {
                let value = arguments
                    .get(index + 1)
                    .ok_or_else(|| "--socket needs a path".to_string())?;
                socket = Some(PathBuf::from(value));
                index += 2;
            }
            "--token" => {
                let value = arguments
                    .get(index + 1)
                    .ok_or_else(|| "--token needs a token".to_string())?;
                token = Some(value.clone());
                index += 2;
            }
            "--interval" => {
                let value = arguments
                    .get(index + 1)
                    .ok_or_else(|| "--interval needs a number of seconds".to_string())?;
                interval = value
                    .parse::<u64>()
                    .map_err(|_| format!("--interval needs a number of seconds, not {value}"))?;
                index += 2;
            }
            _ => {
                if argument.starts_with('-') {
                    return Err(format!("unknown option {argument}\n{}", usage()));
                }
                if directory.is_some() {
                    return Err(format!(
                        "only one directory is wanted, and {argument} is a second one\n{}",
                        usage()
                    ));
                }
                directory = Some(PathBuf::from(argument));
                index += 1;
            }
        }
    }

    let directory = directory.ok_or_else(usage)?;
    let socket = socket
        .or_else(|| std::env::var("OD3SA_QUERY").ok().map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from(DEFAULT_SOCKET));
    let token = match token {
        Some(token) => token,
        None => std::env::var("OD3SA_TOKEN").map_err(|_| {
            "OD3SA_TOKEN is not set: give --token or set it in the environment".to_string()
        })?,
    };

    Ok(Options {
        directory,
        socket,
        token,
        interval,
    })
}

/// What the plugin says when it is asked for help.
fn usage() -> String {
    "usage: kismet-feed <directory> [--socket <path>] [--token <token>] [--interval <seconds>]"
        .to_string()
}

/// Write the files once, and say how many were written.
fn write_once(client: &QueryClient, directory: &Path) -> Result<usize, kismet::FeedError> {
    let written = kismet::feed(client, directory)?;
    Ok(written.len())
}

fn main() -> ExitCode {
    let arguments: Vec<String> = std::env::args().skip(1).collect();

    // Asking for help is not a failure.
    if arguments
        .iter()
        .any(|argument| argument == "--help" || argument == "-h")
    {
        println!("{}", usage());
        return ExitCode::SUCCESS;
    }

    let options = match parse_arguments(&arguments) {
        Ok(options) => options,
        Err(message) => {
            eprintln!("kismet-feed: {message}");
            return ExitCode::FAILURE;
        }
    };

    if let Err(error) = std::fs::create_dir_all(&options.directory) {
        eprintln!(
            "kismet-feed: cannot make {}: {error}",
            options.directory.display()
        );
        return ExitCode::FAILURE;
    }

    let client = QueryClient::new(options.socket.clone(), options.token.clone());

    match write_once(&client, &options.directory) {
        Ok(count) => println!("kismet-feed: wrote {count} netspot files"),
        Err(error) => {
            eprintln!("kismet-feed: {error}");
            return ExitCode::FAILURE;
        }
    }

    if options.interval == 0 {
        return ExitCode::SUCCESS;
    }

    // The files are written again and again, so an access point that is
    // seen again is written again, with its newer signal level.
    loop {
        std::thread::sleep(Duration::from_secs(options.interval));
        match write_once(&client, &options.directory) {
            Ok(count) => println!("kismet-feed: wrote {count} netspot files"),
            Err(error) => eprintln!("kismet-feed: {error}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The arguments as a list.
    fn arguments(lines: &[&str]) -> Vec<String> {
        lines.iter().map(|line| line.to_string()).collect()
    }

    #[test]
    fn the_directory_is_the_first_argument() {
        let options = parse_arguments(&arguments(&["/tmp/netspot", "--token", "t"]))
            .expect("the arguments should parse");
        assert_eq!(options.directory, PathBuf::from("/tmp/netspot"));
        assert_eq!(options.token, "t");
        assert_eq!(options.interval, 0);
    }

    #[test]
    fn the_socket_and_the_interval_can_be_given() {
        let options = parse_arguments(&arguments(&[
            "/tmp/netspot",
            "--socket",
            "/tmp/query.sock",
            "--token",
            "t",
            "--interval",
            "30",
        ]))
        .expect("the arguments should parse");
        assert_eq!(options.socket, PathBuf::from("/tmp/query.sock"));
        assert_eq!(options.interval, 30);
    }

    #[test]
    fn a_missing_directory_is_an_error() {
        let error =
            parse_arguments(&arguments(&["--token", "t"])).expect_err("there should be no options");
        assert!(error.contains("usage"));
    }

    #[test]
    fn an_unknown_option_is_an_error() {
        let error = parse_arguments(&arguments(&["/tmp/netspot", "--bogus"]))
            .expect_err("there should be no options");
        assert!(error.contains("--bogus"));
    }
}
