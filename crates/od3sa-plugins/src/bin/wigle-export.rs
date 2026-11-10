//! The `wigle-export` plugin: the access points the daemon has seen, as a
//! WiGLE CSV.
//!
//! The plugin is run by hand (`run = "external"` in the manifest), so it
//! takes the socket and the token on the command line or from the
//! environment:
//!
//! ```text
//! wigle-export [--socket <path>] [--token <token>] [--output <path>]
//! ```
//!
//! It reads the daemon through the read-only query socket and writes a CSV.
//! It touches no radio, no channel and no service.

use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;

use od3sa_plugins::client::QueryClient;

// The plugin's logic lives in the crate's `wigle` module. It is pulled in
// here by path so that this binary builds on its own. When `lib.rs` grows a
use od3sa_plugins::wigle;

/// The query socket the plugin talks to when nothing else is said.
const DEFAULT_SOCKET: &str = "/tmp/od3sa-recon/query.sock";

/// The help text.
const HELP: &str = "\
wigle-export - the access points the daemon has seen, as a WiGLE CSV

Usage:
  wigle-export [options]

Options:
  --socket <path>   the daemon's query socket
                    (default: $OD3SA_QUERY, or /tmp/od3sa-recon/query.sock)
  --token <token>   the token to present to the daemon
                    (default: $OD3SA_TOKEN)
  --output <path>   the file to write the CSV to (default: stdout)
  -h, --help        show this help
";

/// What the plugin was asked to do.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Options {
    /// The query socket.
    socket: PathBuf,
    /// The token to present.
    token: String,
    /// Where the CSV goes; `None` means stdout.
    output: Option<PathBuf>,
    /// Whether the help text was asked for.
    help: bool,
}

fn main() -> ExitCode {
    let options = match parse(std::env::args().skip(1)) {
        Ok(options) => options,
        Err(reason) => {
            eprintln!("wigle-export: {reason}");
            eprintln!("{HELP}");
            return ExitCode::FAILURE;
        }
    };

    if options.help {
        print!("{HELP}");
        return ExitCode::SUCCESS;
    }

    match run(&options) {
        Ok(()) => ExitCode::SUCCESS,
        Err(reason) => {
            eprintln!("wigle-export: {reason}");
            ExitCode::FAILURE
        }
    }
}

/// Do the export.
fn run(options: &Options) -> Result<(), String> {
    let client = QueryClient::new(options.socket.clone(), options.token.clone());
    let csv = wigle::export_now(&client).map_err(|error| error.to_string())?;

    match &options.output {
        Some(path) => std::fs::write(path, csv)
            .map_err(|error| format!("cannot write {}: {error}", path.display())),
        None => {
            let mut out = std::io::stdout().lock();
            out.write_all(csv.as_bytes())
                .and_then(|()| out.flush())
                .map_err(|error| format!("cannot write the CSV: {error}"))
        }
    }
}

/// Read the command line.
///
/// The parser is hand-written: the plugin has no dependency beyond
/// `serde_json`, and a handful of options does not justify another one.
fn parse<I>(args: I) -> Result<Options, String>
where
    I: IntoIterator<Item = String>,
{
    let mut socket = std::env::var("OD3SA_QUERY").unwrap_or_else(|_| DEFAULT_SOCKET.to_string());
    let mut token = std::env::var("OD3SA_TOKEN").unwrap_or_default();
    let mut output = None;
    let mut help = false;

    let mut args = args.into_iter();
    while let Some(argument) = args.next() {
        match argument.as_str() {
            "--socket" => {
                socket = value("--socket", &mut args)?;
            }
            "--token" => {
                token = value("--token", &mut args)?;
            }
            "--output" => {
                output = Some(PathBuf::from(value("--output", &mut args)?));
            }
            "-h" | "--help" => {
                help = true;
            }
            other => {
                return Err(format!("'{other}' is not an option I know"));
            }
        }
    }

    Ok(Options {
        socket: PathBuf::from(socket),
        token,
        output,
        help,
    })
}

/// The value of an option, which is the next argument.
fn value<I>(name: &str, args: &mut I) -> Result<String, String>
where
    I: Iterator<Item = String>,
{
    args.next().ok_or_else(|| format!("{name} needs a value"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The options of a command line.
    fn options(args: &[&str]) -> Options {
        parse(args.iter().map(|argument| argument.to_string())).expect("the arguments parse")
    }

    #[test]
    fn the_defaults_are_the_socket_and_the_environment() {
        let options = options(&[]);
        assert_eq!(options.socket, PathBuf::from(DEFAULT_SOCKET));
        assert!(options.output.is_none());
        assert!(!options.help);
    }

    #[test]
    fn the_options_are_read() {
        let options = options(&[
            "--socket",
            "/tmp/other.sock",
            "--token",
            "secret",
            "--output",
            "/tmp/out.csv",
        ]);
        assert_eq!(options.socket, PathBuf::from("/tmp/other.sock"));
        assert_eq!(options.token, "secret");
        assert_eq!(options.output, Some(PathBuf::from("/tmp/out.csv")));
    }

    #[test]
    fn an_option_without_a_value_is_an_error() {
        let error = parse(["--socket".to_string()]).expect_err("there is no value");
        assert!(error.contains("--socket"));
    }

    #[test]
    fn an_option_that_is_not_one_is_an_error() {
        let error = parse(["--nonsense".to_string()]).expect_err("it is not an option");
        assert!(error.contains("--nonsense"));
    }
}
