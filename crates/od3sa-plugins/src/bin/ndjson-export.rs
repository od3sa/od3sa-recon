//! The `ndjson-export` plugin: what the daemon has seen, one JSON object
//! per line.
//!
//! The plugin is started by hand, not by the host: it is an export one asks
//! for, not something that runs for ever. The daemon's query socket and the
//! plugin's token come from the environment, the way the host gives them to
//! the plugins it starts:
//!
//! ```sh
//! OD3SA_QUERY=/tmp/od3sa-recon/query.sock \
//! OD3SA_TOKEN="$(od3sa-recond plugin token ndjson-export)" \
//! plugins/ndjson-export/bin/ndjson-export /tmp/export.ndjson devices
//! ```
//!
//! The token is only ever read from the environment, never from the command
//! line: a command line is visible to every process on the machine.
//!
//! The output path is the first argument. The second argument is what to
//! export: `devices`, `aps`, `clients`, `sightings`, `alerts`, or several
//! of them separated by commas. With one kind the path is the file to
//! write; with several kinds the path is a directory, and it holds one
//! file per kind.
//!
//! The export only reads. It never touches a radio, a channel or a service.

use std::path::PathBuf;
use std::process::ExitCode;

use od3sa_plugins::client::QueryClient;
use od3sa_plugins::ndjson;

fn main() -> ExitCode {
    let arguments: Vec<String> = std::env::args().skip(1).collect();

    // Asking for help needs nothing else, not even a socket.
    if arguments
        .iter()
        .any(|argument| argument == "--help" || argument == "-h")
    {
        println!("{}", usage());
        return ExitCode::SUCCESS;
    }

    let mut positional: Vec<String> = Vec::new();
    let mut socket: Option<PathBuf> = None;
    let mut index = 0;

    while index < arguments.len() {
        match arguments[index].as_str() {
            "--socket" => {
                let Some(value) = arguments.get(index + 1) else {
                    eprintln!("ndjson-export: --socket needs the path of the query socket");
                    return ExitCode::FAILURE;
                };
                socket = Some(PathBuf::from(value));
                index += 2;
            }
            other if other.starts_with('-') => {
                eprintln!("ndjson-export: '{other}' is not an option");
                eprintln!("{}", usage());
                return ExitCode::FAILURE;
            }
            other => {
                positional.push(other.to_string());
                index += 1;
            }
        }
    }

    let Some(path) = positional.first().cloned() else {
        eprintln!("{}", usage());
        return ExitCode::FAILURE;
    };
    if positional.len() > 2 {
        eprintln!("ndjson-export: too many arguments: there are only two");
        eprintln!("{}", usage());
        return ExitCode::FAILURE;
    }

    // The second argument is what to export. It is optional, and with no
    // second argument every kind is exported.
    let kinds = match positional.get(1) {
        None => ndjson::Kind::ALL.to_vec(),
        Some(name) => match ndjson::kinds_named(name) {
            Some(kinds) => kinds,
            None => {
                eprintln!(
                    "ndjson-export: '{name}' is not a kind: the kinds are {}",
                    ndjson::kind_names()
                );
                return ExitCode::FAILURE;
            }
        },
    };

    let client = match client(socket) {
        Ok(client) => client,
        Err(message) => {
            eprintln!("ndjson-export: {message}");
            return ExitCode::FAILURE;
        }
    };

    match ndjson::export_to_path(&client, &kinds, &PathBuf::from(&path)) {
        Ok(report) => {
            for (kind, count) in &report.objects {
                eprintln!("ndjson-export: {}: {count} objects", kind.name());
            }
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("ndjson-export: {error}");
            ExitCode::FAILURE
        }
    }
}

/// The client the export reads through.
///
/// The token comes from the environment only. The socket comes from the
/// environment too, unless `--socket` says otherwise.
fn client(socket: Option<PathBuf>) -> Result<QueryClient, String> {
    let token = std::env::var("OD3SA_TOKEN")
        .map_err(|_| "OD3SA_TOKEN is not set: is this plugin started by the host?".to_string())?;

    let socket = match socket {
        Some(socket) => socket,
        None => PathBuf::from(std::env::var("OD3SA_QUERY").map_err(|_| {
            "OD3SA_QUERY is not set: is this plugin started by the host?".to_string()
        })?),
    };

    Ok(QueryClient::new(socket, token))
}

/// What the plugin says when it is asked, or when it is misused.
fn usage() -> String {
    format!(
        "usage: ndjson-export <output-path> [kind] [--socket <path>]\n\
         \n\
         The output path is the first argument. The kind is the second, and\n\
         it is optional: one of {}, or several of them separated by commas,\n\
         or 'all'. With no kind every kind is exported.\n\
         With one kind the path is the file to write; with several kinds the\n\
         path is a directory and it holds one file per kind.\n\
         \n\
         The query socket and the token come from OD3SA_QUERY and\n\
         OD3SA_TOKEN. The token is never read from the command line.",
        ndjson::kind_names()
    )
}
