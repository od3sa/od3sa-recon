//! The `pager-ui` payload: show what the daemon has seen.
//!
//! The Pager's payload menu runs a shell script, and that script calls this
//! binary and hands its output to `logger`. The binary is here because the
//! Pager's busybox cannot speak to a Unix socket: there is no `nc -U` and
//! no JSON parser, so a shell script simply cannot reach the daemon's query
//! socket.

use std::process::ExitCode;

use od3sa_plugins::client::QueryClient;
use od3sa_plugins::pager_ui;

fn main() -> ExitCode {
    let client = match QueryClient::from_env() {
        Ok(client) => client,
        Err(error) => {
            eprintln!("pager-ui: {error}");
            return ExitCode::FAILURE;
        }
    };

    match pager_ui::summarise(&client) {
        Ok(summary) => {
            println!("{}", summary.text());
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("pager-ui: {error}");
            ExitCode::FAILURE
        }
    }
}
