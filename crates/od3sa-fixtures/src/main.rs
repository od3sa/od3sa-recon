//! `od3sa-fixtures`: write the synthetic fixture pcaps.
//!
//! The binary writes the standard set of synthetic fixtures into a directory:
//! a few beacons, some probe requests, some data frames, some EAPOL frames
//! and a file with one of each. Every frame is built from scratch in code;
//! every MAC address belongs to the `00:11:22:33:44:xx` family and every
//! SSID starts with `example-`.
//!
//! Nothing here touches a radio, a capture handle or the network. The binary
//! only writes files.
//!
//! Usage: `od3sa-fixtures <output-dir>`

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used)]

use std::path::Path;
use std::process::ExitCode;

use od3sa_fixtures::standard_fixtures;

/// The version of the crate, taken from the crate metadata.
const VERSION: &str = env!("CARGO_PKG_VERSION");

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();

    match args.first().map(String::as_str) {
        None | Some("--help") | Some("-h") => {
            print_help();
            ExitCode::SUCCESS
        }
        Some("--version") | Some("-V") => {
            println!("od3sa-fixtures {VERSION}");
            ExitCode::SUCCESS
        }
        Some(directory) => match write_fixtures(Path::new(directory)) {
            Ok(written) => {
                for (name, frames) in written {
                    println!("wrote {name} ({frames} frames)");
                }
                ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("od3sa-fixtures: {error}");
                ExitCode::FAILURE
            }
        },
    }
}

/// Write the standard fixtures into `directory`.
///
/// The directory is created when it does not exist. Nothing outside it is
/// touched: the binary only creates and writes the fixture files.
fn write_fixtures(directory: &Path) -> std::io::Result<Vec<(String, usize)>> {
    std::fs::create_dir_all(directory)?;

    let mut written = Vec::new();
    for fixture in standard_fixtures() {
        let path = directory.join(fixture.name);
        od3sa_fixtures::write_pcap(&path, &fixture.frames)?;
        written.push((fixture.name.to_string(), fixture.frames.len()));
    }

    Ok(written)
}

/// Print the usage text.
fn print_help() {
    println!(
        "od3sa-fixtures {VERSION}\n\
         \n\
         Writes the synthetic 802.11 fixtures of od3sa-recon into a directory.\n\
         Every frame is generated in code: the MAC addresses are from the\n\
         00:11:22:33:44:xx family and the SSIDs start with 'example-'.\n\
         \n\
         Usage: od3sa-fixtures <output-dir>\n\
         \n\
         Options:\n  \
             -h, --help       Print this help and exit\n  \
             -V, --version    Print the version and exit"
    );
}
