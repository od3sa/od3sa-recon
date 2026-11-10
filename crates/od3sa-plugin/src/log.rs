//! Where the plugin's output goes.
//!
//! The plugin's stdout and stderr go to `logread`: on the device that is
//! `/dev/log`, and on the build machine it is the daemon's own stderr.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::FileTypeExt;
use std::os::unix::net::UnixDatagram;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};

/// Where the log lines go.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LogDestination {
    /// `/dev/log` when it is there, the daemon's stderr otherwise.
    #[default]
    Auto,
    /// `/dev/log`, whatever happens.
    DevLog,
    /// The daemon's own stderr.
    Stderr,
}

/// The sink the plugin output goes to.
///
/// It is shared by the reader thread of every plugin, so it is behind a
/// lock.
#[derive(Debug, Clone)]
pub(crate) struct LogSink {
    target: Arc<Mutex<Target>>,
}

/// The one place the lines go.
#[derive(Debug)]
enum Target {
    /// A datagram socket, as `/dev/log` is on OpenWrt.
    Datagram {
        /// The socket the datagrams go out on.
        socket: UnixDatagram,
        /// Where they go.
        path: PathBuf,
    },
    /// A file that is appended to.
    File(File),
    /// The daemon's own stderr.
    Stderr,
}

impl LogSink {
    /// A sink for the given destination.
    pub(crate) fn new(destination: LogDestination) -> LogSink {
        let target = match destination {
            LogDestination::Stderr => Target::Stderr,
            LogDestination::DevLog => open_dev_log().unwrap_or(Target::Stderr),
            LogDestination::Auto => open_dev_log().unwrap_or(Target::Stderr),
        };
        LogSink {
            target: Arc::new(Mutex::new(target)),
        }
    }

    /// Write one line.
    pub(crate) fn write_line(&self, line: &str) {
        let mut target = lock(&self.target);

        match &mut *target {
            Target::Datagram { socket, path } => {
                let message = format!("{line}\n");
                let _ = socket.send_to(message.as_bytes(), path);
            }
            Target::File(file) => {
                let _ = writeln!(file, "{line}");
                let _ = file.flush();
            }
            Target::Stderr => {
                eprintln!("{line}");
            }
        }
    }
}

/// Open `/dev/log`, when it can be opened.
///
/// On OpenWrt it is a datagram socket and the line is sent to it as a
/// datagram. When it is a plain file the line is appended to it. When it
/// is not there at all the caller falls back to stderr.
fn open_dev_log() -> Option<Target> {
    let path = Path::new("/dev/log");
    let metadata = fs::symlink_metadata(path).ok()?;

    if metadata.file_type().is_socket() {
        let socket = UnixDatagram::unbound().ok()?;
        return Some(Target::Datagram {
            socket,
            path: path.to_path_buf(),
        });
    }

    let file = OpenOptions::new().append(true).open(path).ok()?;
    Some(Target::File(file))
}

/// Take the lock, taking over a poisoned one.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}
