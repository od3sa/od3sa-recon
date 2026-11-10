//! A gpsd client for od3sa-recon.
//!
//! The daemon tags a sighting with the position of the device when gpsd has
//! one. This crate is the whole of that: a small client for the gpsd JSON
//! protocol that keeps the last fix and never takes the daemon down when
//! gpsd is missing.
//!
//! # Scope
//!
//! * **Read-only.** The client only reads a socket. Nothing here touches a
//!   radio.
//! * **Optional.** A Pager may have no GPS at all and gpsd may not be
//!   running. Failing to connect is a normal outcome, not a fatal one: the
//!   caller may ignore the error and carry on without a position.
//! * **Tolerant.** A line that is not JSON, or is JSON of a shape the daemon
//!   does not want, is ignored rather than raised.
//! * **Sticky.** The last known position is kept when gpsd goes quiet: a
//!   sighting tagged with a position from a minute ago is better than a
//!   sighting with no position at all.
//!
//! The protocol is the gpsd JSON protocol: a request is a command introduced
//! by `?` (see `gpsd_json(5)`), and the answers are JSON objects, one per
//! line. A `WATCH` answer carries the position at the top level, a `POLL`
//! answer carries it inside a `tpv` array; the client reads both.
//!
//! The contract for this crate is `docs/GPS-API.md`.
//!
//! # Example
//!
//! ```no_run
//! use od3sa_gps::GpsdClient;
//!
//! let mut gps = GpsdClient::new();
//! if gps.connect().is_err() {
//!     // No gpsd on this device. Carry on without a position.
//! }
//! let _ = gps.poll();
//! if let Some(fix) = gps.last_fix() {
//!     println!("{} {} {}", fix.lat, fix.lon, fix.mode);
//! }
//! ```

#![forbid(unsafe_code)]

mod time;

#[cfg(test)]
mod tests;

use std::fmt;
use std::io::{ErrorKind, Read, Write};
use std::net::{Shutdown, TcpStream, ToSocketAddrs};
use std::time::Duration;

use serde_json::Value;

use crate::time::parse_iso8601_ms;

/// Where gpsd listens by default.
const DEFAULT_ADDRESS: &str = "127.0.0.1:2947";

/// How long to wait for the TCP connection to be established.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);

/// The request sent to gpsd once the connection is up.
///
/// A request is a command introduced by `?`, not a JSON object: gpsd 3.x
/// answers a bare `{"class":"POLL"}` with an "Unrecognized request" error.
/// The command is `WATCH` with a JSON object as its argument, so that gpsd
/// sends a message every time the position changes. A device has to be
/// watched before it can be polled, so this goes out first.
///
/// See `gpsd_json(5)`.
const WATCH_REQUEST: &str = "?WATCH={\"enable\":true,\"json\":true}\n";

/// A position, as gpsd reports it.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Fix {
    /// The latitude in degrees.
    pub lat: f64,
    /// The longitude in degrees.
    pub lon: f64,
    /// The altitude in metres.
    pub alt: f64,
    /// The fix mode: 1 none, 2 two-dimensional, 3 three-dimensional.
    pub mode: u8,
    /// When gpsd says the fix was taken, in unix epoch milliseconds.
    pub ts_ms: i64,
}

/// Something went wrong talking to gpsd.
///
/// None of these are fatal for the daemon: a device without gpsd is normal.
#[derive(Debug)]
pub enum GpsError {
    /// The socket could not be opened, or a read failed.
    Io(std::io::Error),
    /// The client is not connected, so there is nothing to read.
    NotConnected,
    /// gpsd closed the connection.
    Disconnected,
}

impl fmt::Display for GpsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(err) => write!(f, "gpsd socket: {err}"),
            Self::NotConnected => write!(f, "not connected to gpsd"),
            Self::Disconnected => write!(f, "gpsd closed the connection"),
        }
    }
}

impl std::error::Error for GpsError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            _ => None,
        }
    }
}

impl From<std::io::Error> for GpsError {
    fn from(err: std::io::Error) -> GpsError {
        GpsError::Io(err)
    }
}

/// The gpsd client.
///
/// The client holds one TCP connection to gpsd and the last fix it has seen.
/// It is not a background thread: the daemon calls [`GpsdClient::poll`] on a
/// timer and reconnects when a poll fails.
#[derive(Debug)]
pub struct GpsdClient {
    address: String,
    stream: Option<TcpStream>,
    last_fix: Option<Fix>,
    /// Bytes of a message that has not been terminated by a newline yet.
    pending: Vec<u8>,
}

impl Default for GpsdClient {
    fn default() -> Self {
        Self::new()
    }
}

impl GpsdClient {
    /// A client that will connect to `127.0.0.1:2947`.
    pub fn new() -> GpsdClient {
        GpsdClient::with_address(DEFAULT_ADDRESS)
    }

    /// A client that will connect to the given address.
    pub fn with_address(address: &str) -> GpsdClient {
        GpsdClient {
            address: address.to_owned(),
            stream: None,
            last_fix: None,
            pending: Vec::new(),
        }
    }

    /// The address this client connects to.
    pub fn address(&self) -> &str {
        &self.address
    }

    /// Connect and start watching.
    ///
    /// Failing to connect is **not** an error: gpsd may not be running, and
    /// the daemon has to work without a position. The error is returned so
    /// that the caller may log it; the client stays disconnected and
    /// [`GpsdClient::last_fix`] stays `None`.
    ///
    /// # Errors
    ///
    /// Returns [`GpsError::Io`] when the address cannot be resolved or the
    /// socket cannot be opened.
    pub fn connect(&mut self) -> Result<(), GpsError> {
        let address = self
            .address
            .to_socket_addrs()
            .map_err(GpsError::Io)?
            .next()
            .ok_or_else(|| {
                GpsError::Io(std::io::Error::new(
                    ErrorKind::InvalidInput,
                    "the gpsd address does not resolve",
                ))
            })?;

        // Connect and send the request while the socket is still blocking,
        // so that a partial write cannot turn into a would-block error.
        let mut stream = TcpStream::connect_timeout(&address, CONNECT_TIMEOUT)?;
        stream.write_all(WATCH_REQUEST.as_bytes())?;
        stream.flush()?;

        // Reads must not block: `poll` is called on a timer and returns
        // zero when gpsd has said nothing yet.
        stream.set_nonblocking(true)?;

        self.pending.clear();
        self.stream = Some(stream);
        Ok(())
    }

    /// Read whatever gpsd has sent, and update the last fix.
    ///
    /// Returns the number of messages read. Returns zero when nothing has
    /// arrived yet. Messages that are not JSON, or are JSON of a shape the
    /// daemon does not care about, are counted but ignored.
    ///
    /// # Errors
    ///
    /// Returns [`GpsError::NotConnected`] when the client is not connected,
    /// [`GpsError::Disconnected`] when gpsd closed the connection, and
    /// [`GpsError::Io`] when the socket failed. After any of those the client
    /// is disconnected; the next [`GpsdClient::connect`] tries again.
    pub fn poll(&mut self) -> Result<usize, GpsError> {
        // The stream is moved out for the duration of the read so that the
        // buffer and the last fix can be updated while it is borrowed.
        let mut stream = match self.stream.take() {
            Some(stream) => stream,
            None => return Err(GpsError::NotConnected),
        };

        match self.read_messages(&mut stream) {
            Ok(count) => {
                self.stream = Some(stream);
                Ok(count)
            }
            Err(err) => {
                // The connection is gone: the stream is dropped here and the
                // client reports itself disconnected.
                let _ = stream.shutdown(Shutdown::Both);
                Err(err)
            }
        }
    }

    /// The last fix, if there is one.
    ///
    /// The fix is kept when gpsd goes quiet, so this stays `Some` after a
    /// disconnect until a newer fix arrives.
    pub fn last_fix(&self) -> Option<Fix> {
        self.last_fix
    }

    /// Whether the client is connected.
    pub fn is_connected(&self) -> bool {
        self.stream.is_some()
    }

    /// Disconnect.
    ///
    /// The last fix is kept.
    pub fn disconnect(&mut self) {
        if let Some(stream) = self.stream.take() {
            let _ = stream.shutdown(Shutdown::Both);
        }
        self.pending.clear();
    }

    /// Read from the socket until it would block, and handle what arrives.
    fn read_messages(&mut self, stream: &mut TcpStream) -> Result<usize, GpsError> {
        let mut count = 0usize;
        let mut chunk = [0u8; 4096];
        loop {
            match stream.read(&mut chunk) {
                Ok(0) => return Err(GpsError::Disconnected),
                Ok(n) => {
                    self.pending.extend_from_slice(&chunk[..n]);
                    count += self.take_messages();
                }
                Err(err) if err.kind() == ErrorKind::WouldBlock => break,
                Err(err) if err.kind() == ErrorKind::Interrupted => continue,
                Err(err) => return Err(GpsError::Io(err)),
            }
        }
        Ok(count)
    }

    /// Take the complete messages out of the buffer and handle them.
    ///
    /// A message is one line: gpsd sends one JSON object per line. The
    /// bytes of a half-received line stay in the buffer until the newline
    /// arrives.
    fn take_messages(&mut self) -> usize {
        let mut lines: Vec<Vec<u8>> = Vec::new();
        let mut start = 0usize;
        for (index, byte) in self.pending.iter().enumerate() {
            if *byte == b'\n' {
                lines.push(self.pending[start..index].to_vec());
                start = index + 1;
            }
        }
        if start > 0 {
            self.pending.drain(..start);
        }
        for line in &lines {
            self.handle_line(line);
        }
        lines.len()
    }

    /// Handle one line of the gpsd stream.
    ///
    /// A line that is not JSON, or is JSON the daemon does not care about,
    /// is ignored.
    fn handle_line(&mut self, line: &[u8]) {
        let text = match std::str::from_utf8(line) {
            Ok(text) => text.trim(),
            Err(_) => return,
        };
        if text.is_empty() {
            return;
        }
        let value: Value = match serde_json::from_str(text) {
            Ok(value) => value,
            Err(_) => return,
        };
        if let Some(fix) = fix_from_value(&value) {
            self.last_fix = Some(fix);
        }
    }
}

/// Read a fix out of a gpsd message.
///
/// A `WATCH` message carries the position of a device at the top level. A
/// `POLL` message carries the position of each device inside a `tpv` array,
/// one entry per device; the field inventory of a poll response is not
/// fixed, so a poll without that array is ignored.
///
/// Returns `None` for every message that is not a position: another class
/// (`DEVICES`, `VERSION`, `ERROR`, ...), a position without a fix (mode 1, or
/// no mode at all), and a position that is not worth keeping.
fn fix_from_value(value: &Value) -> Option<Fix> {
    let object = value.as_object()?;
    let class = object.get("class").and_then(Value::as_str)?;
    match class {
        "WATCH" => fix_from_fields(object),
        "POLL" => {
            // The position of each device the daemon is tracking.
            let tpv = object.get("tpv")?.as_array()?;
            tpv.iter()
                .find_map(|entry| fix_from_fields(entry.as_object()?))
        }
        _ => None,
    }
}

/// Read a fix out of the fields of one gpsd position object.
fn fix_from_fields(object: &serde_json::Map<String, Value>) -> Option<Fix> {
    let mode = number(object, "mode")?;
    // Mode 1 is "no fix": it must not replace a good fix with a bad one.
    if mode < 2.0 {
        return None;
    }
    let mode = u8::try_from(mode as u64).ok()?;

    let lat = number(object, "lat")?;
    let lon = number(object, "lon")?;
    if !(-90.0..=90.0).contains(&lat) || !(-180.0..=180.0).contains(&lon) {
        return None;
    }

    let alt = number(object, "alt").unwrap_or(0.0);
    let ts_ms = object
        .get("time")
        .and_then(Value::as_str)
        .and_then(parse_iso8601_ms)
        .unwrap_or(0);

    Some(Fix {
        lat,
        lon,
        alt,
        mode,
        ts_ms,
    })
}

/// A numeric field of a gpsd message.
fn number(object: &serde_json::Map<String, Value>, key: &str) -> Option<f64> {
    object.get(key).and_then(Value::as_f64)
}
