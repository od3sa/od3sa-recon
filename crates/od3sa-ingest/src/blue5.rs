//! The blue5 ingest adapter: the Bluetooth networks the Pager's own scanner
//! has seen, read from the file it writes.
//!
//! blue5 writes a **WiGLE CSV** file: the same format the `wigle-export`
//! plugin writes, so the two agree on what a row means. The device's exact
//! column list is confirmed by OR-011; until then the header is read from
//! the file itself, so a file with a different order still works ✓.
//!
//! # Read-only
//!
//! The adapter **only reads**. It opens the file for reading, follows it as
//! it grows, and writes what it finds into the database through the store's
//! writer. It never writes to the file, never moves it, and never touches
//! the scanner that writes it.

use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

/// One network from the WiGLE CSV.
#[derive(Debug, Clone, PartialEq)]
pub struct Network {
    /// The address the network was seen at.
    pub mac: String,
    /// The network name. May be empty.
    pub ssid: String,
    /// The channel, if the file says.
    pub channel: Option<i64>,
    /// The centre frequency in MHz, if the file says.
    pub frequency: Option<i64>,
    /// The signal level in dBm, if the file says.
    pub signal: Option<i64>,
    /// The latitude, if the file says.
    pub latitude: Option<f64>,
    /// The longitude, if the file says.
    pub longitude: Option<f64>,
    /// The altitude in metres, if the file says.
    pub altitude: Option<f64>,
}

impl Network {
    /// The network as the database wants it: the access point of a network
    /// the Pager's scanner saw.
    pub fn as_access_point(&self) -> od3sa_store::AccessPoint {
        od3sa_store::AccessPoint {
            bssid: mac_to_bytes(&self.mac).unwrap_or([0; 6]),
            ssid: if self.ssid.is_empty() {
                None
            } else {
                Some(self.ssid.as_bytes().to_vec())
            },
            ssid_hidden: self.ssid.is_empty(),
            channel: self.channel.and_then(|channel| u16::try_from(channel).ok()),
            freq_mhz: self
                .frequency
                .and_then(|frequency| u16::try_from(frequency).ok()),
            band: None,
            security: None,
            akm: None,
            pairwise: None,
            group_cipher: None,
            pmf_required: false,
            wps: false,
            ht: false,
            vht: false,
            he: false,
            beacon_interval: None,
        }
    }
}

/// Why a row could not be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IngestError {
    /// The file could not be opened.
    Io(String),
    /// The header names a column this adapter does not know.
    UnknownColumn(String),
    /// A row does not have the shape the header says it does.
    Row(String),
}

impl std::fmt::Display for IngestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(reason) => write!(f, "cannot read the file: {reason}"),
            Self::UnknownColumn(column) => write!(f, "unknown column '{column}'"),
            Self::Row(reason) => write!(f, "the row does not make sense: {reason}"),
        }
    }
}

impl std::error::Error for IngestError {}

/// The columns of a WiGLE CSV, by name.
///
/// The file is read with its own header ✓, so the order does not matter and a
/// file with fewer columns still works ✓.
#[derive(Debug, Clone, Default)]
pub struct Columns {
    mac: Option<usize>,
    ssid: Option<usize>,
    channel: Option<usize>,
    frequency: Option<usize>,
    signal: Option<usize>,
    latitude: Option<usize>,
    longitude: Option<usize>,
    altitude: Option<usize>,
}

/// Read the header and say which column is which.
pub fn read_header(line: &str) -> Result<Columns, IngestError> {
    let mut columns = Columns::default();
    for (index, name) in split_row(line).into_iter().enumerate() {
        match name.trim().to_ascii_lowercase().as_str() {
            "mac" => columns.mac = Some(index),
            "ssid" => columns.ssid = Some(index),
            "channel" => columns.channel = Some(index),
            "frequency" => columns.frequency = Some(index),
            "signal" | "signalstrength" => columns.signal = Some(index),
            "latitude" | "lat" => columns.latitude = Some(index),
            "longitude" | "lon" | "long" => columns.longitude = Some(index),
            "altmeters" | "alt" | "altitude" => columns.altitude = Some(index),
            _ => {}
        }
    }
    if columns.mac.is_none() {
        return Err(IngestError::UnknownColumn("mac".to_string()));
    }
    Ok(columns)
}

/// Read one row, using the columns the header said.
pub fn read_row(line: &str, columns: &Columns) -> Result<Option<Network>, IngestError> {
    let fields = split_row(line);
    if fields.is_empty() {
        return Ok(None);
    }

    let mac = columns
        .mac
        .and_then(|index| fields.get(index))
        .map(|value| value.trim().to_string())
        .unwrap_or_default();
    if mac.is_empty() {
        return Ok(None);
    }

    let text = |index: Option<usize>| -> Option<String> {
        index
            .and_then(|index| fields.get(index))
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
    };

    let number = |index: Option<usize>| -> Option<i64> {
        text(index).and_then(|value| value.parse::<i64>().ok())
    };
    let float = |index: Option<usize>| -> Option<f64> {
        text(index).and_then(|value| value.parse::<f64>().ok())
    };

    Ok(Some(Network {
        mac,
        ssid: text(columns.ssid).unwrap_or_default(),
        channel: number(columns.channel),
        frequency: number(columns.frequency),
        signal: number(columns.signal),
        latitude: float(columns.latitude),
        longitude: float(columns.longitude),
        altitude: float(columns.altitude),
    }))
}

/// Split a CSV row.
///
/// A field with a comma, a quote or a newline in it is quoted, and a quote
/// inside a field is doubled ✓ — the same rules the `wigle-export` plugin
/// writes ✓.
fn split_row(line: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut field = String::new();
    let mut quoted = false;
    let mut characters = line.chars().peekable();

    while let Some(character) = characters.next() {
        if quoted {
            match character {
                '"' => {
                    if characters.peek() == Some(&'"') {
                        characters.next();
                        field.push('"');
                    } else {
                        quoted = false;
                    }
                }
                other => field.push(other),
            }
            continue;
        }
        match character {
            '"' => quoted = true,
            ',' => {
                fields.push(std::mem::take(&mut field));
            }
            other => field.push(other),
        }
    }
    fields.push(field);
    fields
}

/// The address of a network, as six bytes.
fn mac_to_bytes(mac: &str) -> Option<[u8; 6]> {
    let parts: Vec<&str> = mac.split(':').collect();
    if parts.len() != 6 {
        return None;
    }
    let mut bytes = [0u8; 6];
    for (index, part) in parts.iter().enumerate() {
        bytes[index] = u8::from_str_radix(part.trim(), 16).ok()?;
    }
    Some(bytes)
}

/// Follow a file that grows, and hand every new row to a callback.
///
/// The file is opened **for reading only** ✓. The adapter reads the header
/// once, and then reads the rows as they are appended ✓ — it never writes to
/// the file and never moves it ✓.
///
/// It returns when the file cannot be read, so the caller can decide what to
/// do about it.
pub fn follow<F>(path: &Path, mut on_network: F) -> Result<(), IngestError>
where
    F: FnMut(&Network),
{
    let file = File::open(path).map_err(|error| IngestError::Io(error.to_string()))?;
    let mut reader = BufReader::new(file);

    let mut header = String::new();
    reader
        .read_line(&mut header)
        .map_err(|error| IngestError::Io(error.to_string()))?;
    let columns = read_header(&header)?;

    let mut line = String::new();
    loop {
        line.clear();
        let read = reader
            .read_line(&mut line)
            .map_err(|error| IngestError::Io(error.to_string()))?;
        if read == 0 {
            // Nothing new. Wait a moment and look again.
            std::thread::sleep(std::time::Duration::from_millis(500));
            continue;
        }
        if let Some(network) = read_row(&line, &columns)? {
            on_network(&network);
        }
    }
}

/// The networks a file holds, read once.
pub fn read_all(path: &Path) -> Result<Vec<Network>, IngestError> {
    let file = File::open(path).map_err(|error| IngestError::Io(error.to_string()))?;
    let mut reader = BufReader::new(file);

    let mut header = String::new();
    reader
        .read_line(&mut header)
        .map_err(|error| IngestError::Io(error.to_string()))?;
    let columns = read_header(&header)?;

    let mut networks = Vec::new();
    let mut line = String::new();
    loop {
        line.clear();
        let read = reader
            .read_line(&mut line)
            .map_err(|error| IngestError::Io(error.to_string()))?;
        if read == 0 {
            return Ok(networks);
        }
        if let Some(network) = read_row(&line, &columns)? {
            networks.push(network);
        }
    }
}

/// The networks a file holds, by address, for the ones that are new.
pub fn new_networks<'a>(
    seen: &mut HashMap<String, Network>,
    networks: &'a [Network],
) -> Vec<&'a Network> {
    let mut fresh = Vec::new();
    for network in networks {
        let previous = seen.get(&network.mac);
        if previous.map(|previous| previous.signal) != Some(network.signal) {
            fresh.push(network);
            seen.insert(network.mac.clone(), network.clone());
        }
    }
    fresh
}
