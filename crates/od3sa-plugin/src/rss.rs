//! The resident set of a process.
//!
//! The host reads it from `/proc/<pid>/status`, the `VmRSS` line — the
//! same source the device test uses for the daemon's own RSS.

use std::fs;
use std::path::PathBuf;

/// The resident set of a process, in kilobytes.
///
/// Returns `None` when the process is gone, or when the file does not say.
pub fn resident_kb(pid: u32) -> Option<u64> {
    let path = PathBuf::from(format!("/proc/{pid}/status"));
    let text = fs::read_to_string(path).ok()?;

    for line in text.lines() {
        let Some(rest) = line.strip_prefix("VmRSS:") else {
            continue;
        };
        let number = rest.split_whitespace().next()?;
        return number.parse().ok();
    }

    None
}
