//! Interruption handling.
//!
//! The daemon has to stop cleanly when the operator presses Ctrl-C: the
//! capture handle is released, the final summary is printed and the exit
//! status is a normal one.
//!
//! # How
//!
//! The C library's `signal(3)` is the only way to learn about SIGINT
//! without a dependency on `libc`, and the daemon has no dependency beyond
//! `od3sa-parse` and `od3sa-capture`. The handler does one thing: it sets
//! an atomic flag. The capture loop reads the flag between reads, so the
//! daemon stops at the next read timeout, which is a hundred milliseconds
//! by default, and prints the final summary.
//!
//! # Safety
//!
//! This module is the only place in the daemon that uses `unsafe`, and it
//! is the same shape as the capture crate's libpcap module: an
//! `unsafe extern "C"` declaration and a handler function, and nothing else.
//!
//! The handler itself is async-signal-safe: it stores into an
//! [`AtomicBool`], which compiles to a plain store, and it does nothing
//! else. It never allocates, never locks and never prints.

#![allow(unsafe_code)]

use std::sync::atomic::{AtomicBool, Ordering};

/// The signal number of SIGINT, what Ctrl-C sends.
///
/// This is the Linux value; the daemon only runs on Linux.
const SIGINT: i32 = 2;

/// The signal number of SIGTERM, what `kill` sends by default.
const SIGTERM: i32 = 15;

/// The type of a signal handler in the C library.
type Handler = extern "C" fn(i32);

/// Set by the handler when an interruption arrives.
static INTERRUPTED: AtomicBool = AtomicBool::new(false);

unsafe extern "C" {
    /// The C library's `signal(3)`: install a handler for a signal.
    ///
    /// The return value is the previous handler, which the C library may
    /// report as `SIG_ERR`, `SIG_DFL` or `SIG_IGN`: those are not function
    /// pointers, so the return type is a plain pointer and the value is
    /// ignored.
    fn signal(signum: i32, handler: Handler) -> *mut std::ffi::c_void;
}

/// The handler: remember that the daemon was interrupted.
extern "C" fn handle(_signum: i32) {
    // The only thing a signal handler may do here is set a flag.
    INTERRUPTED.store(true, Ordering::SeqCst);
}

/// Install the interruption handler.
///
/// The handler is installed for SIGINT (Ctrl-C) and for SIGTERM (`kill`),
/// so that both stop the daemon cleanly and print the final summary.
pub fn install() {
    // SAFETY: `signal` is the C library's own function, the handler has the
    // C signature it expects, and the handler only stores into an atomic.
    unsafe {
        signal(SIGINT, handle);
        signal(SIGTERM, handle);
    }
}

/// True when an interruption arrived since [`install`] was called.
pub fn interrupted() -> bool {
    INTERRUPTED.load(Ordering::SeqCst)
}
