//! Fuzz target for the radiotap header parser.
//!
//! The radiotap header is a pseudo-header that the driver prepends to every
//! captured frame. It is a variable-length list of fields, described by a
//! bitmask, so the parser walks the mask and skips the fields it does not
//! care about. That walk is where an out-of-bounds read would hide.
//!
//! The target asserts the invariants the parser promises:
//!
//! * the parser never panics: it either parses or reports an error,
//! * the header length it returns fits the buffer and covers the eight byte
//!   preamble,
//! * the fields it reports are exactly the ones the present mask names.
//!
//! A violated invariant is a panic, and a panic fails the target.

#![no_main]

use libfuzzer_sys::fuzz_target;

/// The size of the radiotap preamble: `it_version`, `it_pad`, `it_len` and
/// `it_present`.
const PREAMBLE_LEN: usize = 8;

/// The bit *position* of the flags byte in `it_present`.
const BIT_FLAGS: u32 = 1;
/// The bit *position* of the data rate in `it_present`.
const BIT_RATE: u32 = 2;
/// The bit *position* of the channel in `it_present`.
const BIT_CHANNEL: u32 = 3;
/// The bit *position* of the signal level in dBm in `it_present`.
const BIT_DBM: u32 = 5;

fuzz_target!(|data: &[u8]| {
    // The parser must answer for every input, whatever the bytes are.
    let Ok(header) = od3sa_parse::radiotap::parse(data) else {
        return;
    };

    let len = header.len as usize;

    // The header length is `it_len`: it covers the preamble and it never
    // points past the end of the buffer.
    assert!(len >= PREAMBLE_LEN, "it_len is shorter than the preamble");
    assert!(len <= data.len(), "it_len points past the buffer");

    // The version and the present mask are read straight from the preamble.
    assert_eq!(header.version, data[0]);
    assert_eq!(
        header.present,
        u32::from_le_bytes([data[4], data[5], data[6], data[7]])
    );

    // Every field the daemon reads sits below bit 16, and radiotap fields
    // appear in the header in bit order, so a field that the mask names is
    // always read. A field that is not named is never reported.
    assert_eq!(
        header.flags.is_some(),
        header.present & (1 << BIT_FLAGS) != 0
    );
    assert_eq!(header.rate.is_some(), header.present & (1 << BIT_RATE) != 0);
    assert_eq!(
        header.channel.is_some(),
        header.present & (1 << BIT_CHANNEL) != 0
    );
    assert_eq!(
        header.signal_dbm.is_some(),
        header.present & (1 << BIT_DBM) != 0
    );

    // The channel number is a pure mapping of the centre frequency: a
    // frequency that is not a channel centre gives no channel.
    if let Some(channel) = header.channel {
        let number = od3sa_parse::radiotap::channel_number(channel.freq_mhz);
        if let Some(number) = number {
            assert!(number >= 1, "a channel number is never zero");
        }
    }
});
