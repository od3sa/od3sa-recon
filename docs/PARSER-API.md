# Parser API contract

The contract the metadata parsers in `crates/od3sa-parse/src/` are written
against: `radiotap.rs`, `ieee80211.rs`, `ie.rs` and `frame.rs`.

## Crate rules

- `#![forbid(unsafe_code)]` and `clippy::unwrap_used` / `expect_used` are
  denied outside tests (already in `lib.rs` and `clippy.toml`).
- **Never panic.** Every length is bounds-checked against the buffer before it
  is used. No `unwrap` on arithmetic, no slicing that can panic, no
  `unreachable!()` on untrusted input. A malformed frame is an `Err`, not a
  crash.
- **No payload retention.** The parsers read frame *headers* and specific
  metadata fields. Frame payloads and EAPOL bodies are never copied into a
  returned value. A test must prove this (see "Proving no retention").
- **No radio code, ever.** These crates are pure functions over byte slices.
- Synthetic test data only: MACs `00:11:22:33:44:xx`, SSIDs like
  `example-ssid`. Never commit a real capture.
- Unit tests live in the same file, under `#[cfg(test)] mod tests`.
- `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings` and
  `cargo test` must pass. Use `export PATH="$HOME/.cargo/bin:$PATH"` first.

## Shared error type (`error.rs`, already in the tree)

```rust
pub enum ParseError {
    Truncated { needed: usize, available: usize },
    TooShort { expected: usize, available: usize },
    Invalid(&'static str),
}
pub type Result<T> = core::result::Result<T, ParseError>;
```

`error::take(buf, len)` is the bounds-checking primitive: it borrows `len`
bytes from the front of `buf` or returns `ParseError::Truncated`. Use it
rather than indexing.

## File ownership

| File | Contents |
|---|---|
| `radiotap.rs` | radiotap header |
| `ieee80211.rs` | frame control, MAC header, management fixed fields |
| `ie.rs` | information elements |
| `frame.rs` | dispatch, data-header mapping, EAPOL detection |

## `radiotap.rs`

```rust
/// The radiotap header of a captured frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RadiotapHeader {
    /// Total header length, as stated by `it_len` (includes the 8-byte preamble).
    pub len: u16,
    /// The `it_present` bitmask.
    pub present: u32,
    /// `it_version`; 0 for every header in the wild.
    pub version: u8,
    /// Signal strength in dBm, from the `DBM` field.
    pub signal_dbm: Option<i8>,
    /// Channel, from the `CHANNEL` field.
    pub channel: Option<Channel>,
    /// Data rate in units of 500 kbps, from the `Rate` field.
    pub rate: Option<u8>,
    /// Radiotap flags byte, from the `Flags` field.
    pub flags: Option<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Channel {
    /// Centre frequency in MHz.
    pub freq_mhz: u16,
    /// The channel flags the driver reported.
    pub flags: u16,
}

/// Parse the radiotap header at the start of `buf`.
pub fn parse(buf: &[u8]) -> Result<RadiotapHeader>;

/// The 802.11 channel number for a centre frequency, if there is one.
pub fn channel_number(freq_mhz: u16) -> Option<u16>;
```

Notes:
- The header on the wire is **eight** bytes: `it_version` (u8), `it_pad`
  (u8), `it_len` (u16 little-endian), `it_present` (u32 little-endian). This
  is the Linux kernel's `struct ieee80211_radiotap_header` and the radiotap
  specification. `it_len` covers the whole header, those eight bytes
  included.
- Field bit positions in the `it_present` mask: 0 TSFT (u64), 1 Flags (u8),
  2 Rate (u8), 3 Channel (u16 freq + u16 flags), 4 FHSS (u16), 5 DBM (i8),
  6 Antenna (u8), 7 DBMSGI (i8), 8 MCS (3 bytes), 9 AMPDU (u32), 10 VHT
  (12 bytes), 11 TIMESTAMP (u64), 12 HE (12 bytes), 13 HE-MU (12 bytes),
  14 0-length PSDU (u16), 15 L-SIG (4 bytes), 16 TLV, 17 radiotap
  namespace, 18 vendor namespace, 31 the extension bit.
- Fields are aligned to their natural alignment, with padding between them.
  A field that would not fit is an error, not a guess.
- Only `Flags`, `Rate`, `Channel` and `DBM` are interpreted. Everything else
  is skipped by its size, without reading its contents.
- **Bits 16 and up have no fixed size**, so their length cannot be known
  without reading the fields themselves. Rather than guess, the walk **stops**
  when it reaches one: the parser returns the fields it has read so far and
  no error. Every field the daemon cares about (flags, rate, channel, DBM) is
  below bit 16 and is therefore always read first, since radiotap fields
  appear in bit order. `it_len` still gives the caller the header length, so
  the 802.11 frame that follows can still be found. This includes the
  extension bit (31), which means "more present words follow".
- `channel_number` maps 2412..2484 MHz to channels 1..14, 5000..5900 to
  `(freq - 5000) / 5`, and 5955..7115 to `(freq - 5950) / 5`. Return `None`
  for anything else.

## `ieee80211.rs`

```rust
/// The frame type field of the frame control word.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameType {
    Management,
    Control,
    Data,
    Extension,
    Unknown(u8),
}

/// The MAC header of a frame, without the frame body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MacHeader {
    pub frame_control: u16,
    pub duration: u16,
    pub addr1: [u8; 6],
    pub addr2: [u8; 6],
    pub addr3: [u8; 6],
    pub addr4: Option<[u8; 6]>,
    pub sequence_control: u16,
}

impl MacHeader {
    /// Parse the MAC header at the start of `buf`.
    pub fn parse(buf: &[u8]) -> Result<MacHeader>;
    pub fn frame_type(&self) -> FrameType;
    /// The subtype within the frame type.
    pub fn subtype(&self) -> u8;
    pub fn to_ds(&self) -> bool;
    pub fn from_ds(&self) -> bool;
    pub fn is_protected(&self) -> bool;
}

/// The offset of the information elements inside a management frame body.
pub fn management_ie_offset(subtype: u8) -> Option<usize>;
```

Notes:
- The frame control word is little-endian: protocol version in bits 0..2,
  type in 2..3, subtype in 4..7, and the flags from bit 8 up: ToDS (8),
  FromDS (9), MoreFrag (10), Retry (11), PwrMgt (12), MoreData (13),
  Protected (14), Order (15).
- **Correction (2026-11-05):** the frame control masks above are the ones the
  Linux kernel uses in `include/linux/ieee80211.h`: protocol version `0x0003`,
  type `0x000c`, subtype `0x00f0`, To DS `0x0100`, From DS `0x0200`, More
  Fragments `0x0400`, Retry `0x0800`, Power Management `0x1000`, More Data
  `0x2000`, Protected Frame `0x4000`, Order `0x8000`.
- The MAC header is 24 bytes, or 30 for the four-address form. **Address 4 is
  present if and only if the frame is a data frame with To DS *and* From DS
  both set** (IEEE 802.11-2020 Table 9-30; the kernel's `ieee80211_has_a4()`
  has the same rule). There is no address-4 bit in the frame control: the
  field's presence follows from the two DS bits. A management frame never
  carries address 4.
- A **control** frame is shorter than a MAC header: ACK and CTS are 10 bytes
  (frame control, duration, address 1) and RTS is 16. Control frames have no
  address 2 or 3, so they need their own header type:
  ```rust
  #[derive(Debug, Clone, Copy, PartialEq, Eq)]
  pub struct ControlHeader {
      pub frame_control: u16,
      pub duration: u16,
      pub addr1: [u8; 6],
  }
  impl ControlHeader {
      pub fn parse(buf: &[u8]) -> Result<ControlHeader>;
      pub fn subtype(&self) -> u8;
  }
  ```
- `management_ie_offset` returns where the IEs start in the frame *body*,
  after the subtype-specific fixed fields:
  - beacon (8) and probe response (5): 12 bytes (timestamp, beacon interval,
    capability info),
  - probe request (4): 0 bytes,
  - association request (0): 4 bytes (capability info, listen interval),
  - reassociation request (2): 10 bytes (the same, plus the current access
    point address),
  - association response (1) and reassociation response (3): 6 bytes
    (capability info, status code, association ID),
  - authentication (11): 6 bytes (authentication algorithm, sequence number,
    status code),
  - deauthentication (12) and disassociation (10): 2 bytes (reason code),
  - anything else: `None`.

## `ie.rs`

```rust
/// One information element: its ID and its body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ie<'a> {
    pub id: u8,
    pub body: &'a [u8],
}

/// Walk the elements in `buf`.
pub fn parse_ies(buf: &[u8]) -> Result<Vec<Ie<'_>>>;

/// The SSID of an access point.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ssid {
    /// The raw SSID bytes. Empty means the network hides its name.
    pub bytes: Vec<u8>,
    /// True when the SSID element is empty.
    pub hidden: bool,
}

/// An authentication and key management suite.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Akm {
    /// Pre-shared key (WPA2-Personal), selector `00:0f:ac:2`.
    Psk,
    /// Pre-shared key with SHA-256, selector `00:0f:ac:6`.
    PskSha256,
    /// 802.1X / EAP, selector `00:0f:ac:1`.
    Eap,
    /// 802.1X with SHA-256, selector `00:0f:ac:5`.
    EapSha256,
    /// Fast transition over 802.1X, selector `00:0f:ac:3`.
    FtEap,
    /// Fast transition over PSK, selector `00:0f:ac:4`.
    FtPsk,
    /// Simultaneous Authentication of Equals (WPA3-Personal), `00:0f:ac:8`.
    Sae,
    /// Fast transition over SAE, selector `00:0f:ac:9`.
    FtSae,
    /// SAE with a group-dependent hash (Hash-to-Element), `00:0f:ac:24`.
    SaeH2e,
    /// Fast transition over SAE-H2E, selector `00:0f:ac:25`.
    FtSaeH2e,
    /// Opportunistic Wireless Encryption, selector `00:0f:ac:18`.
    Owe,
    /// A selector that is not in the table.
    Other([u8; 4]),
}

/// A cipher suite.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Cipher {
    /// WEP with a 40-bit key, selector `00:0f:ac:1`.
    Wep40,
    /// WEP with a 104-bit key, selector `00:0f:ac:5`.
    Wep104,
    /// TKIP, selector `00:0f:ac:2`.
    Tkip,
    /// CCMP with a 128-bit key, selector `00:0f:ac:4`.
    Ccmp,
    /// CCMP with a 256-bit key, selector `00:0f:ac:10`.
    Ccmp256,
    /// GCMP with a 128-bit key, selector `00:0f:ac:8`.
    Gcmp,
    /// GCMP with a 256-bit key, selector `00:0f:ac:9`.
    Gcmp256,
    /// Broadcast/multicast integrity protocol, selector `00:0f:ac:6`.
    Bip,
    /// Broadcast/multicast integrity protocol, CMAC-128, `00:0f:ac:12`.
    BipCmac,
    /// A selector that is not in the table.
    Other([u8; 4]),
}

/// What the elements say about the security of a network.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Security {
    /// True for an RSN element (WPA2 and later), false for a vendor WPA
    /// element (WPA1).
    pub rsn: bool,
    pub akm: Vec<Akm>,
    pub pairwise: Vec<Cipher>,
    pub group: Option<Cipher>,
    /// The RSN capabilities field, when present.
    pub rsn_capabilities: Option<u16>,
}

/// A vendor element, reduced to its OUI and type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VendorOui {
    pub oui: [u8; 3],
    pub element_type: u8,
}

/// WPS information, presence and version only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WpsInfo {
    pub version: u8,
}

/// Everything the daemon keeps from a frame's elements.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ElementSummary {
    pub ssid: Option<Ssid>,
    pub security: Option<Security>,
    pub ht: bool,
    pub vht: bool,
    pub he: bool,
    pub vendors: Vec<VendorOui>,
    pub wps: Option<WpsInfo>,
}

/// Summarise a list of elements.
pub fn summarize(ies: &[Ie<'_>]) -> ElementSummary;
```

Notes:
- An element is a one-byte ID, a one-byte length and that many bytes. A
  length that runs past the end of the buffer is an error. A zero-length
  element is legal.
- Element IDs: SSID 0, supported rates 1, DS parameter 3, HT capabilities 45,
  WPS vendor 221 (OUI 00:50:F2, type 6), vendor specific 221, WPA vendor
  element 221 (OUI 00:50:F2, type 1), RSN 48, HT operation 61, VHT
  capabilities 191, VHT operation 192, HE capabilities 255 with extended ID
  35, HE operation 255 with extended ID 36.
- A WPA1 vendor element has OUI `00:50:F2` and type 1; a WPS element has the
  same OUI and type 6. Everything else with ID 221 is a vendor element.
- The RSN element is: version (u16), group cipher (4 bytes), pairwise count
  (u16), pairwise suites (4 bytes each), AKM count (u16), AKM suites (4 bytes
  each), RSN capabilities (u16), then optional PMKID and group management
  cipher lists. Stop where the element ends.
- The WPA1 vendor element holds a similar structure, offset by the 6-byte
  vendor header.
- The suite selectors come from the OUI `00:0F:AC`, with the type numbers
  in the tables below. Quote the reference in a comment and map anything else
  to `Other`.

  **AKM suite types** (IEEE 802.11 Table 12-6, and the Wi-Fi Alliance WPA3
  specification v3.5, which maps them to `wpa_supplicant`'s `key_mgmt`):

  | Selector | Name | Meaning |
  |---|---|---|
  | `00:0f:ac:1` | 802.1X (EAP) | enterprise |
  | `00:0f:ac:2` | PSK | WPA2-Personal |
  | `00:0f:ac:3` | FT over 802.1X | WPA3 enterprise |
  | `00:0f:ac:4` | FT over PSK | WPA2 |
  | `00:0f:ac:5` | 802.1X SHA-256 | WPA3 enterprise only mode |
  | `00:0f:ac:6` | PSK SHA-256 | WPA2 |
  | `00:0f:ac:8` | **SAE** | **WPA3-Personal** |
  | `00:0f:ac:9` | FT over SAE | WPA3 with 802.11r |
  | `00:0f:ac:12` | 802.1X SHA-384 | Suite B 192-bit |
  | `00:0f:ac:18` | OWE | Enhanced Open |
  | `00:0f:ac:24` | SAE with group-dependent hash (SAE-H2E) | WPA3, Wi-Fi 7 |
  | `00:0f:ac:25` | FT over SAE-H2E | WPA3 with 802.11r |

  A WPA3-Personal network in transition mode advertises **both** PSK
  (`:2`) and SAE (`:8`); a WPA3-Personal network advertises SAE (`:8`) only.
  Getting this wrong would label a WPA3 network as WPA2, so keep the two
  apart.

  **Cipher suite types** (IEEE 802.11 Table 12-7):

  | Selector | Name |
  |---|---|
  | `00:0f:ac:1` | WEP-40 |
  | `00:0f:ac:2` | TKIP |
  | `00:0f:ac:4` | CCMP-128 |
  | `00:0f:ac:5` | WEP-104 |
  | `00:0f:ac:6` | BIP |
  | `00:0f:ac:8` | GCMP-128 |
  | `00:0f:ac:9` | GCMP-256 |
  | `00:0f:ac:10` | CCMP-256 |
  | `00:0f:ac:12` | BIP-CMAC-128 |

## `frame.rs`

```rust
/// How a data frame is addressed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DataMapping {
    /// The station that sent or received the frame.
    pub client: Option<[u8; 6]>,
    /// The access point the frame belongs to.
    pub bssid: Option<[u8; 6]>,
    pub to_ds: bool,
    pub from_ds: bool,
}

/// What the body of a data frame is, without keeping any of it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyKind {
    /// Ordinary data.
    Data,
    /// An EAPOL frame: counted, never stored.
    Eapol,
    /// A frame the daemon does not classify.
    Other,
}

/// Map a data frame's addresses to a client and a BSSID.
pub fn map_data_addresses(header: &MacHeader) -> DataMapping;

/// Classify the body of a data frame by looking at its first bytes only.
pub fn classify_body(body: &[u8]) -> BodyKind;
```

Notes:
- **Address rules for data frames**, from IEEE 802.11-2020 Table 9-30 (the
  same table the Linux kernel documents in `include/linux/ieee80211.h`):

  | To DS | From DS | addr1 | addr2 | addr3 | addr4 |
  |---|---|---|---|---|---|
  | 0 | 0 | DA/RA | SA/TA | **BSSID** | absent |
  | 0 | 1 | DA/RA | **BSSID**/TA | SA | absent |
  | 1 | 0 | **BSSID**/RA | SA/TA | DA | absent |
  | 1 | 1 | RA | TA | DA | **SA** |

  So the client (the station) is:
  - `ToDS = 0, FromDS = 0`: addr2 (the source address), BSSID is addr3,
  - `ToDS = 1, FromDS = 0`: addr2 (the source address), BSSID is addr1,
  - `ToDS = 0, FromDS = 1`: addr1 (the destination address, i.e. the
    station the frame is addressed to), BSSID is addr2,
  - `ToDS = 1, FromDS = 1`: addr4 (the source address of the original
    station); the BSSID is not in the frame, so leave it `None` rather than
    guess — the transmitter address addr2 is the bridge that relayed it.

  Where the address that would name the station is a broadcast or multicast
  address, the client is `None`: it does not name one station.
- `classify_body` looks at the LLC/SNAP header: AA AA 03 00 00 00 followed by
  an EtherType. EtherType `0x888E` means EAPOL. Do not read past the
  EtherType, and do not keep any of it.
- The dispatcher in this file classifies a frame as management, control or
  data, and calls into the other modules. It never copies a payload. Control
  frames use `ControlHeader`, not `MacHeader`.

## Proving no retention

Each task that touches frame bodies adds a test like this: build a frame
whose payload is a distinctive ASCII marker, parse it, and assert that the
marker does not appear anywhere in the parsed result. Use
`format!("{result:?}")` and check the marker is absent. A `Debug` that prints
the payload would fail the test, which is the point.

## Proving no panic

Each task adds a test that feeds pseudo-random bytes to the parser and
asserts that it returns either `Ok` or `Err` without panicking. Use a small
deterministic LCG in the test so it is reproducible, and keep the length
small (a few hundred bytes). turns this into a real fuzz target.
