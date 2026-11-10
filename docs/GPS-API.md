# gpsd client contract

The contract for the gpsd client. The daemon tags sightings with a position
when gpsd has one; the schema's `sightings` table has `lat`, `lon`, `alt` and
`fix` columns for exactly that.

## Where it lives

`crates/od3sa-gps`, its own crate: the client is useful on its own and the
daemon is the only thing that has to wire it up.

## What gpsd is

gpsd listens on a socket — by default `127.0.0.1:2947` — and speaks a JSON
protocol. The device has gpsd 3.25 installed and running (`gpsd`,
`gpsd-speed` in the init scripts).

**A request is introduced by `?`.** This is the part that is easy to get
wrong: gpsd 3.x does *not* accept a bare JSON object as a request. A JSON
object is what gpsd *answers* with; a request is a command, and the command is
framed with `?` and either terminated with `;` or given a JSON object as an
argument:

| Form | Example |
|---|---|
| classic | `?WATCH;` or `?POLL;` |
| JSON argument | `?WATCH={"enable":true,"json":true}` |

Sending a bare `{"class":"POLL"}` gets `{"class":"ERROR","message":"Unrecognized
request ..."}` — gpsd does not parse an unprefixed object as a request.

The two requests that matter here:

- `?WATCH={"enable":true,"json":true}` — gpsd answers with the position and
  then sends a new object every time it changes:

  ```json
  {"class":"WATCH","device":"/dev/ttyS0","time":"2026-11-05T09:00:00Z","mode":3,"lat":52.5200,"lon":13.4050,"alt":34.0,"speed":0.0,"track":0.0,"status":1}
  ```

- `?POLL;` — gpsd answers with the current position of each device it is
  tracking. **The position is in a `tpv` array**, one entry per device:

  ```json
  {"class":"POLL","time":"2026-11-05T09:00:00Z","active":1,"tpv":[{"class":"TPV","time":"2026-11-05T09:00:00Z","mode":3,"lat":52.5200,"lon":13.4050,"alt":34.0,"speed":0.0,"track":0.0,"status":1}],"sky":[]}
  ```

  A `WATCH` object carries the position fields at the top level, while a
  `POLL` object carries them inside `tpv[]`. The client has to read both
  shapes. A device has to be watched before it can be polled.

Reference: the `gpsd_json(5)` manual page.

`mode` is the fix mode: 1 = no fix, 2 = 2D fix, 3 = 3D fix. `status` is 1
when the fix is good.

## The API

```rust
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

/// The gpsd client.
pub struct GpsdClient { /* the connection and the last fix */ }

impl GpsdClient {
    /// A client that will connect to `127.0.0.1:2947`.
    pub fn new() -> GpsdClient;

    /// A client that will connect to the given address.
    pub fn with_address(address: &str) -> GpsdClient;

    /// Connect and start watching.
    ///
    /// Failing to connect is **not** an error: gpsd may not be running, and
    /// the daemon has to work without a position.
    pub fn connect(&mut self) -> Result<(), GpsError>;

    /// Read whatever gpsd has sent, and update the last fix.
    ///
    /// Returns the number of messages read. Returns zero when nothing has
    /// arrived yet.
    pub fn poll(&mut self) -> Result<usize, GpsError>;

    /// The last fix, if there is one.
    pub fn last_fix(&self) -> Option<Fix>;

    /// Whether the client is connected.
    pub fn is_connected(&self) -> bool;

    /// Disconnect.
    pub fn disconnect(&mut self);
}
```

## The rules the client follows

- **gpsd being absent is normal.** The daemon runs on a Pager that may have no
  GPS, and gpsd may not be running. A failed connection is not an error that
  stops the daemon: `connect` returns an error the caller may ignore, and
  `last_fix` is `None` until a fix arrives.
- **A disconnected gpsd is reconnected.** After a connection error, the next
  `connect` tries again. The daemon calls `poll` on a timer and reconnects
  when it fails.
- **A message that is not JSON, or is JSON of an unexpected shape, is
  ignored** — not an error. gpsd also sends classes the daemon does not care
  about (`DEVICES`, `VERSION`, and so on).
- **Only a real fix is kept.** A `POLL` or `WATCH` object with `mode` 1 (no
  fix) does not replace a good fix with a bad one.
- **The last known position is kept** when gpsd goes quiet: a sighting may be
  tagged with a position that is a minute old, which is better than no
  position.
- **Nothing here touches a radio.** The client only reads a socket.

## The tests

The acceptance says "tested against a fake gpsd". So the tests start a TCP
listener on a loopback port that speaks the gpsd JSON protocol, and point the
client at it.

1. A fake gpsd that answers a `POLL` with a position: the client keeps the
   fix, with the right latitude, longitude, altitude, mode and time.
2. A `WATCH` object updates the fix.
3. **A message that is not JSON is ignored**, and the client carries on.
4. **A JSON message of an unexpected shape is ignored** — a `DEVICES` object,
   a `POLL` with no position, a `WATCH` for a device with no fix.
5. **A fix with mode 1 does not replace a good fix.**
6. **A gpsd that is not there is not a disaster:** connecting to a port with
   nothing on it returns an error and leaves the client disconnected, with no
   fix.
7. **A connection that drops mid-way is noticed**, and the client reports
   itself disconnected.
8. The time in a `POLL` object is parsed into unix epoch milliseconds.

The fake gpsd is a small helper in the test module: a `TcpListener` on port 0
(the operating system picks a free one), a thread that reads a line and
answers with the lines the test wants.

## Constraints

- The only dependency is `serde_json` (MIT OR Apache-2.0).
- No `unwrap` or `expect` outside the tests.
- No real coordinates: the tests use made-up ones, and the fake gpsd must
  not report a real position.
