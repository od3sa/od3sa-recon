# Event bus contract

The contract for the NDJSON event bus. It extends `docs/api/events.md`, which
lists the topics; this document gives the wire format, the API and the
backpressure policy.

## Where it lives

`crates/od3sa-events`, its own crate, because the plugin host
depends on it and so do the plugins' own code.

## The wire

The bus is a Unix stream socket at `/tmp/od3sa-recon/events.sock`. **The daemon
is the server and the plugins are the clients** — a plugin connects, subscribes,
and reads events.

A subscriber connects and sends one line:

```json
{"op":"subscribe","token":"<token>","topics":["ap.*","alert.raised"]}
```

The bus replies with one line:

```json
{"type":"bus.ready","data":{"topics":["ap.*","alert.raised"]}}
```

and then every event it is subscribed to, one per line:

```json
{"v":0,"type":"ap.new","ts_ms":1762300000000,"seq":42,"data":{"bssid":"00:11:22:33:44:01","ssid":"example-ssid","channel":36,"freq_mhz":5180,"security":"WPA2-PSK","wps":false,"rssi":-61}}
```

A subscriber may send a second subscribe line to change its topics; the bus
replies with another `bus.ready`.

## The topics

From `docs/api/events.md`:

| Topic | `data` |
|---|---|
| `device.new` | `{mac, kind, oui, randomized, rssi, channel, source}` |
| `device.updated` | `{mac, changed:[fields], last_seen_ms, rssi}` |
| `ap.new` | `{bssid, ssid, channel, freq_mhz, security, wps, rssi}` |
| `client.assoc` | `{client, bssid, rssi}` |
| `probe.seen` | `{client, ssid, rssi}` |
| `ble.seen` | `{addr, name, manufacturer_id, rssi, source}` |
| `alert.raised` | `{id, rule, severity, mac, summary}` |
| `source.status` | `{name, kind, status, frames, errors}` |

Plus the bus's own: `bus.dropped` (the subscriber's queue overflowed) and
`bus.ready` (the subscription was accepted).

A topic pattern is `prefix.*` for a prefix, or an exact name. A subscriber
that asks for `ap.*` gets `ap.new` and any other `ap.` topic.

## The API

```rust
/// One event on the bus.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event {
    /// The API version. Zero for now.
    pub version: u32,
    /// The topic.
    pub topic: String,
    /// When it happened, in unix epoch milliseconds.
    pub ts_ms: i64,
    /// A sequence number, increasing over the life of the bus.
    pub seq: u64,
    /// The payload.
    pub data: serde_json::Value,
}

/// A topic pattern: an exact name, or a prefix with a trailing `.*`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TopicPattern {
    /// Exactly this topic.
    Exact(String),
    /// Every topic with this prefix.
    Prefix(String),
}

impl TopicPattern {
    /// Parse a pattern, which is either `name` or `prefix.*`.
    pub fn parse(pattern: &str) -> Result<TopicPattern, EventError>;

    /// Whether the pattern matches a topic.
    pub fn matches(&self, topic: &str) -> bool;
}

/// The event bus.
pub struct EventBus { /* the subscribers and the sequence number */ }

impl EventBus {
    /// A bus with a bounded queue of `queue_len` events per subscriber.
    pub fn new(queue_len: usize) -> EventBus;

    /// The socket to listen on.
    pub fn bind(path: &Path) -> Result<EventBus, EventError>;

    /// The path the bus is listening on.
    pub fn socket_path(&self) -> &Path;

    /// Serve until `stop` is called. One thread per connection.
    pub fn serve(&self) -> Result<(), EventError>;

    /// Stop serving and close the socket.
    pub fn stop(&self);

    /// Publish an event. It goes to every subscriber whose patterns match.
    ///
    /// Returns how many subscribers it reached.
    pub fn publish(&self, event: &Event) -> usize;

    /// The sequence number the next published event will carry.
    pub fn next_seq(&self) -> u64;
}
```

## The backpressure policy

**A slow subscriber must never slow the daemon down, and must never make it
grow without bound.** So:

- each subscriber has a **bounded queue** of `queue_len` events (the default is
  256);
- when a subscriber's queue is full, the **newest** event is dropped and the
  subscriber is told: the bus sends it `{"type":"bus.dropped","data":{"n":N}}`
  where `N` is the number of events dropped since the last notice;
- the publish path never blocks. It takes the subscriber's lock, and if the
  queue is full it drops rather than waits;
- a subscriber that cannot keep up therefore sees gaps, and knows it, rather
  than stalling the collector.

A dropped event is counted per subscriber, and the count is reported in the
`bus.dropped` event. The daemon's own statistics should count them too.

## The token

A subscriber's subscribe line carries a token, exactly as the query socket
does. The bus checks it **before** the topics are looked at, so a subscriber
that cannot authenticate learns nothing about what is happening on the bus.

The token is the same one the daemon holds. The plugin host gives each
plugin its own token, and the bus then filters what each plugin may see —
that is where the per-plugin topic allowlists from `docs/PLUGINS.md` come
in.

## The rules the bus follows

- **Every line is one JSON object.** A request or an event, never two on one
  line and never half an object.
- **A malformed subscribe line does not kill the connection.** The bus replies
  with an error line and keeps the connection open.
- **A subscriber that disconnects is forgotten.** Its queue goes with it.
- **The bus never blocks the collector.** Publishing is a bounded operation.
- **The sequence number increases over the life of the bus** and is the same
  for every subscriber, so two subscribers can tell that they saw the same
  event.

## Tests

1. A subscriber that subscribes to `ap.*` receives an `ap.new` event and one
   line per event.
2. A subscriber that subscribes to `alert.raised` does **not** receive
   `ap.new`.
3. **The queue is bounded:** a subscriber that never reads, with a queue of
   `n`, has at most `n` events queued, and the events after that are dropped
   and counted.
4. **A dropped event is reported:** the subscriber eventually receives
   `bus.dropped` with the count.
5. **Publishing never blocks:** publishing to a subscriber whose queue is full
   returns promptly and does not wait for the subscriber.
6. A malformed subscribe line gets an error and the connection stays open.
7. A token that is wrong is refused, and the refusal does not say which topics
   exist.
8. A subscriber that disconnects is forgotten, and the next publish reaches
   the others.
9. The sequence number increases and is the same for every subscriber.

## Constraints

- The only dependency is `serde_json` (MIT OR Apache-2.0).
- No `unwrap` or `expect` outside the tests.
- No real data: the tests use the synthetic address family and `example-*`
  names.
- Nothing that touches a radio. The bus carries information about frames;
  it does not make them.
