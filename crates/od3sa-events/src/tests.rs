//! Tests for the NDJSON event bus.
//!
//! The data here is synthetic: the `00:11:22:33:44:xx` MAC family and
//! `example-ssid`, as the rest of the project uses. No real capture, no
//! real device, no real network.
//!
//! The socket paths are under the temporary directory and are named so
//! that two tests cannot fight over one.

use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::{Value, json};

use super::*;

/// The token the tests use.
const TOKEN: &str = "test-token-0123456789";

/// A counter that keeps the socket paths of parallel tests apart.
static COUNTER: AtomicUsize = AtomicUsize::new(0);

/// How long a test waits for a line that should not come.
const QUIET: Duration = Duration::from_millis(400);

/// How long a test waits for a line that should come.
const PATIENT: Duration = Duration::from_secs(5);

/// A socket path that no other test uses.
fn temp_socket_path() -> PathBuf {
    let number = COUNTER.fetch_add(1, Ordering::SeqCst);
    let mut path = std::env::temp_dir();
    path.push(format!(
        "od3sa-events-test-{}-{number}.sock",
        std::process::id()
    ));
    let _ = fs::remove_file(&path);
    path
}

/// A bus on a socket of its own, serving in a thread of its own.
struct Fixture {
    bus: EventBus,
    path: PathBuf,
    worker: Option<thread::JoinHandle<()>>,
}

impl Fixture {
    /// Start a bus with a queue of `queue_len` events per subscriber.
    fn start(queue_len: usize) -> Fixture {
        let path = temp_socket_path();
        let bus = EventBus::bind_with(&path, queue_len).expect("the socket binds");
        bus.set_token(TOKEN);

        let worker_bus = bus.clone();
        let worker = thread::spawn(move || {
            let _ = worker_bus.serve();
        });

        Fixture {
            bus,
            path,
            worker: Some(worker),
        }
    }

    /// A bus with the default queue length.
    fn start_default() -> Fixture {
        Fixture::start(DEFAULT_QUEUE_LEN)
    }

    /// Connect a client to the bus.
    fn connect(&self) -> Client {
        Client::connect(&self.path)
    }

    /// Connect a client and subscribe it to `topics`.
    fn subscribe(&self, topics: &[&str]) -> Client {
        let mut client = self.connect();
        let ready = client.subscribe(topics);
        assert_eq!(ready["type"], "bus.ready");
        client
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.bus.stop();
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
        let _ = fs::remove_file(&self.path);
    }
}

/// One client on the other end of the socket.
struct Client {
    writer: UnixStream,
    reader: BufReader<UnixStream>,
}

impl Client {
    /// Connect to the socket at `path`.
    fn connect(path: &PathBuf) -> Client {
        let writer = UnixStream::connect(path).expect("the socket connects");
        writer
            .set_read_timeout(Some(PATIENT))
            .expect("the read timeout is set");
        let reader = BufReader::new(writer.try_clone().expect("the socket clones"));
        Client { writer, reader }
    }

    /// Send one raw line.
    fn send(&mut self, line: &str) {
        self.writer
            .write_all(line.as_bytes())
            .expect("the line is written");
        self.writer
            .write_all(b"\n")
            .expect("the newline is written");
        self.writer.flush().expect("the line is flushed");
    }

    /// Subscribe to `topics` with the bus's own token.
    fn subscribe(&mut self, topics: &[&str]) -> Value {
        self.subscribe_with(TOKEN, topics)
    }

    /// Subscribe to `topics` with the given token, and return the answer.
    fn subscribe_with(&mut self, token: &str, topics: &[&str]) -> Value {
        self.send(
            &json!({
                "op": "subscribe",
                "token": token,
                "topics": topics,
            })
            .to_string(),
        );
        self.next_json().expect("the bus answers")
    }

    /// The next line, or `None` when nothing comes in time.
    fn next_line(&mut self) -> Option<String> {
        let mut line = String::new();
        match self.reader.read_line(&mut line) {
            Ok(0) => None,
            Ok(_) => Some(line.trim_end().to_string()),
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                None
            }
            Err(error) => panic!("the line is read: {error}"),
        }
    }

    /// The next line, parsed as JSON.
    fn next_json(&mut self) -> Option<Value> {
        let line = self.next_line()?;
        Some(
            serde_json::from_str(&line)
                .unwrap_or_else(|error| panic!("the line is JSON ({line}): {error}")),
        )
    }

    /// Wait a little and hope that nothing comes.
    fn expect_silence(&mut self) {
        self.reader
            .get_ref()
            .set_read_timeout(Some(QUIET))
            .expect("the read timeout is set");
        if let Some(line) = self.next_line() {
            panic!("the subscriber was sent {line}");
        }
        self.reader
            .get_ref()
            .set_read_timeout(Some(PATIENT))
            .expect("the read timeout is set");
    }
}

/// An `ap.new` event with synthetic data.
fn ap_event() -> Event {
    Event {
        version: 0,
        topic: "ap.new".to_string(),
        ts_ms: 1_762_300_000_000,
        seq: 0,
        data: json!({
            "bssid": "00:11:22:33:44:01",
            "ssid": "example-ssid",
            "channel": 36,
            "freq_mhz": 5180,
            "security": "WPA2-PSK",
            "wps": false,
            "rssi": -61,
        }),
    }
}

/// An `alert.raised` event with synthetic data.
fn alert_event() -> Event {
    Event {
        version: 0,
        topic: "alert.raised".to_string(),
        ts_ms: 1_762_300_000_001,
        seq: 0,
        data: json!({
            "id": "example-alert-1",
            "rule": "example-rule",
            "severity": "low",
            "mac": "00:11:22:33:44:02",
            "summary": "example summary",
        }),
    }
}

/// An `ap.new` event whose payload is `size` bytes of filler.
///
/// A big payload fills the socket buffer, so that a subscriber that never
/// reads makes the queue overflow for sure.
fn big_ap_event(size: usize) -> Event {
    let mut event = ap_event();
    event.data = json!({
        "bssid": "00:11:22:33:44:01",
        "ssid": "example-ssid",
        "filler": "x".repeat(size),
    });
    event
}

/// Test 1: a subscriber of `ap.*` receives the `ap.new` events, one line
/// each.
#[test]
fn a_subscriber_of_a_prefix_receives_the_event() {
    let fixture = Fixture::start_default();
    let mut client = fixture.subscribe(&["ap.*"]);

    assert_eq!(fixture.bus.publish(&ap_event()), 1);

    let line = client.next_json().expect("the event arrives");
    assert_eq!(line["v"], 0);
    assert_eq!(line["type"], "ap.new");
    assert_eq!(line["ts_ms"], 1_762_300_000_000i64);
    assert_eq!(line["data"]["bssid"], "00:11:22:33:44:01");
    assert_eq!(line["data"]["ssid"], "example-ssid");
    assert_eq!(line["data"]["channel"], 36);
    assert_eq!(line["data"]["rssi"], -61);

    // One line per event, and nothing else.
    assert_eq!(fixture.bus.publish(&ap_event()), 1);
    let second = client.next_json().expect("the second event arrives");
    assert_eq!(second["type"], "ap.new");
    assert_ne!(second["seq"], line["seq"]);
}

/// Test 2: a subscriber of one exact topic does not receive another one.
#[test]
fn a_subscriber_of_an_exact_topic_receives_only_that_topic() {
    let fixture = Fixture::start_default();
    let mut client = fixture.subscribe(&["alert.raised"]);

    assert_eq!(fixture.bus.publish(&ap_event()), 0);
    client.expect_silence();

    // The topic it did ask for still arrives.
    assert_eq!(fixture.bus.publish(&alert_event()), 1);
    let line = client.next_json().expect("the alert arrives");
    assert_eq!(line["type"], "alert.raised");
}

/// Test 3: the queue is bounded. A subscriber that never reads keeps at
/// most `queue_len` events, and the rest are dropped and counted.
#[test]
fn the_queue_of_a_slow_subscriber_is_bounded() {
    let queue_len = 4;
    let fixture = Fixture::start(queue_len);

    // The subscriber never reads, so its socket buffer fills up and the
    // queue overflows.
    let mut client = fixture.connect();
    client.subscribe(&["ap.*"]);

    for _ in 0..100 {
        fixture.bus.publish(&big_ap_event(64 * 1024));
    }

    let subscribers = fixture.bus.subscribers();
    assert_eq!(subscribers.len(), 1);
    assert!(
        subscribers[0].pending() <= queue_len,
        "the queue holds {} events, the bound is {queue_len}",
        subscribers[0].pending()
    );
    assert!(
        subscribers[0].dropped() > 0,
        "the events past the bound are counted"
    );
    assert_eq!(subscribers[0].dropped(), fixture.bus.dropped_count());
}

/// Test 4: a dropped event is reported to the subscriber with the count.
#[test]
fn a_dropped_event_is_reported_to_the_subscriber() {
    let fixture = Fixture::start(2);

    let mut client = fixture.connect();
    client.subscribe(&["ap.*"]);

    for _ in 0..100 {
        fixture.bus.publish(&big_ap_event(64 * 1024));
    }
    assert!(fixture.bus.dropped_count() > 0);

    // The subscriber reads what it can, and the notice follows.
    let mut notice = None;
    for _ in 0..200 {
        let Some(line) = client.next_json() else {
            break;
        };
        if line["type"] == "bus.dropped" {
            notice = Some(line);
            break;
        }
    }

    let notice = notice.expect("the subscriber is told about the drops");
    assert_eq!(notice["type"], "bus.dropped");
    assert!(
        notice["data"]["n"].as_u64().expect("a count") > 0,
        "the notice carries the count of the dropped events"
    );
}

/// Test 5: publishing never blocks. A subscriber with a full queue does
/// not hold the publisher up.
#[test]
fn publishing_never_blocks() {
    let fixture = Fixture::start(2);

    let mut client = fixture.connect();
    client.subscribe(&["ap.*"]);

    // Fill the queue and the socket buffer.
    for _ in 0..100 {
        fixture.bus.publish(&big_ap_event(64 * 1024));
    }
    assert!(fixture.bus.dropped_count() > 0);

    let start = Instant::now();
    for _ in 0..200 {
        fixture.bus.publish(&big_ap_event(1024));
    }
    let elapsed = start.elapsed();

    assert!(
        elapsed < Duration::from_secs(1),
        "publishing took {elapsed:?}, it must not wait for the subscriber"
    );
}

/// Test 6: a malformed subscribe line gets an error, and the connection
/// stays open.
#[test]
fn a_malformed_request_keeps_the_connection_open() {
    let fixture = Fixture::start_default();
    let mut client = fixture.connect();

    client.send("this is not json");
    let error = client.next_json().expect("the bus answers");
    assert_eq!(error["type"], "bus.error");

    // The connection is still open: a good request is answered.
    let ready = client.subscribe(&["ap.*"]);
    assert_eq!(ready["type"], "bus.ready");

    assert_eq!(fixture.bus.publish(&ap_event()), 1);
    let line = client.next_json().expect("the event arrives");
    assert_eq!(line["type"], "ap.new");
}

/// A second subscribe line changes the topics of a subscriber, and the
/// bus answers with another `bus.ready`.
#[test]
fn a_second_subscribe_changes_the_topics() {
    let fixture = Fixture::start_default();
    let mut client = fixture.subscribe(&["ap.*"]);

    // The subscriber asks for another set of topics.
    client.send(
        &json!({
            "op": "subscribe",
            "token": TOKEN,
            "topics": ["alert.raised"],
        })
        .to_string(),
    );
    let ready = client.next_json().expect("the bus answers");
    assert_eq!(ready["type"], "bus.ready");
    assert_eq!(ready["data"]["topics"][0], "alert.raised");

    // The new topics are the ones that count now.
    assert_eq!(fixture.bus.publish(&ap_event()), 0);
    client.expect_silence();

    assert_eq!(fixture.bus.publish(&alert_event()), 1);
    let line = client.next_json().expect("the alert arrives");
    assert_eq!(line["type"], "alert.raised");
}

/// Test 7: a wrong token is refused, and the refusal does not say which
/// topics exist.
#[test]
fn a_wrong_token_is_refused() {
    let fixture = Fixture::start_default();
    let mut client = fixture.connect();

    client.send(
        &json!({
            "op": "subscribe",
            "token": "not-the-token",
            "topics": ["ap.*", "alert.raised"],
        })
        .to_string(),
    );

    let error = client.next_json().expect("the bus answers");
    assert_eq!(error["type"], "bus.error");
    let text = error.to_string();
    assert!(
        !text.contains("ap.") && !text.contains("alert"),
        "the refusal must not talk about the topics: {text}"
    );

    // Nothing is delivered to a subscriber that did not authenticate.
    fixture.bus.publish(&ap_event());
    client.expect_silence();

    // The right token works on the same connection.
    let ready = client.subscribe(&["ap.*"]);
    assert_eq!(ready["type"], "bus.ready");
    assert_eq!(fixture.bus.publish(&ap_event()), 1);
    let line = client.next_json().expect("the event arrives");
    assert_eq!(line["type"], "ap.new");
}

/// Test 8: a subscriber that disconnects is forgotten, and the next
/// publish reaches the others.
#[test]
fn a_subscriber_that_disconnects_is_forgotten() {
    let fixture = Fixture::start_default();

    let leaving = fixture.subscribe(&["ap.*"]);
    let mut staying = fixture.subscribe(&["ap.*"]);
    assert_eq!(fixture.bus.subscriber_count(), 2);

    // The first subscriber goes away.
    drop(leaving);
    let deadline = Instant::now() + PATIENT;
    while fixture.bus.subscriber_count() > 1 && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(fixture.bus.subscriber_count(), 1);

    // The publish reaches the one that stayed.
    assert_eq!(fixture.bus.publish(&ap_event()), 1);
    let line = staying.next_json().expect("the event arrives");
    assert_eq!(line["type"], "ap.new");
}

/// Test 9: the sequence number grows, and it is the same for every
/// subscriber.
#[test]
fn the_sequence_number_grows_and_is_the_same_for_everyone() {
    let fixture = Fixture::start_default();
    let mut first = fixture.subscribe(&["ap.*"]);
    let mut second = fixture.subscribe(&["ap.*"]);

    assert_eq!(fixture.bus.publish(&ap_event()), 2);
    assert_eq!(fixture.bus.publish(&ap_event()), 2);

    let first_lines: Vec<Value> = (0..2)
        .map(|_| first.next_json().expect("the event arrives"))
        .collect();
    let second_lines: Vec<Value> = (0..2)
        .map(|_| second.next_json().expect("the event arrives"))
        .collect();

    for (left, right) in first_lines.iter().zip(second_lines.iter()) {
        assert_eq!(left["seq"], right["seq"]);
    }

    let first_seq = first_lines[0]["seq"].as_u64().expect("a sequence number");
    let second_seq = first_lines[1]["seq"].as_u64().expect("a sequence number");
    assert!(second_seq > first_seq, "the sequence number grows");
}

/// The bus numbers the events itself, and the number it hands out is the
/// one the next event will carry.
#[test]
fn the_bus_numbers_the_events() {
    let fixture = Fixture::start_default();

    let before = fixture.bus.next_seq();
    fixture.bus.publish(&ap_event());
    assert_eq!(fixture.bus.next_seq(), before + 1);
}

/// A pattern matches the topics it should and no others.
#[test]
fn a_pattern_matches_the_right_topics() {
    let prefix = TopicPattern::parse("ap.*").expect("the pattern is good");
    assert!(prefix.matches("ap.new"));
    assert!(prefix.matches("ap.updated"));
    assert!(!prefix.matches("alert.raised"));
    assert!(!prefix.matches("apple.new"));

    let exact = TopicPattern::parse("alert.raised").expect("the pattern is good");
    assert!(exact.matches("alert.raised"));
    assert!(!exact.matches("alert.cleared"));
    assert!(!exact.matches("alert.raised.extra"));

    assert!(TopicPattern::parse("").is_err());
    assert!(TopicPattern::parse("ap.*.new").is_err());
    assert!(TopicPattern::parse("*").is_err());
}

/// Several publishers and several subscribers at once: nothing deadlocks,
/// and every subscriber sees the events it asked for.
#[test]
fn several_publishers_and_subscribers_at_once() {
    // A queue big enough that nothing is dropped, so that the test is
    // about delivery and not about the backpressure policy.
    let fixture = Fixture::start(1024);

    let mut clients = Vec::new();
    for _ in 0..3 {
        clients.push(fixture.subscribe(&["ap.*"]));
    }

    let bus = fixture.bus.clone();
    let publishers: Vec<_> = (0..4)
        .map(|worker| {
            let bus = bus.clone();
            thread::spawn(move || {
                for index in 0..50 {
                    let mut event = ap_event();
                    event.data = json!({
                        "bssid": "00:11:22:33:44:01",
                        "ssid": "example-ssid",
                        "worker": worker,
                        "index": index,
                    });
                    bus.publish(&event);
                }
            })
        })
        .collect();

    for publisher in publishers {
        publisher.join().expect("the publisher finishes");
    }

    // Every subscriber got every event.
    for client in &mut clients {
        let mut seen = 0;
        while seen < 200 {
            let Some(line) = client.next_json() else {
                break;
            };
            if line["type"] == "ap.new" {
                seen += 1;
            }
        }
        assert_eq!(seen, 200, "every event arrives");
    }
    assert_eq!(fixture.bus.dropped_count(), 0);
}

/// The public API is the one the contract gives.
///
/// This test does not run anything: it fails to compile if a name or a
/// signature drifts away from `docs/EVENTS-API.md`.
#[test]
fn the_api_is_the_one_the_contract_gives() {
    use std::path::Path;

    let _: fn(usize) -> EventBus = EventBus::new;
    let _: fn(&Path) -> Result<EventBus, EventError> = EventBus::bind;
    let _: fn(&EventBus) -> &Path = EventBus::socket_path;
    let _: fn(&EventBus) -> Result<(), EventError> = EventBus::serve;
    let _: fn(&EventBus) = EventBus::stop;
    let _: fn(&EventBus, &Event) -> usize = EventBus::publish;
    let _: fn(&EventBus) -> u64 = EventBus::next_seq;

    let _: fn(&str) -> Result<TopicPattern, EventError> = TopicPattern::parse;
    let _: fn(&TopicPattern, &str) -> bool = TopicPattern::matches;

    // The event carries the fields the contract lists, with the types it
    // gives them.
    let event = Event {
        version: 0,
        topic: "ap.new".to_string(),
        ts_ms: 1_762_300_000_000,
        seq: 42,
        data: json!({"bssid": "00:11:22:33:44:01"}),
    };
    let Event {
        version: _,
        topic: _,
        ts_ms: _,
        seq: _,
        data: _,
    } = event;

    // The patterns are the two the contract lists.
    let _ = TopicPattern::Exact("alert.raised".to_string());
    let _ = TopicPattern::Prefix("ap.".to_string());
}

/// A plugin's token only reaches the topics it was given.
#[test]
fn a_scoped_token_only_sees_the_topics_it_was_given() {
    let fixture = Fixture::start_default();

    // The plugin's own secret, scoped to the access point topics.
    fixture.bus.add_token(
        "plugin-secret",
        vec![TopicPattern::Prefix("ap.".to_string())],
    );

    let mut client = fixture.connect();
    let ready = client.subscribe_with("plugin-secret", &["ap.*"]);
    assert_eq!(ready["type"], "bus.ready");

    // It gets the topics it asked for.
    assert_eq!(fixture.bus.publish(&ap_event()), 1);
    let line = client.next_json().expect("the event arrives");
    assert_eq!(line["type"], "ap.new");

    // And nothing else.
    assert_eq!(fixture.bus.publish(&alert_event()), 0);
    client.expect_silence();
}

/// A scoped token that asks for more than it was given gets nothing.
#[test]
fn a_scoped_token_asking_for_more_gets_nothing() {
    let fixture = Fixture::start_default();
    fixture.bus.add_token(
        "plugin-secret",
        vec![TopicPattern::Prefix("ap.".to_string())],
    );

    let mut client = fixture.connect();
    let ready = client.subscribe_with("plugin-secret", &["alert.raised"]);
    assert_eq!(ready["type"], "bus.ready");

    // The topic was dropped, so nothing arrives.
    assert_eq!(fixture.bus.publish(&alert_event()), 0);
    client.expect_silence();
}

/// The bus's own token still sees everything.
#[test]
fn the_global_token_still_sees_everything() {
    let fixture = Fixture::start_default();
    fixture.bus.add_token(
        "plugin-secret",
        vec![TopicPattern::Prefix("ap.".to_string())],
    );

    let mut client = fixture.subscribe(&["alert.raised"]);
    assert_eq!(fixture.bus.publish(&alert_event()), 1);
    let line = client.next_json().expect("the event arrives");
    assert_eq!(line["type"], "alert.raised");
}
