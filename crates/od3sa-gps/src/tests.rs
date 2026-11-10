//! The tests: a fake gpsd on a loopback port, and the client pointed at it.
//!
//! The fake gpsd speaks the real gpsd framing: a request is a command
//! introduced by `?`, and a command that is not is answered with the
//! "Unrecognized request" error a real gpsd sends. Every position in this
//! file is made up. The fake gpsd never reports a real place.

use std::io::{BufRead, BufReader, ErrorKind, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use crate::{Fix, GpsError, GpsdClient};

/// A poll response: the position of each device is inside `tpv`.
const POLL_WITH_POSITION: &str = concat!(
    r#"{"class":"POLL","time":"2026-11-05T09:00:00Z","active":1,"tpv":[{"class":"TPV","#,
    r#""time":"2026-11-05T09:00:00Z","mode":3,"lat":12.3456,"lon":-54.3210,"alt":123.4,"#,
    r#""speed":0.0,"track":0.0,"status":1}],"sky":[]}"#
);

/// A later position, so a watch can be seen to update the fix. A watch
/// carries the position at the top level.
const WATCH_WITH_NEW_POSITION: &str = concat!(
    r#"{"class":"WATCH","device":"/dev/ttyS0","time":"2026-11-05T09:00:10Z","mode":2,"#,
    r#""lat":12.4000,"lon":-54.4000,"alt":130.0,"speed":0.1,"track":12.0,"status":1}"#
);

/// A watch with no fix: mode 1.
const WATCH_WITHOUT_FIX: &str = concat!(
    r#"{"class":"WATCH","device":"/dev/ttyS0","time":"2026-11-05T09:00:20Z","mode":1,"#,
    r#""lat":0.0,"lon":0.0,"alt":0.0}"#
);

/// A class the daemon does not care about.
const DEVICES: &str =
    r#"{"class":"DEVICES","devices":[{"class":"DEVICE","path":"/dev/ttyS0","driver":"ublox"}]}"#;

/// A poll response with no device in it.
const POLL_WITHOUT_POSITION: &str =
    r#"{"class":"POLL","time":"2026-11-05T09:00:00Z","active":0,"tpv":[],"sky":[]}"#;

/// A poll response whose field inventory does not include `tpv` at all.
const POLL_WITHOUT_TPV: &str = r#"{"class":"POLL","time":"2026-11-05T09:00:00Z","active":0}"#;

/// What a real gpsd answers when it does not understand the request.
const ERROR: &str = r#"{"class":"ERROR","message":"Unrecognized request"}"#;

/// Something that is not JSON.
const NOT_JSON: &str = "this is not json at all";

/// The request the client is expected to send.
const EXPECTED_REQUEST: &str = "?WATCH={\"enable\":true,\"json\":true}";

/// The epoch milliseconds of `2026-11-05T09:00:00Z`.
const TS_MS: i64 = 1_793_869_200_000;

/// The epoch milliseconds of `2026-11-05T09:00:10Z`.
const TS_MS_LATER: i64 = 1_793_869_210_000;

/// A fake gpsd: a TCP listener that speaks the gpsd JSON protocol.
struct FakeGpsd {
    address: String,
    socket: Arc<Mutex<Option<TcpStream>>>,
    received: Arc<Mutex<Vec<String>>>,
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl FakeGpsd {
    /// A fake gpsd that answers the first request with `replies` and then
    /// keeps the connection open.
    fn start(replies: &[&str]) -> FakeGpsd {
        FakeGpsd::spawn(replies, false)
    }

    /// A fake gpsd that answers the first request with `replies` and then
    /// drops the connection.
    fn start_and_drop(replies: &[&str]) -> FakeGpsd {
        FakeGpsd::spawn(replies, true)
    }

    /// A fake gpsd on a free loopback port.
    fn spawn(replies: &[&str], drop_after: bool) -> FakeGpsd {
        let listener = TcpListener::bind("127.0.0.1:0").expect("the fake gpsd binds");
        listener
            .set_nonblocking(true)
            .expect("the fake gpsd listener is non-blocking");
        let address = listener
            .local_addr()
            .expect("the fake gpsd has an address")
            .to_string();
        let socket: Arc<Mutex<Option<TcpStream>>> = Arc::new(Mutex::new(None));
        let shared = Arc::clone(&socket);
        let received: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let requests = Arc::clone(&received);
        let stop = Arc::new(AtomicBool::new(false));
        let stopper = Arc::clone(&stop);
        let replies: Vec<String> = replies.iter().map(|reply| (*reply).to_owned()).collect();

        let handle = thread::spawn(move || {
            loop {
                if stopper.load(Ordering::SeqCst) {
                    return;
                }
                match listener.accept() {
                    Ok((stream, _)) => {
                        serve(stream, &replies, drop_after, &shared, &stopper, &requests);
                        if drop_after {
                            return;
                        }
                    }
                    Err(err) if err.kind() == ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(2));
                    }
                    Err(_) => return,
                }
            }
        });

        FakeGpsd {
            address,
            socket,
            received,
            stop,
            handle: Some(handle),
        }
    }

    /// The request lines the fake gpsd actually received.
    fn received(&self) -> Vec<String> {
        self.received.lock().expect("the fake gpsd lock").clone()
    }

    /// Wait until the fake gpsd has received a request, and return every
    /// request line it has received.
    fn wait_for_request(&self) -> Vec<String> {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let received = self.received();
            if !received.is_empty() || Instant::now() >= deadline {
                return received;
            }
            thread::sleep(Duration::from_millis(5));
        }
    }

    /// Send another line to the client.
    fn send(&self, line: &str) {
        let mut guard = self.socket.lock().expect("the fake gpsd lock");
        if let Some(stream) = guard.as_mut() {
            let _ = writeln!(stream, "{line}");
            let _ = stream.flush();
        }
    }
}

impl Drop for FakeGpsd {
    fn drop(&mut self) {
        // Tell the fake gpsd to stop, wake it up if it is reading, and wait
        // for it to finish.
        self.stop.store(true, Ordering::SeqCst);
        if let Some(stream) = self.socket.lock().expect("the fake gpsd lock").take() {
            let _ = stream.shutdown(Shutdown::Both);
        }
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

/// Answer one connection: read the request, answer it, then either keep the
/// connection open or let it drop.
fn serve(
    mut stream: TcpStream,
    replies: &[String],
    drop_after: bool,
    shared: &Arc<Mutex<Option<TcpStream>>>,
    stop: &AtomicBool,
    received: &Arc<Mutex<Vec<String>>>,
) {
    let read_half = match stream.try_clone() {
        Ok(half) => half,
        Err(_) => return,
    };
    let mut reader = BufReader::new(read_half);
    let mut line = String::new();
    match reader.read_line(&mut line) {
        Ok(0) | Err(_) => return,
        Ok(_) => {}
    }

    // A request is a command introduced by `?`. A real gpsd does not parse a
    // bare JSON object as a request and says so.
    let request = line.trim().to_owned();
    received
        .lock()
        .expect("the fake gpsd lock")
        .push(request.clone());

    if request.starts_with('?') {
        for reply in replies {
            if writeln!(stream, "{reply}").is_err() {
                return;
            }
        }
    } else if writeln!(stream, "{ERROR}").is_err() {
        return;
    }
    if stream.flush().is_err() {
        return;
    }

    if drop_after {
        // The last handle on the socket goes away with this frame, so the
        // client sees the connection close.
        let _ = shared.lock().expect("the fake gpsd lock").take();
        return;
    }

    *shared.lock().expect("the fake gpsd lock") = Some(stream);
    if stop.load(Ordering::SeqCst) {
        // The fake gpsd is being dropped: let go of the socket so that the
        // read below returns.
        if let Some(stream) = shared.lock().expect("the fake gpsd lock").take() {
            let _ = stream.shutdown(Shutdown::Both);
        }
        return;
    }

    loop {
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
    }
}

/// Poll until a fix arrives, and return how many messages were read.
fn poll_until_fix(client: &mut GpsdClient) -> (usize, Option<Fix>) {
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut total = 0usize;
    while Instant::now() < deadline {
        match client.poll() {
            Ok(count) => total += count,
            Err(_) => break,
        }
        if let Some(fix) = client.last_fix() {
            return (total, Some(fix));
        }
        thread::sleep(Duration::from_millis(5));
    }
    (total, client.last_fix())
}

/// Poll for a while without waiting for anything in particular.
fn poll_for(client: &mut GpsdClient, how_long: Duration) -> usize {
    let deadline = Instant::now() + how_long;
    let mut total = 0usize;
    while Instant::now() < deadline {
        match client.poll() {
            Ok(count) => total += count,
            Err(_) => break,
        }
        thread::sleep(Duration::from_millis(5));
    }
    total
}

#[test]
fn a_poll_response_keeps_the_fix() {
    let fake = FakeGpsd::start(&[POLL_WITH_POSITION]);
    let mut client = GpsdClient::with_address(&fake.address);
    client.connect().expect("the client connects");

    let (count, fix) = poll_until_fix(&mut client);
    let fix = fix.expect("the client keeps the fix");

    assert_eq!(count, 1, "one message was read");
    assert_eq!(fix.lat, 12.3456);
    assert_eq!(fix.lon, -54.3210);
    assert_eq!(fix.alt, 123.4);
    assert_eq!(fix.mode, 3);
    assert_eq!(fix.ts_ms, TS_MS);
    assert!(client.is_connected());
}

#[test]
fn the_client_sends_a_question_mark_request() {
    let fake = FakeGpsd::start(&[POLL_WITH_POSITION]);
    let mut client = GpsdClient::with_address(&fake.address);
    client.connect().expect("the client connects");

    let received = fake.wait_for_request();

    assert_eq!(received.len(), 1, "one request was sent");
    assert_eq!(
        received.first().map(String::as_str),
        Some(EXPECTED_REQUEST),
        "the request is the command the fake gpsd understands"
    );
    assert!(
        received[0].starts_with('?'),
        "a request is a command introduced by `?`, not a bare JSON object"
    );
}

#[test]
fn a_watch_updates_the_fix() {
    let fake = FakeGpsd::start(&[WATCH_WITH_NEW_POSITION]);
    let mut client = GpsdClient::with_address(&fake.address);
    client.connect().expect("the client connects");

    let (_, fix) = poll_until_fix(&mut client);
    let fix = fix.expect("the client keeps the fix");
    assert_eq!(fix.lat, 12.4000);
    assert_eq!(fix.lon, -54.4000);
    assert_eq!(fix.alt, 130.0);
    assert_eq!(fix.mode, 2);
    assert_eq!(fix.ts_ms, TS_MS_LATER);
}

#[test]
fn a_message_that_is_not_json_is_ignored() {
    let fake = FakeGpsd::start(&[NOT_JSON, POLL_WITH_POSITION]);
    let mut client = GpsdClient::with_address(&fake.address);
    client.connect().expect("the client connects");

    let (count, fix) = poll_until_fix(&mut client);
    let fix = fix.expect("the client carries on after a bad message");

    assert_eq!(count, 2, "both messages were read");
    assert_eq!(fix.lat, 12.3456, "the good message was still taken");
    assert!(client.is_connected(), "the client carries on");
}

#[test]
fn a_json_message_of_an_unexpected_shape_is_ignored() {
    let fake = FakeGpsd::start(&[
        DEVICES,
        POLL_WITHOUT_POSITION,
        POLL_WITHOUT_TPV,
        WATCH_WITHOUT_FIX,
        ERROR,
        r#"{"hello":"world"}"#,
    ]);
    let mut client = GpsdClient::with_address(&fake.address);
    client.connect().expect("the client connects");

    let count = poll_for(&mut client, Duration::from_millis(300));

    assert_eq!(count, 6, "every message was read");
    assert!(client.last_fix().is_none(), "no fix was kept");
    assert!(client.is_connected(), "the client carries on");

    // The client still works: a real position is taken afterwards.
    fake.send(POLL_WITH_POSITION);
    let (_, fix) = poll_until_fix(&mut client);
    assert_eq!(fix.expect("the fix arrives").lat, 12.3456);
}

#[test]
fn a_fix_with_mode_one_does_not_replace_a_good_fix() {
    let fake = FakeGpsd::start(&[POLL_WITH_POSITION]);
    let mut client = GpsdClient::with_address(&fake.address);
    client.connect().expect("the client connects");

    let (_, fix) = poll_until_fix(&mut client);
    let good = fix.expect("the client keeps the fix");
    assert_eq!(good.mode, 3);

    fake.send(WATCH_WITHOUT_FIX);
    poll_for(&mut client, Duration::from_millis(300));

    assert_eq!(
        client.last_fix(),
        Some(good),
        "the good fix is kept when gpsd says there is no fix"
    );
}

#[test]
fn a_gpsd_that_is_not_there_is_not_a_disaster() {
    // A port with nothing on it: bind one, take its number, let it go.
    let listener = TcpListener::bind("127.0.0.1:0").expect("a free port");
    let address = listener.local_addr().expect("an address").to_string();
    drop(listener);

    let mut client = GpsdClient::with_address(&address);
    assert!(client.connect().is_err(), "connecting fails");
    assert!(!client.is_connected(), "the client is disconnected");
    assert!(client.last_fix().is_none(), "there is no fix");
    assert!(
        client.poll().is_err(),
        "polling a disconnected client fails"
    );
}

#[test]
fn a_connection_that_drops_is_noticed() {
    let fake = FakeGpsd::start_and_drop(&[WATCH_WITH_NEW_POSITION]);
    let mut client = GpsdClient::with_address(&fake.address);
    client.connect().expect("the client connects");

    let deadline = Instant::now() + Duration::from_secs(5);
    let mut noticed = false;
    while Instant::now() < deadline {
        match client.poll() {
            Ok(_) => {}
            Err(GpsError::Disconnected) => {
                noticed = true;
                break;
            }
            Err(_) => break,
        }
        thread::sleep(Duration::from_millis(5));
    }

    assert!(noticed, "the dropped connection was noticed");
    assert!(
        !client.is_connected(),
        "the client reports itself disconnected"
    );
}

#[test]
fn the_time_in_a_poll_object_is_parsed_into_epoch_milliseconds() {
    let fake = FakeGpsd::start(&[POLL_WITH_POSITION]);
    let mut client = GpsdClient::with_address(&fake.address);
    client.connect().expect("the client connects");

    let (_, fix) = poll_until_fix(&mut client);
    let fix = fix.expect("the client keeps the fix");

    assert_eq!(fix.ts_ms, TS_MS);
    assert_eq!(fix.ts_ms, 1_793_869_200_000);
}

#[test]
fn a_client_reconnects_after_a_failure() {
    let fake = FakeGpsd::start(&[POLL_WITH_POSITION]);
    let mut client = GpsdClient::with_address(&fake.address);

    client.connect().expect("the client connects");
    let (_, fix) = poll_until_fix(&mut client);
    assert!(fix.is_some());

    client.disconnect();
    assert!(!client.is_connected());

    client.connect().expect("the client connects again");
    assert!(client.is_connected());

    let (_, fix) = poll_until_fix(&mut client);
    assert_eq!(fix.expect("the fix arrives again").lat, 12.3456);
}
