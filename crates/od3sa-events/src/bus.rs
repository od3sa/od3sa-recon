//! The bus itself: the socket, the subscribers and the sequence number.
//!
//! The daemon is the server and the plugins are the clients. A plugin
//! connects, sends one subscribe line and reads events.
//!
//! # The backpressure policy
//!
//! A slow subscriber must never slow the daemon down, and must never make
//! it grow without bound. So every subscriber has a **bounded queue** of
//! `queue_len` events. When the queue is full the **newest** event is
//! dropped, the subscriber is told how many it missed, and the publish
//! path never waits.
//!
//! The lock is held for as long as it takes to push one line or to pop
//! one line. The write to the socket happens **outside** the lock, so a
//! subscriber that stops reading cannot hold up the collector.

use std::collections::VecDeque;
use std::fs;
use std::io::{self, BufRead, BufReader, Write};
use std::net::Shutdown;
use std::os::unix::fs::FileTypeExt;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, RwLock};
use std::thread;
use std::time::Duration;

use crate::error::EventError;
use crate::event::{Event, TopicPattern};
use crate::wire;

/// The default number of events a subscriber may fall behind by.
pub const DEFAULT_QUEUE_LEN: usize = 256;

/// The default path of the event socket.
pub const DEFAULT_SOCKET_PATH: &str = "/tmp/od3sa-recon/events.sock";

/// The longest subscribe line the bus reads.
const MAX_LINE: usize = 64 * 1024;

/// How long the accept loop waits between polls of the socket.
const ACCEPT_POLL: Duration = Duration::from_millis(20);

/// The largest number of answer lines (a `bus.ready` or an error) that
/// wait for one subscriber.
const MAX_CONTROL: usize = 64;

/// Take a lock, taking over a poisoned one.
///
/// A panic in another thread must not take the bus down: the data behind
/// the lock is still consistent.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

/// Compare two tokens without leaking how much of them matched.
fn same_token(left: &str, right: &str) -> bool {
    let left = left.as_bytes();
    let right = right.as_bytes();
    if left.len() != right.len() {
        return false;
    }
    let mut difference = 0u8;
    for (a, b) in left.iter().zip(right.iter()) {
        difference |= a ^ b;
    }
    difference == 0
}

/// One thing waiting to be written to a subscriber.
///
/// Everything a subscriber sees goes through one queue, so that it reads
/// in the order it happened: the answer to a request, then the events.
#[derive(Debug)]
enum Outgoing {
    /// An answer to a request: a `bus.ready` line or an error line.
    Control(String),
    /// An event, and whether it was queued after events were dropped, so
    /// that the notice about the drops goes in front of it.
    Event {
        /// The line to write.
        line: String,
        /// Whether the notice about the drops goes in front of this one.
        after_drop: bool,
    },
}

/// What one subscriber holds.
#[derive(Debug, Default)]
struct SubscriberState {
    /// The patterns the subscriber asked for.
    topics: Vec<TopicPattern>,
    /// Everything waiting to be written, oldest at the front.
    queue: VecDeque<Outgoing>,
    /// How many events are in the queue.
    events_queued: usize,
    /// How many answer lines are in the queue.
    controls_queued: usize,
    /// How many events were dropped since the last notice.
    dropped: u64,
    /// Whether the next event that is queued comes after a drop.
    drop_pending: bool,
    /// How many events are being written right now.
    writing: usize,
    /// Whether the subscriber is gone.
    closed: bool,
}

/// One connection on the bus.
#[derive(Debug)]
pub(crate) struct Subscriber {
    /// A number that tells two subscribers apart.
    id: u64,
    /// The state, behind one lock.
    state: Mutex<SubscriberState>,
    /// Wakes the writer when there is something to write.
    wake: Condvar,
    /// The socket, so that it can be shut down when the subscriber is gone.
    socket: Mutex<Option<UnixStream>>,
}

impl Subscriber {
    /// A subscriber with nothing in it yet.
    fn new(id: u64) -> Subscriber {
        Subscriber {
            id,
            state: Mutex::new(SubscriberState::default()),
            wake: Condvar::new(),
            socket: Mutex::new(None),
        }
    }

    /// The state, behind the lock.
    fn state(&self) -> MutexGuard<'_, SubscriberState> {
        lock(&self.state)
    }

    /// How many events are held for this subscriber: the ones waiting in
    /// the queue and the one being written.
    #[cfg(test)]
    pub(crate) fn pending(&self) -> usize {
        let state = self.state();
        state.events_queued + state.writing
    }

    /// How many events were dropped since the last notice.
    #[cfg(test)]
    pub(crate) fn dropped(&self) -> u64 {
        self.state().dropped
    }

    /// Put an answer line at the back of the queue.
    ///
    /// The queue is bounded, so a plugin that never reads cannot make the
    /// bus grow.
    fn push_control(&self, line: String) {
        let mut state = self.state();
        if state.closed {
            return;
        }
        if state.controls_queued >= MAX_CONTROL {
            return;
        }
        state.queue.push_back(Outgoing::Control(line));
        drop(state);
        self.wake.notify_all();
    }
}

/// The state every subscriber shares.
#[derive(Debug)]
struct Inner {
    /// Where the socket lives.
    path: PathBuf,
    /// The socket, once it is bound.
    listener: Mutex<Option<Arc<UnixListener>>>,
    /// How many events a subscriber may fall behind by.
    queue_len: usize,
    /// The token a subscriber must present.
    token: RwLock<Option<String>>,
    /// Tokens that may only see some of the topics.
    ///
    /// A plugin gets a token of its own, scoped to the topics its manifest
    /// asked for, so it cannot read what it was not given.
    scoped_tokens: RwLock<Vec<(String, Vec<TopicPattern>)>>,
    /// The sequence number the last published event carried.
    ///
    /// This is an `AtomicUsize` and not an `AtomicU64` because the device's
    /// CPU has no 64-bit atomics: `AtomicU64` does not exist on a 32-bit
    /// target such as `mipsel-unknown-linux-musl`, and the crate would not
    /// compile for it. On a 32-bit device the number wraps after four
    /// billion events, which at the rate this daemon publishes is years
    /// away.
    seq: AtomicUsize,
    /// The subscribers, in the order they arrived.
    subscribers: Mutex<Vec<Arc<Subscriber>>>,
    /// The next number for a subscriber.
    next_id: AtomicUsize,
    /// How many events were dropped, over all subscribers.
    dropped_total: AtomicUsize,
    /// Whether the bus was asked to stop.
    stopping: AtomicBool,
}

/// The event bus.
///
/// The daemon owns one of these. It hands events to the plugins that
/// subscribed to them, and it never waits for a plugin to keep up.
#[derive(Debug, Clone)]
pub struct EventBus {
    inner: Arc<Inner>,
}

impl EventBus {
    /// A bus with a bounded queue of `queue_len` events per subscriber.
    ///
    /// The socket is bound when [`serve`](EventBus::serve) is called, on
    /// the default path.
    pub fn new(queue_len: usize) -> EventBus {
        EventBus::with_path(queue_len, Path::new(DEFAULT_SOCKET_PATH))
    }

    /// The socket to listen on.
    ///
    /// The socket is bound now, so a path that cannot be used is reported
    /// here rather than later. The queue per subscriber holds the default
    /// number of events.
    ///
    /// # Errors
    ///
    /// Returns an error if the path cannot be bound, if the path exists
    /// and is not a socket, or if the socket cannot be made private.
    pub fn bind(path: &Path) -> Result<EventBus, EventError> {
        EventBus::bind_with(path, DEFAULT_QUEUE_LEN)
    }

    /// The socket to listen on, with a queue of `queue_len` events per
    /// subscriber.
    ///
    /// # Errors
    ///
    /// Returns an error if the path cannot be bound, if the path exists
    /// and is not a socket, or if the socket cannot be made private.
    pub fn bind_with(path: &Path, queue_len: usize) -> Result<EventBus, EventError> {
        let bus = EventBus::with_path(queue_len, path);
        let listener = bind_listener(path)?;
        {
            let mut slot = lock(&bus.inner.listener);
            *slot = Some(Arc::new(listener));
        }
        Ok(bus)
    }

    /// A bus with a path and a queue length, not bound yet.
    fn with_path(queue_len: usize, path: &Path) -> EventBus {
        EventBus {
            inner: Arc::new(Inner {
                path: path.to_path_buf(),
                listener: Mutex::new(None),
                queue_len,
                token: RwLock::new(None),
                scoped_tokens: RwLock::new(Vec::new()),
                seq: AtomicUsize::new(0),
                subscribers: Mutex::new(Vec::new()),
                next_id: AtomicUsize::new(1),
                dropped_total: AtomicUsize::new(0),
                stopping: AtomicBool::new(false),
            }),
        }
    }

    /// The path the bus is listening on.
    pub fn socket_path(&self) -> &Path {
        &self.inner.path
    }

    /// Set the token a subscriber must present.
    ///
    /// The token is checked before the topics are looked at, so a
    /// subscriber that cannot authenticate learns nothing about what is on
    /// the bus. Until a token is set, every subscribe request is refused.
    pub fn set_token(&self, token: impl Into<String>) {
        let token = token.into();
        match self.inner.token.write() {
            Ok(mut slot) => *slot = Some(token),
            Err(poisoned) => *poisoned.into_inner() = Some(token),
        }
    }

    /// Give a token the right to see only some of the topics.
    ///
    /// The plugin host calls this for each plugin it starts, with the
    /// plugin's own secret and the topics its manifest asked for. A
    /// subscriber presenting that secret gets the topics it asked for and
    /// nothing else: a request for a topic outside the scope is silently
    /// dropped rather than refused, so the plugin sees less and not an
    /// error.
    pub fn add_token(&self, token: impl Into<String>, topics: Vec<TopicPattern>) {
        let token = token.into();
        let mut tokens = match self.inner.scoped_tokens.write() {
            Ok(tokens) => tokens,
            Err(poisoned) => poisoned.into_inner(),
        };
        tokens.retain(|(existing, _)| existing != &token);
        tokens.push((token, topics));
    }

    /// How many events were dropped, over all subscribers.
    pub fn dropped_count(&self) -> u64 {
        self.inner.dropped_total.load(Ordering::SeqCst) as u64
    }

    /// How many subscribers the bus holds.
    pub fn subscriber_count(&self) -> usize {
        lock(&self.inner.subscribers).len()
    }

    /// Serve until `stop` is called. One thread per connection.
    ///
    /// # Errors
    ///
    /// Returns an error if the socket cannot be bound or stops accepting
    /// connections.
    pub fn serve(&self) -> Result<(), EventError> {
        let listener = self.listener()?;
        listener.set_nonblocking(true)?;

        while !self.inner.stopping.load(Ordering::SeqCst) {
            match listener.accept() {
                Ok((stream, _address)) => {
                    let worker = self.clone();
                    let _worker = thread::Builder::new()
                        .name("od3sa-events".to_string())
                        .spawn(move || {
                            if let Err(error) = worker.serve_connection(stream) {
                                // A plugin that goes away mid-request is not
                                // a failure of the bus.
                                if error.kind() != io::ErrorKind::BrokenPipe {
                                    eprintln!("od3sa-events: connection ended: {error}");
                                }
                            }
                        });
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(ACCEPT_POLL);
                }
                Err(error) => return Err(EventError::Io(error)),
            }
        }

        Ok(())
    }

    /// Stop serving and close the socket.
    ///
    /// The accept loop notices at its next turn. Connections that are open
    /// are shut down, so the plugins see the socket go away. The socket
    /// file is removed, so the next run can bind the same path.
    pub fn stop(&self) {
        self.inner.stopping.store(true, Ordering::SeqCst);

        let subscribers: Vec<Arc<Subscriber>> = lock(&self.inner.subscribers).clone();
        for subscriber in subscribers {
            self.close_subscriber(&subscriber);
        }

        // The socket file goes with the socket. It is only removed when it
        // is still a socket: the daemon does not delete files it does not
        // own.
        if let Ok(metadata) = fs::symlink_metadata(&self.inner.path)
            && metadata.file_type().is_socket()
        {
            let _ = fs::remove_file(&self.inner.path);
        }
    }

    /// Publish an event. It goes to every subscriber whose patterns match.
    ///
    /// Returns how many subscribers it reached, that is, how many had the
    /// event routed to them. A subscriber whose queue was full drops the
    /// event and is told so with a `bus.dropped` line; it still counts as
    /// reached, because the event was addressed to it.
    ///
    /// The publish path never waits for a subscriber.
    pub fn publish(&self, event: &Event) -> usize {
        let seq = self.assign_seq();
        let line = wire::event_line(event, seq);

        let subscribers: Vec<Arc<Subscriber>> = lock(&self.inner.subscribers).clone();
        let mut reached = 0;
        for subscriber in subscribers {
            if self.deliver(&subscriber, &event.topic, &line) {
                reached += 1;
            }
        }
        reached
    }

    /// The sequence number the next published event will carry.
    ///
    /// The bus numbers the events itself, so the number always grows and
    /// two subscribers can tell that they saw the same event.
    pub fn next_seq(&self) -> u64 {
        self.inner.seq.load(Ordering::SeqCst) as u64 + 1
    }

    /// The number an event will carry, and remember it.
    ///
    /// The bus owns the numbering: the number of the event is the one
    /// after the last one, so that it grows over the life of the bus.
    fn assign_seq(&self) -> u64 {
        self.inner.seq.fetch_add(1, Ordering::SeqCst) as u64 + 1
    }

    /// Put one event in the queue of one subscriber.
    ///
    /// Returns whether the subscriber wanted the event. When its queue is
    /// full the newest event is dropped, the subscriber is told how many
    /// it missed, and this returns at once: the publish path never waits.
    fn deliver(&self, subscriber: &Arc<Subscriber>, topic: &str, line: &str) -> bool {
        let mut state = subscriber.state();
        if state.closed {
            return false;
        }

        if !state.topics.iter().any(|pattern| pattern.matches(topic)) {
            return false;
        }

        if state.events_queued + state.writing >= self.inner.queue_len {
            // The queue is full: the newest event is dropped and the
            // subscriber is told about it later.
            state.dropped += 1;
            state.drop_pending = true;
            self.inner.dropped_total.fetch_add(1, Ordering::SeqCst);
            drop(state);
            subscriber.wake.notify_all();
            return true;
        }

        let after_drop = state.drop_pending;
        state.drop_pending = false;
        state.events_queued += 1;
        state.queue.push_back(Outgoing::Event {
            line: line.to_string(),
            after_drop,
        });
        drop(state);
        subscriber.wake.notify_all();
        true
    }

    /// Read the requests of one connection and answer them.
    fn serve_connection(&self, stream: UnixStream) -> io::Result<()> {
        let id = self.inner.next_id.fetch_add(1, Ordering::SeqCst) as u64;
        let subscriber = Arc::new(Subscriber::new(id));

        {
            let mut slot = lock(&subscriber.socket);
            *slot = Some(stream.try_clone()?);
        }
        lock(&self.inner.subscribers).push(subscriber.clone());

        // The writer has a thread of its own: a write to a socket can
        // block on a slow reader, and that must not stop the bus.
        let writer_subscriber = subscriber.clone();
        let writer_stream = stream.try_clone()?;
        let writer = thread::Builder::new()
            .name("od3sa-events-writer".to_string())
            .spawn(move || writer_loop(writer_subscriber, writer_stream));

        let reader = stream.try_clone()?;
        let result = self.read_requests(&subscriber, reader);

        // The plugin is gone: forget it and let the writer finish.
        self.close_subscriber(&subscriber);
        if let Ok(handle) = writer {
            let _ = handle.join();
        }

        result
    }

    /// Read subscribe requests until the plugin closes the connection.
    fn read_requests(&self, subscriber: &Arc<Subscriber>, stream: UnixStream) -> io::Result<()> {
        let mut reader = BufReader::new(stream);
        let mut buffer = Vec::new();

        loop {
            buffer.clear();
            match read_line(&mut reader, &mut buffer, MAX_LINE)? {
                Line::EndOfFile => break,
                Line::TooLong => {
                    subscriber.push_control(wire::error_line("the request line is too long"));
                }
                Line::Complete => {
                    let text = String::from_utf8_lossy(&buffer).into_owned();
                    self.handle_request(subscriber, &text);
                }
            }
        }

        Ok(())
    }

    /// Answer one subscribe request.
    ///
    /// A malformed request gets an error line and the connection stays
    /// open.
    fn handle_request(&self, subscriber: &Arc<Subscriber>, line: &str) {
        let request = match wire::parse_subscribe(line) {
            Ok(request) => request,
            Err(wire::SubscribeError::Malformed(reason)) => {
                subscriber.push_control(wire::error_line(reason));
                return;
            }
        };

        // The token is checked before the topics are looked at, so a
        // subscriber that cannot authenticate learns nothing about what
        // is on the bus.
        if !self.token_matches(&request.token) {
            subscriber.push_control(wire::error_line("bad or missing token"));
            return;
        }

        let names = match wire::parse_topics(&request.topics) {
            Ok(names) => names,
            Err(wire::SubscribeError::Malformed(reason)) => {
                subscriber.push_control(wire::error_line(reason));
                return;
            }
        };

        let mut patterns = Vec::with_capacity(names.len());
        for name in &names {
            match TopicPattern::parse(name) {
                Ok(pattern) => patterns.push(pattern),
                Err(_) => {
                    subscriber.push_control(wire::error_line("a topic pattern is not valid"));
                    return;
                }
            }
        }

        // A scoped token only gets the topics it was given. A request for
        // anything else is dropped rather than refused: the plugin sees
        // less, not an error.
        if let Some(scope) = self.scope_for(&request.token) {
            patterns.retain(|pattern| {
                scope
                    .iter()
                    .any(|allowed| crate::event::covers(allowed, pattern))
            });
        }

        let names: Vec<String> = patterns.iter().map(TopicPattern::as_str).collect();
        self.announce(subscriber, patterns, &names);
    }

    /// Subscribe the subscriber to the topics, and tell it what it got.
    ///
    /// The topics and the answer go in together, so that no event can slip
    /// in front of the `bus.ready` line.
    fn announce(
        &self,
        subscriber: &Arc<Subscriber>,
        patterns: Vec<TopicPattern>,
        names: &[String],
    ) {
        {
            let mut state = subscriber.state();
            if state.closed {
                return;
            }
            state.topics = patterns;
            if state.controls_queued < MAX_CONTROL {
                state.controls_queued += 1;
                state
                    .queue
                    .push_back(Outgoing::Control(wire::ready_line(names)));
            }
        }
        subscriber.wake.notify_all();
    }

    /// Whether a token is the one the bus holds.
    fn token_matches(&self, token: &str) -> bool {
        if self.is_global_token(token) {
            return true;
        }
        self.scope_for(token).is_some()
    }

    /// Whether this is the bus's own token, which may see everything.
    fn is_global_token(&self, token: &str) -> bool {
        match self.inner.token.read() {
            Ok(slot) => match slot.as_deref() {
                Some(expected) => same_token(expected, token),
                None => false,
            },
            Err(poisoned) => match poisoned.into_inner().as_deref() {
                Some(expected) => same_token(expected, token),
                None => false,
            },
        }
    }

    /// The topics a scoped token may see.
    fn scope_for(&self, token: &str) -> Option<Vec<TopicPattern>> {
        let tokens = match self.inner.scoped_tokens.read() {
            Ok(tokens) => tokens,
            Err(poisoned) => poisoned.into_inner(),
        };
        tokens
            .iter()
            .find(|(secret, _)| same_token(secret, token))
            .map(|(_, topics)| topics.clone())
    }

    /// Forget a subscriber and shut its socket down.
    fn close_subscriber(&self, subscriber: &Arc<Subscriber>) {
        {
            let mut state = subscriber.state();
            if state.closed {
                return;
            }
            state.closed = true;
            state.queue.clear();
            state.events_queued = 0;
            state.controls_queued = 0;
        }
        subscriber.wake.notify_all();

        lock(&self.inner.subscribers).retain(|other| other.id != subscriber.id);

        if let Ok(mut slot) = subscriber.socket.lock()
            && let Some(socket) = slot.take()
        {
            let _ = socket.shutdown(Shutdown::Both);
        }
    }

    /// The listener, binding the socket if it is not bound yet.
    fn listener(&self) -> Result<Arc<UnixListener>, EventError> {
        {
            let slot = lock(&self.inner.listener);
            if let Some(listener) = slot.as_ref() {
                return Ok(Arc::clone(listener));
            }
        }

        let listener = Arc::new(bind_listener(&self.inner.path)?);
        let mut slot = lock(&self.inner.listener);
        match slot.as_ref() {
            Some(existing) => Ok(Arc::clone(existing)),
            None => {
                *slot = Some(Arc::clone(&listener));
                Ok(listener)
            }
        }
    }

    /// The subscribers, for the tests.
    #[cfg(test)]
    pub(crate) fn subscribers(&self) -> Vec<Arc<Subscriber>> {
        lock(&self.inner.subscribers).clone()
    }
}

/// Write the lines of one subscriber to its socket.
///
/// The socket is written outside the lock, so a subscriber that stops
/// reading holds up nobody but itself.
fn writer_loop(subscriber: Arc<Subscriber>, mut stream: UnixStream) {
    loop {
        let item = {
            let mut state = subscriber.state();
            loop {
                if state.closed {
                    return;
                }

                match state.queue.pop_front() {
                    Some(Outgoing::Control(line)) => {
                        state.controls_queued = state.controls_queued.saturating_sub(1);
                        break Item::Line(line, false);
                    }
                    Some(Outgoing::Event { line, after_drop }) => {
                        state.events_queued = state.events_queued.saturating_sub(1);
                        // A notice about the dropped events goes in front
                        // of the first event that was queued after them,
                        // so that the subscriber sees the gap where it
                        // happened.
                        let notice = if after_drop && state.dropped > 0 {
                            let count = state.dropped;
                            state.dropped = 0;
                            Some(wire::dropped_line(count))
                        } else {
                            None
                        };
                        state.writing += 1;
                        break match notice {
                            Some(notice) => Item::NoticeThen(notice, line),
                            None => Item::Line(line, true),
                        };
                    }
                    None => {
                        // The queue is empty: if events were dropped, the
                        // gap is at the end of what the subscriber has
                        // seen.
                        if state.dropped > 0 {
                            let count = state.dropped;
                            state.dropped = 0;
                            state.drop_pending = false;
                            break Item::Line(wire::dropped_line(count), false);
                        }

                        state = match subscriber.wake.wait(state) {
                            Ok(guard) => guard,
                            Err(poisoned) => poisoned.into_inner(),
                        };
                    }
                }
            }
        };

        let (first, second, is_event) = match item {
            Item::Line(line, is_event) => (line, None, is_event),
            Item::NoticeThen(notice, line) => (notice, Some(line), true),
        };

        let written = write_line(&mut stream, &first).is_ok()
            && match second {
                Some(line) => write_line(&mut stream, &line).is_ok(),
                None => true,
            };

        if is_event {
            // The event is written; it is not held any more.
            let mut state = subscriber.state();
            state.writing = state.writing.saturating_sub(1);
        }

        if !written {
            return;
        }
    }
}

/// What the writer writes next.
enum Item {
    /// One line, and whether it is an event that was counted as held.
    Line(String, bool),
    /// A notice about the dropped events, and the line that follows it.
    NoticeThen(String, String),
}

/// What one read of a request line found.
enum Line {
    /// A whole line was read.
    Complete,
    /// The connection ended.
    EndOfFile,
    /// The line was longer than the bus accepts.
    TooLong,
}

/// Read one line, up to `limit` bytes.
///
/// A line that is too long is thrown away up to its end, so that the next
/// read starts on a line boundary.
fn read_line(reader: &mut impl BufRead, buffer: &mut Vec<u8>, limit: usize) -> io::Result<Line> {
    let mut too_long = false;

    loop {
        let available = match reader.fill_buf() {
            Ok(available) => available,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        };

        if available.is_empty() {
            if too_long {
                return Ok(Line::TooLong);
            }
            return Ok(if buffer.is_empty() {
                Line::EndOfFile
            } else {
                Line::Complete
            });
        }

        match available.iter().position(|byte| *byte == b'\n') {
            Some(index) => {
                if !too_long {
                    if buffer.len() + index > limit {
                        too_long = true;
                        buffer.clear();
                    } else {
                        buffer.extend_from_slice(&available[..index]);
                    }
                }
                reader.consume(index + 1);
                return Ok(if too_long {
                    Line::TooLong
                } else {
                    Line::Complete
                });
            }
            None => {
                if !too_long {
                    if buffer.len() + available.len() > limit {
                        too_long = true;
                        buffer.clear();
                    } else {
                        buffer.extend_from_slice(available);
                    }
                }
                let length = available.len();
                reader.consume(length);
            }
        }
    }
}

/// Write one line, with its newline.
fn write_line(stream: &mut UnixStream, line: &str) -> io::Result<()> {
    let mut buffer = String::with_capacity(line.len() + 1);
    buffer.push_str(line);
    buffer.push('\n');
    stream.write_all(buffer.as_bytes())?;
    stream.flush()
}

/// Bind the socket at `path`.
///
/// A socket file left over from a previous run is removed first. A path
/// that exists and is not a socket is left alone and reported as an error:
/// the daemon does not delete files it does not own.
fn bind_listener(path: &Path) -> Result<UnixListener, EventError> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)?;
    }

    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_socket() => fs::remove_file(path)?,
        Ok(_) => {
            return Err(EventError::Io(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("'{}' exists and is not a socket", path.display()),
            )));
        }
        Err(_) => {}
    }

    let listener = UnixListener::bind(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(listener)
}
