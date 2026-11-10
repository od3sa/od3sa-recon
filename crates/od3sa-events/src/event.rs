//! The things that travel on the bus: an event and a topic pattern.

use serde_json::Value;

use crate::EventError;

/// One event on the bus.
///
/// The envelope on the wire is
/// `{"v":0,"type":"<topic>","ts_ms":<int>,"seq":<int>,"data":{...}}`,
/// one JSON object on one line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event {
    /// The API version. Zero for now.
    pub version: u32,
    /// The topic.
    pub topic: String,
    /// When it happened, in unix epoch milliseconds.
    pub ts_ms: i64,
    /// A sequence number, increasing over the life of the bus.
    ///
    /// The bus assigns the number when the event is published, so this
    /// field is what the event carries on the wire and what a received
    /// event holds. See [`crate::EventBus::next_seq`].
    pub seq: u64,
    /// The payload.
    pub data: Value,
}

impl Event {
    /// An event with version zero and no sequence number.
    ///
    /// The sequence number is filled in by the bus when the event is
    /// published.
    pub fn new(topic: impl Into<String>, ts_ms: i64, data: Value) -> Event {
        Event {
            version: 0,
            topic: topic.into(),
            ts_ms,
            seq: 0,
            data,
        }
    }
}

/// A topic pattern: an exact name, or a prefix with a trailing `.*`.
///
/// A pattern is either `name` or `prefix.*`. A subscriber that asks for
/// `ap.*` gets `ap.new` and any other `ap.` topic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TopicPattern {
    /// Exactly this topic.
    Exact(String),
    /// Every topic with this prefix.
    ///
    /// The prefix is the text before the `.*`. [`parse`](TopicPattern::parse)
    /// puts the dot in it, so `parse("ap.*")` gives `Prefix("ap.")`.
    Prefix(String),
}

/// Whether an allowed pattern covers a requested one.
///
/// A scoped token may ask for less than it was given and get it; asking for
/// more is dropped. "Covers" means everything the requested pattern would
/// match is inside the allowed one.
pub fn covers(allowed: &TopicPattern, requested: &TopicPattern) -> bool {
    match (allowed, requested) {
        (TopicPattern::Exact(a), TopicPattern::Exact(r)) => a == r,
        (TopicPattern::Exact(a), TopicPattern::Prefix(r)) => a.starts_with(r.as_str()),
        (TopicPattern::Prefix(a), TopicPattern::Exact(r)) => r.starts_with(a.as_str()),
        (TopicPattern::Prefix(a), TopicPattern::Prefix(r)) => a.as_str().starts_with(r.as_str()),
    }
}

impl TopicPattern {
    /// Parse a pattern, which is either `name` or `prefix.*`.
    ///
    /// # Errors
    ///
    /// Returns an error when the pattern is empty, when it holds a `*`
    /// anywhere but at the end, or when it holds a `*` in the middle of
    /// the prefix (`a.*.b`).
    pub fn parse(pattern: &str) -> Result<TopicPattern, EventError> {
        let trimmed = pattern.trim();

        if trimmed.is_empty() {
            return Err(EventError::BadPattern {
                pattern: pattern.to_string(),
                reason: "the pattern is empty",
            });
        }

        if let Some(prefix) = trimmed.strip_suffix(".*") {
            if prefix.contains('*') {
                return Err(EventError::BadPattern {
                    pattern: pattern.to_string(),
                    reason: "the pattern holds a wildcard in the prefix",
                });
            }

            // The dot belongs to the prefix, so that `ap.*` matches `ap.new`
            // and not `apple.new`.
            return Ok(TopicPattern::Prefix(format!("{prefix}.")));
        }

        if trimmed.contains('*') {
            return Err(EventError::BadPattern {
                pattern: pattern.to_string(),
                reason: "the only wildcard is a `.*` at the end",
            });
        }

        Ok(TopicPattern::Exact(trimmed.to_string()))
    }

    /// Whether the pattern matches a topic.
    ///
    /// A prefix matches the topics of one namespace: the prefix `ap.`
    /// matches `ap.new` and `ap.updated`, and not `apple.new`. A prefix
    /// that does not end with a dot is treated the same way, so that
    /// `Prefix("ap")` and `Prefix("ap.")` agree.
    pub fn matches(&self, topic: &str) -> bool {
        match self {
            TopicPattern::Exact(name) => topic == name,
            TopicPattern::Prefix(prefix) => match topic.strip_prefix(prefix.as_str()) {
                Some(rest) => prefix.ends_with('.') || rest.starts_with('.'),
                None => false,
            },
        }
    }

    /// The pattern as it was written, for a log line or a status reply.
    pub fn as_str(&self) -> String {
        match self {
            TopicPattern::Exact(name) => name.clone(),
            TopicPattern::Prefix(prefix) => format!("{}.*", prefix.trim_end_matches('.')),
        }
    }
}
