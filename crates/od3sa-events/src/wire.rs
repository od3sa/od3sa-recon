//! The wire format: one JSON object per line.
//!
//! The shapes here are the contract in `docs/EVENTS-API.md`. Every line is
//! one object, and the field order is the one the contract shows, so that a
//! log line can be read by a human.

use serde_json::Value;

use crate::event::Event;

/// The line of one event, without the newline.
pub(crate) fn event_line(event: &Event, seq: u64) -> String {
    let mut line = String::with_capacity(160);
    line.push_str("{\"v\":");
    line.push_str(&event.version.to_string());
    line.push_str(",\"type\":");
    push_string(&mut line, &event.topic);
    line.push_str(",\"ts_ms\":");
    line.push_str(&event.ts_ms.to_string());
    line.push_str(",\"seq\":");
    line.push_str(&seq.to_string());
    line.push_str(",\"data\":");
    // `Value` is always valid JSON, so the display form cannot fail.
    line.push_str(&event.data.to_string());
    line.push('}');
    line
}

/// The line that answers a subscribe request.
pub(crate) fn ready_line(topics: &[String]) -> String {
    let mut line = String::with_capacity(64);
    line.push_str("{\"type\":\"bus.ready\",\"data\":{\"topics\":");
    push_strings(&mut line, topics);
    line.push_str("}}");
    line
}

/// The line that tells a subscriber how many events it missed.
pub(crate) fn dropped_line(count: u64) -> String {
    format!("{{\"type\":\"bus.dropped\",\"data\":{{\"n\":{count}}}}}")
}

/// The line that refuses a request.
pub(crate) fn error_line(message: &str) -> String {
    let mut line = String::with_capacity(64);
    line.push_str("{\"type\":\"bus.error\",\"data\":{\"error\":");
    push_string(&mut line, message);
    line.push_str("}}");
    line
}

/// Push a JSON string, quotes included.
fn push_string(out: &mut String, text: &str) {
    match serde_json::to_string(text) {
        Ok(quoted) => out.push_str(&quoted),
        // A Rust string is always encodable, so this cannot happen.
        Err(_) => out.push_str("\"\""),
    }
}

/// Push a JSON array of strings.
fn push_strings(out: &mut String, items: &[String]) {
    out.push('[');
    for (index, item) in items.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        push_string(out, item);
    }
    out.push(']');
}

/// A subscribe request as it arrived.
#[derive(Debug)]
pub(crate) struct SubscribeRequest {
    /// The token the subscriber claims.
    pub(crate) token: String,
    /// The topics, as they were written, still unparsed.
    ///
    /// The bus looks at this only after it has checked the token.
    pub(crate) topics: Value,
}

/// Why a subscribe request could not be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SubscribeError {
    /// The line is not a subscribe request the bus understands.
    Malformed(&'static str),
}

/// Read one subscribe request.
///
/// The token is **not** checked here, and the topics are not looked at:
/// the bus checks the token first, so that a subscriber that cannot
/// authenticate learns nothing about what is on the bus. Only the shape of
/// the line is read here.
pub(crate) fn parse_subscribe(line: &str) -> Result<SubscribeRequest, SubscribeError> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return Err(SubscribeError::Malformed("the line is empty"));
    }

    let parsed: Value = match serde_json::from_str(trimmed) {
        Ok(parsed) => parsed,
        Err(_) => return Err(SubscribeError::Malformed("the line is not JSON")),
    };

    let object = match parsed.as_object() {
        Some(object) => object,
        None => return Err(SubscribeError::Malformed("the line is not a JSON object")),
    };

    match object.get("op").and_then(Value::as_str) {
        Some("subscribe") => {}
        Some(_) => return Err(SubscribeError::Malformed("unknown operation")),
        None => return Err(SubscribeError::Malformed("the line has no operation")),
    }

    let token = match object.get("token") {
        Some(Value::String(token)) => token.clone(),
        Some(_) => return Err(SubscribeError::Malformed("the token is not a string")),
        None => String::new(),
    };

    let topics = object.get("topics").cloned().unwrap_or(Value::Null);

    Ok(SubscribeRequest { token, topics })
}

/// Read the topic patterns of a subscribe request.
///
/// Returns the patterns as they were written, so that the answer can echo
/// them back, and the patterns themselves.
pub(crate) fn parse_topics(topics: &Value) -> Result<Vec<String>, SubscribeError> {
    let items = match topics {
        Value::Null => return Ok(Vec::new()),
        Value::Array(items) => items,
        Value::String(text) => {
            // One topic, written as a string, is one topic.
            return Ok(vec![text.clone()]);
        }
        _ => return Err(SubscribeError::Malformed("the topics are not an array")),
    };

    let mut names = Vec::with_capacity(items.len());
    for item in items {
        match item.as_str() {
            Some(text) => names.push(text.to_string()),
            None => return Err(SubscribeError::Malformed("a topic is not a string")),
        }
    }
    Ok(names)
}
