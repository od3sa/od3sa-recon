//! The JSON-RPC client the plugins use to read the database.
//!
//! A plugin is a separate process, and it reaches the data through the
//! daemon's read-only query socket — never through the database file, which
//! would let two writers fight over it and would let a plugin see more than
//! its capabilities allow.
//!
//! The client is deliberately small: one request, one response, one
//! connection per call. A plugin that asks ten questions opens ten
//! connections, which on a device with 104 MB of RAM is a price worth
//! paying for a process that is short-lived anyway.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;

use serde_json::{Value, json};

/// Why a query failed.
#[derive(Debug)]
pub enum PluginError {
    /// The environment the plugin was given is not enough to talk to the
    /// daemon.
    Environment(String),
    /// The socket could not be reached.
    Connect(String),
    /// The daemon answered with an error.
    Rpc {
        /// The JSON-RPC error code.
        code: i64,
        /// What the daemon said.
        message: String,
    },
    /// The daemon's answer was not the JSON it should have been.
    Protocol(String),
    /// The daemon said nothing.
    NoAnswer,
}

impl std::fmt::Display for PluginError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Environment(reason) => write!(f, "{reason}"),
            Self::Connect(reason) => write!(f, "cannot reach the daemon: {reason}"),
            Self::Rpc { code, message } => write!(f, "the daemon refused: {code}: {message}"),
            Self::Protocol(reason) => write!(f, "the daemon's answer made no sense: {reason}"),
            Self::NoAnswer => write!(f, "the daemon said nothing"),
        }
    }
}

impl std::error::Error for PluginError {}

/// The query socket and the token to present.
#[derive(Debug, Clone)]
pub struct QueryClient {
    socket: PathBuf,
    token: String,
    /// Answers to give instead of talking to a socket.
    ///
    /// A plugin's test needs a daemon to talk to, and there is not one on a
    /// build machine. This is how a test says what the daemon would answer.
    answers: Option<Vec<(String, Value)>>,
}

impl QueryClient {
    /// A client for the given socket and token.
    pub fn new(socket: PathBuf, token: String) -> QueryClient {
        QueryClient {
            socket,
            token,
            answers: None,
        }
    }

    /// A client that answers from a script instead of from a socket.
    ///
    /// The answers are `(method, answer)` pairs; a method that is not in the
    /// script is an error, so a test cannot quietly pass with a method the
    /// daemon does not have.
    pub fn scripted(answers: Vec<(&str, Value)>) -> QueryClient {
        QueryClient {
            socket: PathBuf::from("/nonexistent"),
            token: "scripted".to_string(),
            answers: Some(
                answers
                    .into_iter()
                    .map(|(method, answer)| (method.to_string(), answer))
                    .collect(),
            ),
        }
    }

    /// A client from the environment the host gives a plugin.
    ///
    /// The host sets `OD3SA_QUERY` and `OD3SA_TOKEN` ✓; a plugin started by
    /// hand has to set them itself ✓.
    pub fn from_env() -> Result<QueryClient, PluginError> {
        let socket = std::env::var("OD3SA_QUERY").map_err(|_| {
            PluginError::Environment(
                "OD3SA_QUERY is not set: is this plugin started by the host?".to_string(),
            )
        })?;
        let token = std::env::var("OD3SA_TOKEN").map_err(|_| {
            PluginError::Environment(
                "OD3SA_TOKEN is not set: is this plugin started by the host?".to_string(),
            )
        })?;
        Ok(QueryClient::new(PathBuf::from(socket), token))
    }

    /// The socket this client talks to.
    pub fn socket(&self) -> &PathBuf {
        &self.socket
    }

    /// Call a method and return its result.
    pub fn call(&self, method: &str, params: Value) -> Result<Value, PluginError> {
        // A scripted client answers from its script.
        if let Some(answers) = &self.answers {
            return answers
                .iter()
                .find(|(name, _)| name == method)
                .map(|(_, answer)| answer.clone())
                .ok_or_else(|| {
                    PluginError::Protocol(format!("the script has no answer for {method}"))
                });
        }

        // The token and the method's own arguments share one object: that is
        // what the daemon reads.
        let mut all = params.as_object().cloned().unwrap_or_default();
        all.insert("token".to_string(), Value::String(self.token.clone()));
        let request = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": all,
        });
        let line = serde_json::to_string(&request)
            .map_err(|error| PluginError::Protocol(error.to_string()))?;

        let mut stream = UnixStream::connect(&self.socket)
            .map_err(|error| PluginError::Connect(error.to_string()))?;
        stream
            .write_all(line.as_bytes())
            .and_then(|()| stream.write_all(b"\n"))
            .and_then(|()| stream.flush())
            .map_err(|error| PluginError::Connect(error.to_string()))?;

        let mut reader = BufReader::new(stream);
        let mut answer = String::new();
        reader
            .read_line(&mut answer)
            .map_err(|error| PluginError::Connect(error.to_string()))?;
        if answer.trim().is_empty() {
            return Err(PluginError::NoAnswer);
        }

        let answer: Value = serde_json::from_str(&answer)
            .map_err(|error| PluginError::Protocol(error.to_string()))?;
        if let Some(error) = answer.get("error") {
            return Err(PluginError::Rpc {
                code: error.get("code").and_then(Value::as_i64).unwrap_or(0),
                message: error
                    .get("message")
                    .and_then(Value::as_str)
                    .unwrap_or("no reason given")
                    .to_string(),
            });
        }
        answer
            .get("result")
            .cloned()
            .ok_or_else(|| PluginError::Protocol("no result".to_string()))
    }

    /// Call a method that returns a list of items, and follow the cursor
    /// until there are no more.
    ///
    /// The daemon pages its answers, so a plugin that wants everything has to
    /// ask for it a page at a time ✓.
    pub fn call_all(&self, method: &str, params: Value) -> Result<Vec<Value>, PluginError> {
        let mut items = Vec::new();
        let mut params = params;
        loop {
            let page = self.call(method, params.clone())?;
            if let Some(page_items) = page.get("items").and_then(Value::as_array) {
                items.extend(page_items.iter().cloned());
            }
            let cursor = page.get("next_cursor").and_then(Value::as_str);
            match cursor {
                Some(cursor) if !cursor.is_empty() => {
                    params["cursor"] = Value::String(cursor.to_string());
                }
                _ => return Ok(items),
            }
        }
    }
}
