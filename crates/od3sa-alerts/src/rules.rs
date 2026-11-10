//! The rules, and the configuration they are parsed from.
//!
//! The configuration is TOML. Every rule has an `enabled` flag and a
//! `severity`; a rule that is not configured at all is off.
//!
//! ```toml
//! enabled = true
//! new_device = { enabled = true, severity = "info" }
//! watchlist = { enabled = true, severity = "warning",
//!               macs = ["00:11:22:33:44:ff"], ouis = ["00:11:22"],
//!               ssids = ["example-ssid"] }
//! seen_again = { enabled = true, severity = "info", after_seconds = 300 }
//! rogue_ap = { enabled = true, severity = "warning" }
//! strong_signal = { enabled = true, severity = "info", rssi_above = -40 }
//! deauth_burst = { enabled = true, severity = "warning",
//!                  count = 5, within_seconds = 10 }
//! ```
//!
//! The parsing is done by hand rather than with `serde`, so that the crate
//! keeps to the two dependencies it is allowed: `od3sa-store` and `toml`.

use std::fmt;

/// How serious an alert is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub enum Severity {
    /// Something worth knowing about.
    #[default]
    Info,
    /// Something worth looking at.
    Warning,
    /// Something that needs attention now.
    Critical,
}

impl Severity {
    /// The name of the severity, as it is written in the configuration and
    /// stored in the `alerts` table.
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Warning => "warning",
            Severity::Critical => "critical",
        }
    }

    /// Parse a severity name, as it is written in the configuration.
    ///
    /// The name is matched exactly, in lower case. Anything else is an
    /// error: a severity that is spelled in another way is a mistake in the
    /// configuration, and a mistake should be reported rather than guessed at.
    pub fn parse(name: &str) -> Option<Severity> {
        match name {
            "info" => Some(Severity::Info),
            "warning" => Some(Severity::Warning),
            "critical" => Some(Severity::Critical),
            _ => None,
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A rule that is on or off, with its severity.
///
/// The rules that take no further parameters — `new_device` and `rogue_ap` —
/// are configured with this.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    /// Whether the rule is on.
    pub enabled: bool,
    /// How serious the alerts it raises are.
    pub severity: Severity,
}

impl Rule {
    /// A rule that is on, with a severity.
    pub fn new(severity: Severity) -> Rule {
        Rule {
            enabled: true,
            severity,
        }
    }

    /// A rule that is off.
    pub fn off() -> Rule {
        Rule {
            enabled: false,
            severity: Severity::Info,
        }
    }
}

/// The watchlist rule: a device that matches a listed MAC, OUI or SSID.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Watchlist {
    /// Whether the rule is on.
    pub enabled: bool,
    /// How serious the alerts it raises are.
    pub severity: Severity,
    /// The MAC addresses to match, in lower case with colons.
    pub macs: Vec<String>,
    /// The OUI prefixes to match, in lower case with colons.
    pub ouis: Vec<String>,
    /// The SSIDs to match, as bytes.
    pub ssids: Vec<Vec<u8>>,
}

impl Watchlist {
    /// True when the address is on the list, or its OUI is.
    pub fn matches_mac(&self, mac: [u8; 6]) -> bool {
        let text = format_mac(mac);
        if self.macs.iter().any(|listed| listed == &text) {
            return true;
        }
        let oui = format_oui(mac);
        self.ouis.iter().any(|listed| listed == &oui)
    }

    /// True when the SSID is on the list.
    ///
    /// The SSID is matched as bytes, because an SSID is not necessarily text.
    pub fn matches_ssid(&self, ssid: &[u8]) -> bool {
        self.ssids.iter().any(|listed| listed.as_slice() == ssid)
    }
}

/// The `seen_again` rule: a device that comes back after an absence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeenAgain {
    /// Whether the rule is on.
    pub enabled: bool,
    /// How serious the alerts it raises are.
    pub severity: Severity,
    /// The absence, in seconds, that has to pass before the rule fires.
    pub after_seconds: u64,
}

/// The `strong_signal` rule: a signal stronger than a threshold.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StrongSignal {
    /// Whether the rule is on.
    pub enabled: bool,
    /// How serious the alerts it raises are.
    pub severity: Severity,
    /// The threshold, in dBm. A signal is stronger than this when it is
    /// greater than it: `-40` is stronger than `-80`.
    pub rssi_above: i8,
}

/// The `deauth_burst` rule: a burst of deauthentication frames about one
/// device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeauthBurst {
    /// Whether the rule is on.
    pub enabled: bool,
    /// How serious the alerts it raises are.
    pub severity: Severity,
    /// How many frames about the same device are needed.
    pub count: u32,
    /// The window, in seconds, the frames have to fall in.
    pub within_seconds: u64,
}

/// The rules, parsed from the configuration.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Rules {
    /// Whether the rules are on at all.
    ///
    /// This is the top level `enabled` flag. When it is false, no rule
    /// fires, whatever the individual rules say.
    pub enabled: bool,
    /// A device seen for the first time.
    pub new_device: Option<Rule>,
    /// A device that matches the watchlist.
    pub watchlist: Option<Watchlist>,
    /// A device that was seen again after an absence.
    pub seen_again: Option<SeenAgain>,
    /// The same SSID on a different access point, or with different security.
    pub rogue_ap: Option<Rule>,
    /// A signal stronger than the threshold.
    pub strong_signal: Option<StrongSignal>,
    /// A burst of deauthentication frames about one device.
    pub deauth_burst: Option<DeauthBurst>,
}

/// Something was wrong with the configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AlertError {
    /// The configuration is not valid TOML, or is of the wrong shape.
    Config(String),
}

impl fmt::Display for AlertError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AlertError::Config(message) => {
                write!(f, "the alert configuration is not valid: {message}")
            }
        }
    }
}

impl std::error::Error for AlertError {}

impl Rules {
    /// Parse the configuration.
    ///
    /// A configuration that cannot be parsed is an error, and the caller
    /// decides what to do about it. An empty configuration means every rule
    /// is off.
    pub fn parse(toml: &str) -> Result<Rules, AlertError> {
        let value: toml::Value =
            ::toml::from_str(toml).map_err(|error| AlertError::Config(error.to_string()))?;

        let table = match value {
            toml::Value::Table(table) => table,
            other => {
                return Err(AlertError::Config(format!(
                    "the configuration must be a table, not {}",
                    kind_of(&other)
                )));
            }
        };

        // The top level `enabled` is a master switch. It is on unless the
        // configuration says otherwise: the rules carry their own `enabled`
        // flags, so a rule that is not wanted is switched off in its own
        // table. A configuration that names no rule at all still has every
        // rule off, because a rule that is not configured is off.
        let mut rules = Rules {
            enabled: bool_field(&table, "enabled")?.unwrap_or(true),
            ..Rules::default()
        };

        if let Some(value) = table.get("new_device") {
            rules.new_device = Some(simple_rule(value, "new_device")?);
        }
        if let Some(value) = table.get("rogue_ap") {
            rules.rogue_ap = Some(simple_rule(value, "rogue_ap")?);
        }
        if let Some(value) = table.get("watchlist") {
            rules.watchlist = Some(watchlist_rule(value)?);
        }
        if let Some(value) = table.get("seen_again") {
            rules.seen_again = Some(seen_again_rule(value)?);
        }
        if let Some(value) = table.get("strong_signal") {
            rules.strong_signal = Some(strong_signal_rule(value)?);
        }
        if let Some(value) = table.get("deauth_burst") {
            rules.deauth_burst = Some(deauth_burst_rule(value)?);
        }

        Ok(rules)
    }

    /// The rules as they were configured, for logging.
    pub fn summary(&self) -> String {
        let mut parts: Vec<String> = Vec::new();
        parts.push(format!("enabled={}", self.enabled));
        if let Some(rule) = &self.new_device {
            parts.push(format!("new_device({})", describe(rule)));
        }
        if let Some(rule) = &self.watchlist {
            parts.push(format!(
                "watchlist({}, {} macs, {} ouis, {} ssids)",
                describe_flag(rule.enabled, rule.severity),
                rule.macs.len(),
                rule.ouis.len(),
                rule.ssids.len()
            ));
        }
        if let Some(rule) = &self.seen_again {
            parts.push(format!(
                "seen_again({}, after {} s)",
                describe_flag(rule.enabled, rule.severity),
                rule.after_seconds
            ));
        }
        if let Some(rule) = &self.rogue_ap {
            parts.push(format!("rogue_ap({})", describe(rule)));
        }
        if let Some(rule) = &self.strong_signal {
            parts.push(format!(
                "strong_signal({}, above {} dBm)",
                describe_flag(rule.enabled, rule.severity),
                rule.rssi_above
            ));
        }
        if let Some(rule) = &self.deauth_burst {
            parts.push(format!(
                "deauth_burst({}, {} in {} s)",
                describe_flag(rule.enabled, rule.severity),
                rule.count,
                rule.within_seconds
            ));
        }
        parts.join(", ")
    }
}

/// A MAC address in the form the database stores it: lower case, colons.
pub fn format_mac(mac: [u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

/// The OUI of a MAC address, in the same form.
pub fn format_oui(mac: [u8; 6]) -> String {
    format!("{:02x}:{:02x}:{:02x}", mac[0], mac[1], mac[2])
}

/// The name of the type of a TOML value, for an error message.
fn kind_of(value: &toml::Value) -> &'static str {
    match value {
        toml::Value::String(_) => "a string",
        toml::Value::Integer(_) => "an integer",
        toml::Value::Float(_) => "a float",
        toml::Value::Boolean(_) => "a boolean",
        toml::Value::Datetime(_) => "a datetime",
        toml::Value::Array(_) => "an array",
        toml::Value::Table(_) => "a table",
    }
}

/// Read a boolean field, if it is there.
fn bool_field(table: &toml::Table, name: &str) -> Result<Option<bool>, AlertError> {
    match table.get(name) {
        None => Ok(None),
        Some(toml::Value::Boolean(value)) => Ok(Some(*value)),
        Some(other) => Err(AlertError::Config(format!(
            "{name} must be a boolean, not {}",
            kind_of(other)
        ))),
    }
}

/// Read an integer field, if it is there.
fn integer_field(table: &toml::Table, name: &str) -> Result<Option<i64>, AlertError> {
    match table.get(name) {
        None => Ok(None),
        Some(toml::Value::Integer(value)) => Ok(Some(*value)),
        Some(other) => Err(AlertError::Config(format!(
            "{name} must be an integer, not {}",
            kind_of(other)
        ))),
    }
}

/// Read a string field, if it is there.
fn string_field(table: &toml::Table, name: &str) -> Result<Option<String>, AlertError> {
    match table.get(name) {
        None => Ok(None),
        Some(toml::Value::String(value)) => Ok(Some(value.clone())),
        Some(other) => Err(AlertError::Config(format!(
            "{name} must be a string, not {}",
            kind_of(other)
        ))),
    }
}

/// Read a list of strings, if it is there.
fn string_list_field(table: &toml::Table, name: &str) -> Result<Vec<String>, AlertError> {
    match table.get(name) {
        None => Ok(Vec::new()),
        Some(toml::Value::Array(items)) => {
            let mut values = Vec::with_capacity(items.len());
            for item in items {
                match item {
                    toml::Value::String(value) => values.push(value.clone()),
                    other => {
                        return Err(AlertError::Config(format!(
                            "every entry of {name} must be a string, not {}",
                            kind_of(other)
                        )));
                    }
                }
            }
            Ok(values)
        }
        Some(other) => Err(AlertError::Config(format!(
            "{name} must be an array of strings, not {}",
            kind_of(other)
        ))),
    }
}

/// The table of a rule, or an error.
fn rule_table<'a>(value: &'a toml::Value, name: &str) -> Result<&'a toml::Table, AlertError> {
    match value {
        toml::Value::Table(table) => Ok(table),
        other => Err(AlertError::Config(format!(
            "{name} must be a table, not {}",
            kind_of(other)
        ))),
    }
}

/// The severity of a rule table, or an error.
fn severity_field(table: &toml::Table, name: &str) -> Result<Severity, AlertError> {
    let text = string_field(table, "severity")?
        .ok_or_else(|| AlertError::Config(format!("{name} must have a severity")))?;
    Severity::parse(&text).ok_or_else(|| {
        AlertError::Config(format!(
            "{name} has the unknown severity {text:?}; it must be info, warning or critical"
        ))
    })
}

/// Parse a rule that takes nothing but `enabled` and `severity`.
fn simple_rule(value: &toml::Value, name: &str) -> Result<Rule, AlertError> {
    let table = rule_table(value, name)?;
    Ok(Rule {
        enabled: bool_field(table, "enabled")?.unwrap_or(true),
        severity: severity_field(table, name)?,
    })
}

/// Parse the watchlist rule.
fn watchlist_rule(value: &toml::Value) -> Result<Watchlist, AlertError> {
    let table = rule_table(value, "watchlist")?;
    Ok(Watchlist {
        enabled: bool_field(table, "enabled")?.unwrap_or(true),
        severity: severity_field(table, "watchlist")?,
        macs: string_list_field(table, "macs")?
            .iter()
            .map(|mac| mac.to_lowercase())
            .collect(),
        ouis: string_list_field(table, "ouis")?
            .iter()
            .map(|oui| oui.to_lowercase())
            .collect(),
        ssids: string_list_field(table, "ssids")?
            .iter()
            .map(|ssid| ssid.as_bytes().to_vec())
            .collect(),
    })
}

/// Parse the `seen_again` rule.
fn seen_again_rule(value: &toml::Value) -> Result<SeenAgain, AlertError> {
    let table = rule_table(value, "seen_again")?;
    let after_seconds = integer_field(table, "after_seconds")?
        .ok_or_else(|| AlertError::Config("seen_again must have after_seconds".to_string()))?;
    Ok(SeenAgain {
        enabled: bool_field(table, "enabled")?.unwrap_or(true),
        severity: severity_field(table, "seen_again")?,
        after_seconds: u64::try_from(after_seconds).map_err(|_| {
            AlertError::Config("seen_again.after_seconds must not be negative".to_string())
        })?,
    })
}

/// Parse the `strong_signal` rule.
fn strong_signal_rule(value: &toml::Value) -> Result<StrongSignal, AlertError> {
    let table = rule_table(value, "strong_signal")?;
    let rssi_above = integer_field(table, "rssi_above")?
        .ok_or_else(|| AlertError::Config("strong_signal must have rssi_above".to_string()))?;
    Ok(StrongSignal {
        enabled: bool_field(table, "enabled")?.unwrap_or(true),
        severity: severity_field(table, "strong_signal")?,
        rssi_above: i8::try_from(rssi_above).map_err(|_| {
            AlertError::Config("strong_signal.rssi_above must fit in a byte".to_string())
        })?,
    })
}

/// Parse the `deauth_burst` rule.
fn deauth_burst_rule(value: &toml::Value) -> Result<DeauthBurst, AlertError> {
    let table = rule_table(value, "deauth_burst")?;
    let count = integer_field(table, "count")?
        .ok_or_else(|| AlertError::Config("deauth_burst must have count".to_string()))?;
    let within_seconds = integer_field(table, "within_seconds")?
        .ok_or_else(|| AlertError::Config("deauth_burst must have within_seconds".to_string()))?;
    Ok(DeauthBurst {
        enabled: bool_field(table, "enabled")?.unwrap_or(true),
        severity: severity_field(table, "deauth_burst")?,
        count: u32::try_from(count).map_err(|_| {
            AlertError::Config("deauth_burst.count must not be negative".to_string())
        })?,
        within_seconds: u64::try_from(within_seconds).map_err(|_| {
            AlertError::Config("deauth_burst.within_seconds must not be negative".to_string())
        })?,
    })
}

/// Describe a simple rule for the summary.
fn describe(rule: &Rule) -> String {
    describe_flag(rule.enabled, rule.severity)
}

/// Describe an enabled flag and a severity for the summary.
fn describe_flag(enabled: bool, severity: Severity) -> String {
    if enabled {
        severity.as_str().to_string()
    } else {
        format!("off, {}", severity.as_str())
    }
}
