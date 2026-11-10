# Alerts engine contract

The contract for the awareness alert rules. DESIGN.md lists the rules:

- new device
- watchlist match (MAC, OUI or SSID)
- device seen again after an absence
- **rogue AP**: same SSID, different BSSID or security
- signal threshold (RSSI above X)
- deauth/disassoc burst observed

The rules are configured in TOML, written to the `alerts` table, and emitted
as `alert.raised` events.

**These are awareness rules.** They describe what was seen. Nothing in this
crate acts on an alert, and nothing here transmits anything.

## Where it lives

`crates/od3sa-alerts`, its own crate. It reads what the aggregator produced —
so it depends on `od3sa-store` for the types — and it never touches the
database itself.

## The configuration

```toml
# The rules that are on.
enabled = true

# A device seen for the first time.
new_device = { enabled = true, severity = "info" }

# A device that matches the watchlist.
watchlist = {
    enabled = true,
    severity = "warning",
    macs = ["00:11:22:33:44:ff"],
    ouis = ["00:11:22"],
    ssids = ["example-ssid"],
}

# A device that was seen again after an absence.
seen_again = { enabled = true, severity = "info", after_seconds = 300 }

# The same SSID on a different access point, or with different security.
rogue_ap = { enabled = true, severity = "warning" }

# A signal stronger than the threshold.
strong_signal = { enabled = true, severity = "info", rssi_above = -40 }

# Deauthentication or disassociation frames about one device.
deauth_burst = { enabled = true, severity = "warning", count = 5, within_seconds = 10 }
```

Every rule has an `enabled` flag and a `severity`: `info`, `warning` or
`critical`. A rule that is not configured is off.

## The API

```rust
/// How serious an alert is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Info,
    Warning,
    Critical,
}

/// One alert.
#[derive(Debug, Clone, PartialEq)]
pub struct Alert {
    /// Which rule raised it.
    pub rule: String,
    /// How serious it is.
    pub severity: Severity,
    /// The device it is about, when it is about one.
    pub mac: Option<[u8; 6]>,
    /// A short line for a human.
    pub summary: String,
    /// Anything else worth keeping, as JSON.
    pub details: serde_json::Value,
}

/// The rules, parsed from the configuration.
#[derive(Debug, Clone, Default)]
pub struct Rules {
    /* the configured rules */
}

impl Rules {
    /// Parse the configuration.
    ///
    /// A configuration that cannot be parsed is an error, and the caller
    /// decides what to do about it. An empty configuration means every rule
    /// is off.
    pub fn parse(toml: &str) -> Result<Rules, AlertError>;

    /// The rules as they were configured, for logging.
    pub fn summary(&self) -> String;
}

/// The engine: it watches what the aggregator produces and raises alerts.
pub struct AlertEngine {
    /* the rules and the state they need */
}

impl AlertEngine {
    /// An engine with the given rules.
    pub fn new(rules: Rules) -> AlertEngine;

    /// Feed one observation in, and get the alerts it raised.
    ///
    /// The engine keeps the state the rules need — which devices it has seen,
    /// which SSIDs it has seen on which access points, and how many
    /// deauthentication frames it has seen about each device recently.
    pub fn observe(&mut self, observation: &Observation, now_ms: i64) -> Vec<Alert>;
}
```

## The rules, in detail

**`new_device`** — the observation names a device the engine has not seen
before. Raised once per device.

**`watchlist`** — the device's MAC matches a listed MAC, or its OUI matches a
listed OUI, or the access point's SSID matches a listed SSID. The MAC and
the OUI are matched in lower case, with the colons as the MAC is stored
(`aa:bb:cc:dd:ee:ff`); the SSID is matched exactly, as bytes, because an
SSID is not necessarily text.

**`seen_again`** — the device was seen before, and the time since it was last
seen is at least `after_seconds`. This is the "it came back" rule, which is
what a watchlist is usually for.

**`rogue_ap`** — an access point with an SSID that has been seen before, on a
**different BSSID**, or with **different security**. The engine remembers the
SSID it has seen and the BSSID and the security it was seen with. This is the
rule that catches a second access point claiming a name it does not own.

**`strong_signal`** — the signal level is stronger than `rssi_above`. A
stronger signal is closer to zero, so `-40` is stronger than `-80`.

**`deauth_burst`** — `count` or more deauthentication or disassociation
frames about the same device within `within_seconds`. The engine counts them
per device and forgets the old ones.

## The rules the engine follows

- **An alert is raised once, not on every frame.** The engine keeps the state
  it needs to know whether it has already said it: the devices it has seen,
  the access points it has seen, and the recent deauthentication counts.
- **The engine's state is bounded.** It keeps a table of devices and a table
  of access points, both capped, so a long run on a busy channel cannot grow
  without limit. The oldest entries are dropped.
- **The engine does not write to the database.** It returns the alerts; the
  caller writes them to the `alerts` table and publishes them as
  `alert.raised`.
- **The engine never touches a radio**, and it never acts on an alert. These
  are descriptions of what was seen.
- **A rule that is off raises nothing**, and a rule that is not configured at
  all is off.

## The tests

1. `new_device` raises once for a device the engine has not seen, and not
   again for the same device.
2. `watchlist` raises for a listed MAC, for a listed OUI and for a listed
   SSID, and not for anything else.
3. `seen_again` raises when the device comes back after the configured
   absence, and not before it.
4. **`rogue_ap` raises for the same SSID on a different BSSID**, and for the
   same SSID with different security, and **does not raise for the same SSID
   on the same BSSID with the same security**.
5. `strong_signal` raises for a signal stronger than the threshold and not
   for a weaker one.
6. `deauth_burst` raises when the count is reached inside the window and not
   when the frames are spread further apart in time.
7. A rule that is disabled raises nothing.
8. A configuration that cannot be parsed is an error.
9. **The engine's tables are bounded:** more devices than the cap leaves the
   table at the cap.
10. An alert carries the rule, the severity, the MAC when there is one, a
    summary a human can read, and the details as JSON.

Build the observations with the aggregator from `od3sa-store` and the frames
from `od3sa-fixtures`.

## Constraints

- The dependencies are `od3sa-store` (first-party) and `toml`
  (MIT OR Apache-2.0). `serde_json` comes through `od3sa-store`'s
  re-export. A new dependency has to be MIT-compatible.
- No `unwrap` or `expect` outside the tests.
- No real data: the tests use the synthetic address family and `example-*`
  names.
- The rules are awareness-only. Nothing that touches a radio.
