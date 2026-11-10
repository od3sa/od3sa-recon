# Plugin system (API v0)

Plugins run **out of process**, can be written in any language, and get
data in two ways:

1. **Event bus:** `/tmp/od3sa-recon/events.sock` (Unix stream socket). Each
   line is a JSON event (NDJSON). See `api/events.md`.
2. **Query API:** `/tmp/od3sa-recon/query.sock`, JSON-RPC 2.0, read-only
   methods with filters and cursor pagination. See `api/query.md`.

The API has **no call that touches a radio, a service or a channel**. A
plugin cannot change a channel, restart `pineapd`, or transmit. What a
plugin *can* do is what its manifest asks for: read the events and the
queries it was scoped to, write under the paths it declared, and open
sockets if it declared that it would. The host enforces the scope of the
token; it does not sandbox the plugin's filesystem or its network, and the
docs say so rather than implying otherwise.

## Manifest (`plugin.toml`)

```toml
name = "wigle-export"
version = "0.1.0"
api = 0                         # major API version (a number, not a string)
exec = "bin/wigle-export"       # relative to the plugin dir
run = "external"                # "daemon" (supervised by od3sa-recond) | "external" (run independently)
capabilities = ["query:aps.list", "query:sightings.list", "fs:write:/mmc/od3sa-recon/export"]
memory_mb = 8                   # budget; the host kills the plugin above 1.5x
network = false                 # true only for feed plugins
```

- **Capabilities** are allowlists for event topics, query methods,
  filesystem write paths and network. The host enforces them on the
  sockets by filtering topics and methods per authenticated plugin token.
- **Every capability is one the host knows.** A capability that does not
  exist is an error, and the plugin is not started. A manifest that is not
  valid TOML is the same: it is refused with a log line, and the plugin
  never starts.
- **The query capability names a real method.** The daemon's methods are
  `status`, `devices.list`, `devices.get`, `aps.list`, `clients.list`,
  `probes.list`, `ble.list`, `sightings.list`, `alerts.list` and
  `sources.list`; `query:devices` would never authorise a `devices.list`
  call.
- **`api` is a number.** The manifest parser wants `api = 0`, not
  `api = "0"`.
- **The write path is a capability**, not a field of its own:
  `fs:write:/mmc/od3sa-recon/export`.
- There are **no capabilities** for radios, channel, TX, or
  pineapd/blue5 control. They don't exist.

## Lifecycle
- Plugins live in `/mmc/od3sa-recon/plugins/<name>/`.
- The host reads the manifests, then starts `run="daemon"` plugins with
  env `OD3SA_EVENTS`, `OD3SA_QUERY` and `OD3SA_TOKEN`. It restarts them
  with backoff and stops them on daemon stop.
- `external` plugins are run by hand and connect themselves. They need a
  token of their own, which the daemon prints at start-up.
- Health: the host sends `ping` and the plugin answers with `pong`.
  Plugin stdout/stderr go to logread.

## The token

Every plugin gets **its own** token, scoped to the capabilities its
manifest asked for. The secret is what goes into `OD3SA_TOKEN`; the
scopes are what the secret stands for. Two plugins never share one, so a
plugin that gets hold of another's token learns nothing with it.

The daemon generates the tokens at start-up and **prints them once**, in
the log and on stdout:

```
plugin token: pager-ui: <secret>
```

The token is not written to the database and not written to a file that
persists. It is in the log, so treat the log as sensitive.

To run an external plugin by hand:

```sh
export OD3SA_QUERY=/tmp/od3sa-recon/query.sock
export OD3SA_TOKEN=<the secret from the log>
```

## Budget
Total plugin RSS is capped at **20 MB by default**, configurable. The
daemon plus all plugins must stay comfortably inside the roughly 104 MB
that's free.

## First-party plugins
| Plugin | Purpose | Default |
|---|---|---|
| `pager-ui` | Pager payload: status, counts, top devices, alerts via `LOG` / `ALERT` | on demand |
| `ndjson-export` | JSON/NDJSON export of devices, sightings and alerts | on demand |
| `wigle-export` | WiGLE CSV for Wi-Fi APs (+ BLE) with GPS | on demand |
| `pcapng-meta` | pcapng with **headers only** (truncated, no payloads, no EAPOL) | **off** |
| `kismet-feed` | Writes the netspot files a Kismet server reads | off |

All five are `run = "external"`: the operator starts them, and the daemon
supervises the ones that ask to be supervised.

## Versioning
- API major `0` is unstable: it changes as the project finds what it
  needs.
- Breaking changes bump the major version. Events carry `"v": 0`.
- Schemas live in `docs/api/`.
