# Query API v0 (read-only JSON-RPC 2.0)

Transport: the `/tmp/od3sa-recon/query.sock` Unix socket, with optional HTTP `POST /rpc` on 127.0.0.1. Every request carries a `token`. All methods are **read-only**.

| Method | Params | Returns |
|---|---|---|
| `status` | – | `{version, api, uptime_s, sources[], counts{devices,aps,clients,ble}, db_bytes, rss_kb}` |
| `devices.list` | `{kind?, since_ms?, oui?, min_rssi?, limit≤500, cursor?}` | `{items[], next_cursor}` |
| `devices.get` | `{mac}` | device + AP/BLE detail + recent sightings |
| `aps.list` | `{ssid?, band?, security?, since_ms?, limit, cursor?}` | `{items[], next_cursor}` |
| `clients.list` | `{bssid?, since_ms?, limit, cursor?}` | ... |
| `probes.list` | `{client?, ssid?, since_ms?, limit, cursor?}` | ... |
| `ble.list` | `{since_ms?, name?, limit, cursor?}` | ... |
| `sightings.list` | `{mac?, from_ms, to_ms, limit, cursor?}` | buckets with optional GPS |
| `alerts.list` | `{since_ms?, rule?, severity?, limit, cursor?}` | ... |
| `sources.list` | – | sources and status |

Example:
```json
{"jsonrpc":"2.0","id":1,"method":"aps.list","params":{"band":"5","limit":50,"token":"<token>"}}
```
There are deliberately **no** methods for config writes, radios, channels or services. Alert rules and watchlists are edited in the config file by the owner, not through the plugin API.
