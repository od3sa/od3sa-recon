# Query API contract

The contract the read-only JSON-RPC query socket is written against. It
extends `docs/api/query.md`, which lists the methods; this document gives the
exact wire shapes.

## Where it lives

In the daemon crate, `crates/od3sa-recond/src/query.rs`. The daemon serves the
socket; the query code is a library type the daemon owns. It reads through
`od3sa-store`'s `Store::query`, and it **never writes**.

## Transport

A Unix stream socket at `/tmp/od3sa-recon/query.sock`. One JSON-RPC 2.0
request per line, one response per line, in NDJSON. The socket is created by
the daemon at start-up; a stale socket file from a previous run is removed
first.

## The request

```json
{"jsonrpc":"2.0","id":1,"method":"devices.list","params":{"limit":50,"token":"<token>"}}
```

- `id` is any JSON value; the response carries the same one back. A request
  without an `id` is a notification and gets no response.
- `params` is an object. Unknown keys are ignored, missing keys take their
  defaults.
- `token` must be in `params`. A request without a valid token is refused.

## The response

```json
{"jsonrpc":"2.0","id":1,"result":{"items":[...],"next_cursor":null}}
```

or

```json
{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"no such method"}}
```

Error codes: `-32700` for a line that is not JSON, `-32600` for a request
that is not JSON-RPC 2.0, `-32601` for an unknown method, `-32602` for bad
parameters, `-32000` for a database error, and `-32001` for a bad or missing
token.

## The methods

Every method is read-only. There is no method that writes, and there is no
method that touches a radio, a channel or a service.

### `status`

No parameters beyond the token.

```json
{"version":"0.1.0","api":0,"uptime_s":1234,"sources":[{"name":"pcap:wlan1mon","kind":"pcap","status":"running","frames":12345,"errors":0}],"counts":{"devices":42,"aps":7,"clients":30,"ble":0},"db_bytes":1048576,"rss_kb":4096}
```

### `devices.list`

Parameters: `kind`, `since_ms`, `oui`, `min_rssi`, `limit` (at most 500,
default 100), `cursor`.

```json
{"items":[{"mac":"00:11:22:33:44:01","kind":"ap","oui":"00:11:22","randomized":false,"first_seen_ms":1762300000000,"last_seen_ms":1762300060000,"max_rssi":-42,"last_rssi":-55}],"next_cursor":null}
```

### `devices.get`

Parameters: `mac`.

```json
{"device":{...as above...},"access_point":{...},"ble":null,"sightings":[{"ts_ms":1762300060000,"bucket_ms":1762300060000,"n":3,"rssi_min":-60,"rssi_max":-42,"rssi_avg":-51.0,"channel":36,"lat":null,"lon":null,"alt":null,"fix":null}]}
```

### `aps.list`

Parameters: `ssid`, `band`, `security`, `since_ms`, `limit`, `cursor`.

```json
{"items":[{"bssid":"00:11:22:33:44:01","ssid":"example-ssid","ssid_hidden":false,"channel":36,"freq_mhz":5180,"band":"5","security":"WPA2-PSK","akm":"PSK","pairwise":"CCMP","group_cipher":"CCMP","pmf_required":false,"wps":false,"ht":true,"vht":true,"he":false,"vendor_ies":null,"beacon_int":100,"last_beacon_ms":1762300060000}],"next_cursor":null}
```

### `clients.list`

Parameters: `bssid`, `since_ms`, `limit`, `cursor`.

```json
{"items":[{"client":"00:11:22:33:44:02","bssid":"00:11:22:33:44:01","first_seen_ms":1762300000000,"last_seen_ms":1762300060000}],"next_cursor":null}
```

### `probes.list`

Parameters: `client`, `ssid`, `since_ms`, `limit`, `cursor`.

```json
{"items":[{"client":"00:11:22:33:44:02","ssid":"example-ssid","first_seen_ms":1762300000000,"last_seen_ms":1762300060000,"count":3}],"next_cursor":null}
```

### `ble.list`

Parameters: `since_ms`, `name`, `limit`, `cursor`. Empty until the blue5
ingest lands.

### `sightings.list`

Parameters: `mac`, `from_ms`, `to_ms`, `limit`, `cursor`.

```json
{"items":[{"device_id":1,"source_id":1,"bucket_ms":1762300060000,"n":3,"rssi_min":-60,"rssi_max":-42,"rssi_avg":-51.0,"channel":36,"lat":null,"lon":null,"alt":null,"fix":null}],"next_cursor":null}
```

### `alerts.list`

Parameters: `since_ms`, `rule`, `severity`, `limit`, `cursor`.

```json
{"items":[{"id":1,"ts_ms":1762300060000,"rule":"new_device","severity":"info","device_id":1,"summary":"example-ssid","details":null}],"next_cursor":null}
```

### `sources.list`

```json
{"items":[{"name":"pcap:wlan1mon","kind":"pcap","iface":"wlan1mon","status":"running","last_seen_ms":1762300060000,"frames":12345,"errors":0}],"next_cursor":null}
```

## The shapes that need saying twice

- **A MAC address is a string** `aa:bb:cc:dd:ee:ff`, lower case. The schema
  stores it that way.
- **An SSID is a string**, decoded as UTF-8 with the replacement character
  for anything that is not valid UTF-8. The schema stores the raw bytes as a
  BLOB, and the query layer decodes them.
- **A null means "not known"**, not zero and not an empty string. A device
  with no signal level has `max_rssi: null`.
- **Times are unix epoch milliseconds**, as in the schema.
- **A BLOB that is not text** (an SSID that is not valid UTF-8) is decoded
  with the replacement character, never dropped.

## Pagination

`limit` at most 500. `next_cursor` is an opaque string, or `null` when there
are no more rows. The cursor is the `last_seen_ms` (or the row's id) of the
last row returned, encoded so that the caller cannot change its meaning. A
cursor from another method is an error.

## The token

Every request carries `token` in its parameters. The daemon holds one token,
generated at start-up and written to the log once (never to the database, and
never to a file that persists). A request without the token, or with the
wrong one, is refused with `-32001` and no data.

The token is what the plugin host extends: each plugin gets
its own token, and the query server filters what it may see. For now there is
one token and everything it can reach.

## The rules the query socket follows

- **Read-only.** Every query is a `SELECT`. There is no method that writes,
  and no method that takes a SQL string from the caller.
- **The token is checked before the method**, so an unauthenticated caller
  cannot learn which methods exist by probing them.
- **A database error is an error response**, not a crash and not an empty
  result that looks like "no devices".
- **One bad line does not kill the connection.** A line that is not JSON gets
  an error response and the socket stays open.
- **The socket is read-only in the sense that matters**: it cannot change a
  channel, a mode, a service or the database.

## Tests

1. Every method answers with the shape above, against a database with
   synthetic rows in it.
2. An unknown method is `-32601`; a malformed line is `-32700`; a request
   without a token is `-32001`.
3. **No method writes:** after every method has been called against a
   populated database, the database's contents are unchanged.
4. Pagination: with more rows than the limit, `next_cursor` is not null, and
   following it walks the rest without repeats or gaps.
5. A line that is not JSON gets an error and the connection stays open.
6. The request and the response are one line each, so a client can read them
   with a line-oriented reader.

Use `od3sa-store`'s `Store` to build the database for the tests, with
synthetic rows — no real MACs, no real SSIDs.

## Constraints

- The only dependency is `serde_json` (MIT OR Apache-2.0), and
  `od3sa-store`. A new dependency has to be MIT-compatible.
- No `unwrap` or `expect` outside the tests.
- No real data.
- Every method is a `SELECT` with bound parameters. There is no call that
  changes the database, and none may be added.
