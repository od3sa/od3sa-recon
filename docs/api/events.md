# Events v0 (NDJSON over a Unix socket)

Envelope: `{"v":0,"type":"<topic>","ts_ms":<int>,"seq":<int>,"data":{...}}`

Subscribe by sending one line after connecting:
```json
{"op":"subscribe","token":"<token>","topics":["ap.*","alert.raised"]}
```

| Topic | data |
|---|---|
| `device.new` | `{mac, kind, oui, randomized, rssi, channel, source}` |
| `ap.new` | `{bssid, ssid, channel, freq_mhz, security, wps, rssi}` |
| `client.assoc` | `{client, bssid, rssi}` |
| `probe.seen` | `{client, ssid, rssi}` (deduplicated per minute) |
| `alert.raised` | `{id, rule, severity, mac, summary}` |

These five are what the collector publishes today. Three more topics are
planned and are **not** published yet, so a subscriber should not wait for
them:

| Topic | Status |
|---|---|
| `device.updated` | planned: a device seen again with different fields |
| `ble.seen` | planned: it needs the blue5 ingest adapter, which is not wired into the daemon yet |
| `source.status` | planned: the state of each capture source |

Example (dummy):
```json
{"v":0,"type":"ap.new","ts_ms":1762300000000,"seq":42,"data":{"bssid":"00:11:22:33:44:01","ssid":"example-ssid","channel":36,"freq_mhz":5180,"security":"WPA2-PSK","wps":false,"rssi":-61}}
```
Backpressure: each subscriber has a bounded queue. If it overflows, events are dropped and `{"type":"bus.dropped","data":{"n":N}}` is sent.
