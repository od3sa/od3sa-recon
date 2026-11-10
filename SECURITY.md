# Security policy

## What this project is

`od3sa-recon` is a **passive, listen-only** radio metadata collector for the
WiFi Pineapple Pager. It reads frames from a monitor interface that another
service already owns, stores metadata, and hands the data to plugins.

It does not transmit. The capture crate does not declare libpcap's transmit
functions (`pcap_inject`, `pcap_sendpacket`), so there is no call site to
review — that holds whatever the toolchain does. The build also strips
those symbols out of the linked archive where the target's `objcopy` is
available, so the shipped binary usually has no transmit entry point at
all.

## Reporting a vulnerability

Report it privately through GitHub's **Security Advisories** on this
repository: *Security → Report a vulnerability*. Do not open a public issue
for a security report.

Please include:

- what the issue is, and which component it is in (the capture crate, the
  plugin host, the query socket, the event bus, the store, a plugin);
- how to reproduce it — the command, the config, and what you saw;
- what an attacker gains.

You can expect an acknowledgement within a few days. If the report is
accepted, a fix goes into a branch and a pull request, and you are credited
in the advisory unless you would rather not be.

## What counts as a vulnerability here

These are the things that would matter for a tool whose whole promise is
that it is passive and read-only:

- **Transmitting anything.** Any path that sends a frame, a probe, a beacon,
  a deauthentication or a disassociation frame, on any interface, ever.
- **Changing a radio.** Setting a channel, a mode, a power level, or
  bringing an interface up or down.
- **Touching `pineapd` or `blue5`.** Stopping, restarting, reconfiguring, or
  writing to their sockets.
- **Opening `hci0`.** Any active Bluetooth operation — inquiry, scan
  requests, connections.
- **Storing a payload.** A frame body, an EAPOL body or any other payload
  reaching the database or an export file, when it should not.
- **Escaping a capability.** A plugin reaching a query method, an event
  topic, a filesystem path or a network destination that its manifest does
  not declare.
- **Reading another plugin's data.** A plugin using another plugin's token,
  or getting past the token check at all.

## What is not a vulnerability

- **Metadata about nearby networks is the point.** Seeing an SSID, a BSSID
  or a channel is what the tool does. If you can see it on your own
  equipment, you can see it here.
- **The tools it ships with are read-only by design.** The ingest adapters
  read files another program wrote. The exports write files. Neither
  changes anything they read.
- **Running a plugin is your decision.** Plugins are third-party programs
  with the capabilities their manifest declares. The host enforces the
  manifest; it cannot vouch for what a plugin does inside its own process.
- **Physical access to the Pager.** Whoever holds the device can read the
  database, the logs and the configuration directly.

## Responsible use

Observing radio metadata is still observing other people's networks. Only
run this on equipment you own or on a network where you have the owner's
permission to do so, and follow the laws that apply where you are.

The database holds identifiers of networks and devices that are not yours.
Treat it as the sensitive material it is: keep it on the SD card, do not
publish it, and delete it when you are done with it. The retention rules in
the configuration bound how long it grows, but they do not decide for you
whether to keep it at all.

## Out of scope

- Vulnerabilities in the OpenWrt firmware, in `pineapd`, in `blue5` or in
  any other component of the Pager's own software. Report those to their
  maintainers.
- Vulnerabilities in Rust, in `libpcap`, in `SQLite` or in any other
  dependency. Report those upstream. `cargo deny check advisories` runs in
  CI against the RustSec database, which is where such a report belongs.
- Physical attacks on the device.
