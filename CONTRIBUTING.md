# Contributing

Thanks for looking at it. This is a small project with a narrow purpose, and
the guardrails below are not stylistic preferences — they are what makes it
worth running.

## The one thing that matters most

**This project must never transmit.** Not a beacon, not a probe, not a
deauthentication, not a test frame. It reads a monitor interface that another
service already owns, and it does nothing else to the radio.

If you are about to add code that writes to an interface, changes a channel
or a mode, brings an interface up or down, or touches `hci0`, stop. That is
not a contribution this project can accept, and the guardrails are enforced
in the code as well as described here:

- the capture crate declares no libpcap transmit function, so there is no
  call site to review;
- the build strips `pcap_inject` and `pcap_sendpacket` out of the linked
  archive where the target's `objcopy` is available, so the shipped binary
  usually has no transmit entry point at all;
- the plugin API has no call that touches a radio.

The same applies to the other services on the device: **never stop, restart
or reconfigure `pineapd` or `blue5`.** They respawn anyway, and stopping
them is not this project's business.

## Other rules

- **Metadata only.** No frame body and no EAPOL body is stored. The
  database has nowhere to put one.
- **No real data in the repository.** No captures, no real MAC addresses, no
  real SSIDs, no Bluetooth addresses, no GPS tracks. The test fixtures are
  synthetic: `00:11:22:33:44:xx`, `example-ssid`. A pcap that a device
  produced does not go in a commit, in a pull request or in an issue.
- **No offensive tooling.** Defensive and awareness use only.
- **MIT.** Every crate and every `Cargo.toml` sets `license = "MIT"`.
  Dependencies must be MIT-compatible. `cargo deny check licenses` enforces
  this in CI — if your dependency is not on the allow list, the check fails
  and asks, rather than merging quietly.
- **No secrets.** No passwords, no SSH keys, no tokens.

## Building and testing

On an x86 Linux machine:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --all-targets
```

The capture crate links against `libpcap`, so the test binaries need it:
`sudo apt-get install libpcap-dev`.

The device build is a separate route, because `mipsel-unknown-linux-musl`
is a Tier 3 target with no prebuilt standard library:

```sh
build/build-mipsel.sh    # the daemon and the plugins, for the device
build/build-ipk.sh       # the opkg package
```

That needs the OpenWrt 24.10.1 SDK, which the script fetches if it is not
already on the machine. Expect the first run to take a while.

The fuzz targets need `cargo-fuzz`:

```sh
cargo fuzz run frame
```

## Style

The code follows what `rustfmt` and `clippy` want — run both before you
push. Beyond that:

- the workspace lints deny `unwrap` and `expect` outside tests: a parser
  bug must not take the collector down, so the code handles the error
  instead of asserting;
- every public item is documented, because `missing_docs` is warned;
- comments explain **why**, not what. The code already says what it does.

## Tests

A parser change needs a test that proves two things: the parser does not
panic on malformed input, and no payload or EAPOL body is retained. A
distinctive marker in the payload must not appear in the parsed result.

New behaviour needs a test that fails without your change. Tests use
synthetic fixtures only.

## Pull requests

1. Branch from `main`: `your-name/what-you-did`.
2. Make the change, with tests, and make sure `cargo fmt`, `cargo clippy`
   and `cargo test` all pass.
3. Open a pull request describing what changed and why.

If your change touches the capture path, the plugin host or anything that
could reach a radio, say so in the description. That is the part a reviewer
has to look at most carefully.

## Licence

By contributing, you agree that your contribution is licensed under the
MIT licence, like the rest of the project.
