# Fuzz targets for the od3sa-recon parsers

cargo-fuzz targets for the metadata parsers in `crates/od3sa-parse`. They
exist to prove one property above all others: **the parsers never panic**. A
malformed frame must be an error, never a crash, because a crash in the
collector on the Pager takes the whole recon down.

The fuzz crate is **not** a member of the workspace at the repository root.
It has its own `[workspace]` table, its own `Cargo.lock` and its own build
profile, so `cargo build` at the root never touches it and the nightly
toolchain it needs never leaks into the daemon build.

## What the targets cover

| Target | What it drives | What it asserts |
|---|---|---|
| `fuzz_targets/radiotap.rs` | `radiotap::parse` | `it_len` covers the 8-byte preamble and fits the buffer; the version and the present mask are the preamble bytes; a field is reported exactly when the present mask names it; `channel_number` never returns zero. |
| `fuzz_targets/ieee80211.rs` | `MacHeader::parse`, `ControlHeader::parse` | the address-4 field is present exactly for a data frame with both distribution-system bits set; the type, subtype, protocol version and the To DS / From DS / Protected flags agree with the raw frame control word. |
| `fuzz_targets/ie.rs` | `ie::parse_ies`, `ie::summarize` | the elements cover the buffer exactly; the SSID is the first SSID element and is hidden when empty; the vendor list holds the OUI and type of every vendor element long enough to have both; an RSN element wins over a WPA1 one. The summary is also driven over elements whose bodies are cut short at an arbitrary point, so the RSN and WPA suite lists are read from bodies that end in the middle of a suite. |
| `fuzz_targets/frame.rs` | `frame::dispatch`, `frame::classify_body` | the class of a frame agrees with the frame type in its frame control word; a body is EAPOL exactly when it starts with an LLC/SNAP header carrying the EAPOL EtherType; the address mapping follows the two distribution-system bits. |
| `fuzz_targets/capture.rs` | `radiotap::parse` + `frame::dispatch` + `frame::dispatch_capture` | the radiotap header length is sane; the one-call capture path and the two-step path agree on the frame they see. |

A violated invariant is a `panic!`, and a panic fails the target. So do an
abort, an out-of-bounds read (the sanitizer catches it) and a run that takes
unreasonably long.

## Running them

The fuzz targets need the nightly toolchain and the sanitizer runtime:

```
export PATH="$HOME/.cargo/bin:$PATH"
cd /path/to/od3sa-recon

cargo +nightly fuzz run radiotap  -- -max_total_time=60
cargo +nightly fuzz run ieee80211 -- -max_total_time=60
cargo +nightly fuzz run ie        -- -max_total_time=60
cargo +nightly fuzz run frame     -- -max_total_time=60
cargo +nightly fuzz run capture   -- -max_total_time=60
```

`-max_total_time=60` runs each target for a minute. Drop it to run until a
crash is found.

libFuzzer's own limits do the rest of the work: a run that takes
unreasonably long trips `-timeout` (1200 s by default) and a run that
allocates unreasonably much trips `-rss_limit_mb` (2048 MB by default), and
both are reported as a crash. Pass `-timeout=25 -rss_limit_mb=2560` to
tighten them for a short run.

A target that finds a crash exits non-zero and writes the offending input to
`fuzz/artifacts/<target>/`. Reproduce it with:

```
cargo +nightly fuzz run <target> fuzz/artifacts/<target>/crash-<hash>
```

## Corpus and artifacts are git-ignored

`fuzz/.gitignore` ignores `target/`, `corpus/`, `artifacts/` and `coverage/`.
The corpus is a working directory for the fuzzer, not a source of truth: it
is rebuilt from scratch on every run. **No corpus and no crash input is
committed**, and no real capture, real MAC or real SSID ever goes into one.

## Dependencies and licensing

The project is MIT and `fuzz/Cargo.toml` sets `license = "MIT"`. The only
dependencies are:

* `libfuzzer-sys` 0.4 — MIT OR Apache-2.0,
* `od3sa-parse` — the crate under test, a path dependency inside this repo.

No GPL, LGPL or AGPL dependency is involved.

## Guardrails

These targets are pure functions over byte slices. They touch no radio, no
pcap handle and no network. The parsers keep metadata only, and the fuzz
targets assert nothing that would make them keep a payload.
