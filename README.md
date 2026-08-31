# chromium-root-certs

This repository is a two-crate Rust workspace for maintaining and publishing a
Chromium Root Store snapshot.

## Workspace layout

- chromium-root-certs is the published, no_std runtime crate. It contains only
  checked-in rustls-pki-types certificate entries, Chrome constraints, and Trust
  Anchor IDs.
- chromium-crs is the unpublished maintenance crate. Its library
  authenticates and parses Chromium source data, while its binary updates and
  regenerates the published crate.

The repository root is a virtual Cargo workspace and is not itself a package.
This keeps runtime dependencies separate from network, protobuf, archive, and
code-generation dependencies.

## Updating the snapshot

Run these commands from the workspace root:

    cargo run -p chromium-crs -- update
    cargo run -p chromium-crs -- generate
    cargo run -p chromium-crs -- check

update downloads and authenticates the current Chrome PKI Metadata component.
generate rebuilds the static Rust source from the checked-in component payload.
check verifies that the payload, source lock, and generated source agree.

Authenticated maintenance inputs live under chromium-crs/data. Generated
runtime data lives under chromium-root-certs/src.

The weekly GitHub workflow performs the network update and uploads changed files
as an artifact. It does not commit or push changes.

Generation validates every DER certificate and Trust Anchor ID in the signed
component before filtering the TLS roots that the runtime crate publishes.
Duplicate IDs and ambiguous provenance fields are rejected.

## Validation

    cargo fmt --all
    cargo test --workspace
    cargo clippy --workspace --all-targets -- -D warnings
    cargo run -p chromium-crs -- check

## License

Project code is licensed under BSD-3-Clause. Imported Chromium data remains
subject to the license included with each crate.
