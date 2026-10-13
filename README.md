# chromium-roots

[![CI and release](https://github.com/0x676e67/chromium-roots/actions/workflows/release-plz.yml/badge.svg?branch=main)](https://github.com/0x676e67/chromium-roots/actions/workflows/release-plz.yml)
[![License](https://img.shields.io/github/license/0x676e67/chromium-roots)](LICENSE)
[![Crates.io](https://img.shields.io/crates/v/chromium-roots.svg)](https://crates.io/crates/chromium-roots)

A compiled-in snapshot of the Chrome Root Store, generated from Chromium's PKI Metadata component.

The public crate includes full DER-encoded root certificates, Chrome trust constraints, and Trust Anchor IDs. It provides static root data and does not implement certificate verification.

Applications must update the crate and rebuild to receive root-store changes.

## Workspace

- [`chromium-roots`](chromium-roots): generated data for TLS clients.
- [`chromium-crs`](chromium-crs): source retrieval, validation, and deterministic generation.

The scheduled GitHub workflow checks for upstream changes each week. See the [`chromium-crs` documentation](chromium-crs/README.md) for manual update commands and source details.

CI runs workflow lint, MSRV, stable Rust validation, and integration examples in
order. The main-branch release workflow calls this same CI before running
release-plz on that exact commit; failed or cancelled validation cannot proceed
to release. Lockfile-only pushes still run CI but skip release-plz. Pull requests
and manual CI runs only validate. Squash release PRs: publication is rejected if
release-plz would switch to an unverified ancestor instead of the tested commit.

## License

See [LICENSE](LICENSE) and [NOTICE](NOTICE) for licensing and attribution.
