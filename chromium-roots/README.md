# chromium-roots

[![CI](https://github.com/0x676e67/chromium-roots/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/0x676e67/chromium-roots/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/chromium-roots.svg)](https://crates.io/crates/chromium-roots)
[![License](https://img.shields.io/github/license/0x676e67/chromium-roots)](LICENSE)

A compiled-in snapshot of the Chrome Root Store, generated from Chromium's PKI Metadata component.

This crate provides full DER-encoded root certificates together with Chrome trust constraints and Trust Anchor IDs. It contains static data and does not implement certificate verification.

Applications must update this dependency and rebuild to receive root-store changes.

## Updating

The checked-in source is generated deterministically by [`chromium-crs`](../chromium-crs). Do not edit the generated module by hand.

## License

See [LICENSE](LICENSE), [NOTICE](NOTICE), and [CHROMIUM_LICENSE](CHROMIUM_LICENSE) for licensing and attribution.
