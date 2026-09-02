# chromium-roots

[![CI](https://github.com/0x676e67/chromium-roots/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/0x676e67/chromium-roots/actions/workflows/ci.yml)
[![License](https://img.shields.io/github/license/0x676e67/chromium-roots)](LICENSE)

A compiled-in snapshot of the Chrome Root Store, generated from Chromium's PKI Metadata component.

The public crate includes full DER-encoded root certificates, Chrome trust constraints, and Trust Anchor IDs. It provides static root data and does not implement certificate verification.

Applications must update the crate and rebuild to receive root-store changes.

## Workspace

- [`chromium-roots`](chromium-roots): generated data for TLS clients.
- [`chromium-crs`](chromium-crs): source retrieval, validation, and deterministic generation.

The scheduled GitHub workflow checks for upstream changes each week. See the [`chromium-crs` documentation](chromium-crs/README.md) for manual update commands and source details.

## License

See [LICENSE](LICENSE) and [NOTICE](NOTICE) for licensing and attribution.
