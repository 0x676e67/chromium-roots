# chromium-roots

chromium-roots publishes the Chrome Root Store as static Rust data.

Normal builds perform no network access, protobuf parsing, signature
verification, certificate parsing, or code generation. The crate exposes
rustls-pki-types certificate entries, original DER certificates, Chrome
constraints, and the requested-trust-anchor identifiers used by BoringSSL.

The generated source is checked into src/generated.rs. Source authentication and
regeneration are implemented by the sibling chromium-crs crate.

The btls example shows how to pass the encoded Trust Anchor IDs through btls-sys
using released btls packages, then verifies that the inspection endpoint
observed every published ID.

Project code is licensed under BSD-3-Clause. Generated Chromium data is covered
by CHROMIUM_LICENSE.
