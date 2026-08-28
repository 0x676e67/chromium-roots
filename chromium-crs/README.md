# chromium-crs

chromium-crs is the unpublished maintenance crate for
chromium-root-certs.

The library owns the Chrome PKI Metadata component model, CRX3 authentication,
protobuf schema validation, X.509 validation, and Trust Anchor ID validation.
The package binary owns update orchestration and deterministic Rust code
generation.

Authenticated source files are stored in data:

Every DER certificate and Trust Anchor ID in the authenticated component is
validated before publication filtering. The source lock must contain each field
once and must name the pinned Chrome component endpoint.

- crs.pb is the serialized Chrome Root Store payload.
- SOURCE.toml records component versions, URLs, and SHA-256 digests.
- CHROMIUM_LICENSE records the upstream data license.

Run the maintenance commands from the workspace root:

    cargo run -p chromium-crs -- update
    cargo run -p chromium-crs -- generate
    cargo run -p chromium-crs -- check

Unknown protobuf fields, reserved fields, and unexpected wire types are rejected
so Chromium schema changes require an explicit source review.
