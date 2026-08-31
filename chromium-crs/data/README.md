# Authenticated Chromium inputs

This directory belongs to the chromium-crs maintenance crate.

- crs.pb is the serialized RootStore payload extracted from the authenticated
  Chrome PKI Metadata component.
- SOURCE.toml records component identity, versions, URLs, and SHA-256 digests.
- CHROMIUM_LICENSE is the upstream license distributed with the source data.

The published chromium-root-certs crate does not read this directory during
builds. Regenerate or update these files through the chromium-crs binary;
do not edit them by hand.
