//! Authenticated source model for the Chrome Root Store.
//!
//! This crate is the upstream-facing half of the workspace. It owns Chrome PKI
//! Metadata downloads, CRX3 verification, protobuf decoding, and certificate
//! validation. The sibling chromium-roots crate contains only generated
//! static data and its public lookup API.

use anyhow::{Result, ensure};
use sha2::{Digest, Sha256};

mod certificates;
mod component;
mod crx3;
mod protobuf;
mod wire;

pub use certificates::{
    validate_certificate_der, validate_tls_trust_anchor_der, validate_trust_anchor_id,
};
pub use component::{COMPONENT_UPDATE_URL, ComponentSnapshot, download_latest};
pub use protobuf::parse_root_store;

/// Chrome's fixed PKI Metadata component identifier.
///
/// Chromium derives this identifier from the first 128 bits of the component
/// signer's SHA-256 public-key-information digest.
pub const PKI_METADATA_COMPONENT_ID: &str = "efniojlnjndmcbiieegkicadnoecjjef";

/// Identifies which signed Root Store list supplied a certificate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TrustAnchorKind {
    /// Entry from the historical TLS-only root list.
    Root,
    /// Entry from the additional certificate list.
    Additional,
}

/// A set of conditions that Chromium evaluates together.
///
/// Every populated field in one set must hold. Multiple sets attached to an
/// anchor are alternatives.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ConstraintSet {
    /// Latest accepted timestamp for at least one valid SCT.
    pub sct_not_after_sec: Option<i64>,

    /// Exclusive lower timestamp bound for every valid SCT.
    pub sct_all_after_sec: Option<i64>,

    /// Inclusive minimum Chrome version.
    pub min_version: Option<String>,

    /// Exclusive maximum Chrome version.
    pub max_version_exclusive: Option<String>,

    /// Permitted DNS subtrees for every leaf subject alternative name.
    pub permitted_dns_names: Vec<String>,

    /// Inclusive maximum Merkle Tree Certificate index.
    pub index_not_after: Option<u64>,

    /// Exclusive minimum Merkle Tree Certificate index.
    pub index_after: Option<u64>,

    /// Latest accepted leaf certificate validity start.
    pub validity_starts_not_after_sec: Option<i64>,

    /// Exclusive lower bound for the leaf certificate validity start.
    pub validity_starts_after_sec: Option<i64>,
}

/// One classical X.509 entry from the signed component payload.
///
/// The structure retains Chrome-specific policy metadata rather than reducing
/// the input to certificates alone. Consumers can therefore enforce policy that
/// is outside a conventional Web PKI root bundle.
#[allow(clippy::struct_excessive_bools, clippy::struct_field_names)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrustAnchor {
    /// Source list containing the entry.
    pub kind: TrustAnchorKind,

    /// Complete DER-encoded certificate.
    pub der: Vec<u8>,

    /// Extended Validation policy object identifiers.
    pub ev_policy_oids: Vec<String>,

    /// Alternative Chrome-specific constraint sets.
    pub constraints: Vec<ConstraintSet>,

    /// Optional human-readable name.
    pub display_name: Option<String>,

    /// Whether the anchor may issue qualified website certificates.
    pub eutl: bool,

    /// Whether Chrome enforces the anchor validity period.
    pub enforce_anchor_expiry: bool,

    /// Whether Chrome enforces constraints encoded in the anchor.
    pub enforce_anchor_constraints: bool,

    /// Whether the entry is a TLS trust anchor.
    pub tls_trust_anchor: bool,

    /// Binary relative object identifier advertised by the TLS extension.
    pub trust_anchor_id: Option<Vec<u8>>,

    /// Stable Chrome Root Store identifier.
    pub crs_root_id: Option<i32>,
}

impl TrustAnchor {
    /// Creates an entry with Chromium's list-specific TLS trust default.
    pub(crate) fn new(kind: TrustAnchorKind, der: Vec<u8>) -> Self {
        Self {
            kind,
            der,
            ev_policy_oids: Vec::new(),
            constraints: Vec::new(),
            display_name: None,
            eutl: false,
            enforce_anchor_expiry: false,
            enforce_anchor_constraints: false,
            tls_trust_anchor: kind == TrustAnchorKind::Root,
            trust_anchor_id: None,
            crs_root_id: None,
        }
    }
}

/// Decoded classical portion of one complete signed Root Store.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RootStore {
    /// Monotonically increasing Chrome Root Store major version.
    pub version: i64,

    /// Classical certificate entries in signed source order.
    pub anchors: Vec<TrustAnchor>,
}

/// Authenticated package provenance recorded beside a snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceMetadata {
    component_id: String,
    component_version: String,
    browser_version: String,
    crx_sha256: [u8; 32],
    crs_sha256: [u8; 32],
}

impl SourceMetadata {
    /// Constructs and validates snapshot provenance.
    ///
    /// # Errors
    ///
    /// Returns an error if the component ID is not the pinned Chrome PKI Metadata ID.
    pub fn new(
        component_id: String,
        component_version: String,
        browser_version: String,
        component_sha256: [u8; 32],
        payload_sha256: [u8; 32],
    ) -> Result<Self> {
        ensure!(
            component_id == PKI_METADATA_COMPONENT_ID,
            "unexpected PKI Metadata component ID"
        );
        validate_dotted_version(&component_version, "component version", None)?;
        validate_dotted_version(&browser_version, "browser version", Some(4))?;

        Ok(Self {
            component_id,
            component_version,
            browser_version,
            crx_sha256: component_sha256,
            crs_sha256: payload_sha256,
        })
    }

    /// Returns the authenticated component identifier.
    #[must_use]
    pub fn component_id(&self) -> &str {
        &self.component_id
    }

    /// Returns the signed component package version.
    #[must_use]
    pub fn component_version(&self) -> &str {
        &self.component_version
    }

    /// Returns the Chrome Stable version used for the update request.
    #[must_use]
    pub fn browser_version(&self) -> &str {
        &self.browser_version
    }

    /// Returns the SHA-256 digest of the complete CRX3 package.
    #[must_use]
    pub fn crx_sha256(&self) -> &[u8; 32] {
        &self.crx_sha256
    }

    /// Returns the SHA-256 digest of the extracted Root Store payload.
    #[must_use]
    pub fn crs_sha256(&self) -> &[u8; 32] {
        &self.crs_sha256
    }

    /// Verifies that serialized Root Store bytes match this provenance.
    ///
    /// # Errors
    ///
    /// Returns an error if the payload digest differs from the authenticated digest.
    pub fn verify_payload(&self, payload: &[u8]) -> Result<()> {
        let actual: [u8; 32] = Sha256::digest(payload).into();
        ensure!(
            actual == self.crs_sha256,
            "crs.pb SHA-256 does not match snapshot provenance"
        );
        Ok(())
    }
}

/// Accepts only dotted ASCII numeric versions with an optional fixed width.
fn validate_dotted_version(
    value: &str,
    label: &str,
    expected_components: Option<usize>,
) -> Result<()> {
    let components = value.split('.');
    ensure!(
        components.clone().all(|component| !component.is_empty()
            && component.bytes().all(|byte| byte.is_ascii_digit())),
        "{label} is not a dotted numeric version"
    );
    if let Some(expected_components) = expected_components {
        ensure!(
            components.count() == expected_components,
            "{label} must have {expected_components} components"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_metadata_rejects_another_component() {
        let result = SourceMetadata::new(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
            "1".to_owned(),
            "150.0.0.0".to_owned(),
            [0; 32],
            [0; 32],
        );
        assert!(result.is_err());
    }
}
