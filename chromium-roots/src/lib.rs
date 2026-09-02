#![no_std]
//! Static classical X.509 TLS trust anchors from the Chromium Root Store.
//!
//! Cargo generates the data from an authenticated Chrome PKI Metadata snapshot
//! maintained by the sibling maintenance crate. Generated provenance records
//! the exact component, requesting Chrome version, and content hashes. The
//! shared generator validates every signed X.509 certificate and Trust Anchor
//! ID, and preserves Chrome-specific constraints in the generated constants.
//!
//! This crate preserves Chromium's Root Store data but does not implement
//! Chromium's complete certificate verifier. Consumers that need
//! Chrome-equivalent verification must enforce [`RootConstraint`] and the
//! anchor enforcement flags.

/// Identifies where an anchor appears in Chromium's Root Store data.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TrustAnchorKind {
    /// Entry from the historical `trust_anchors` list.
    Root,
    /// Entry from `additional_certs` with `tls_trust_anchor` enabled.
    Additional,
}

/// A set of Chrome-specific conditions that must all hold for an anchor.
///
/// When an anchor has multiple sets, Chromium accepts the anchor when at least
/// one complete set is satisfied.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RootConstraint {
    /// Latest accepted SCT timestamp, in seconds since the Unix epoch.
    pub sct_not_after_sec: Option<i64>,

    /// Exclusive lower bound for every valid SCT, in seconds since the Unix epoch.
    pub sct_all_after_sec: Option<i64>,

    /// Inclusive minimum Chrome version.
    pub min_version: Option<&'static str>,

    /// Exclusive maximum Chrome version.
    pub max_version_exclusive: Option<&'static str>,

    /// Permitted DNS subtrees for every leaf subject alternative name.
    pub permitted_dns_names: &'static [&'static str],

    /// Inclusive maximum Merkle Tree Certificate index.
    pub index_not_after: Option<u64>,

    /// Exclusive minimum Merkle Tree Certificate index.
    pub index_after: Option<u64>,

    /// Latest accepted leaf `notBefore`, in seconds since the Unix epoch.
    pub validity_starts_not_after_sec: Option<i64>,

    /// Exclusive lower bound for leaf `notBefore`, in seconds since the Unix epoch.
    pub validity_starts_after_sec: Option<i64>,
}

/// Metadata for one classical X.509 TLS trust anchor.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TrustAnchor {
    /// DER-encoded certificate.
    pub der: &'static [u8],

    /// SHA-256 digest of the complete DER certificate.
    pub sha256: [u8; 32],

    /// Source list containing this certificate.
    pub kind: TrustAnchorKind,

    /// Stable identifier assigned by the Chrome Root Store.
    pub crs_root_id: Option<i32>,

    /// Binary relative-OID Trust Anchor ID, without DER tag and length.
    pub trust_anchor_id: Option<&'static [u8]>,

    /// Chrome-specific alternative constraint sets.
    pub constraints: &'static [RootConstraint],

    /// Extended Validation policy OIDs associated with this anchor.
    pub ev_policy_oids: &'static [&'static str],

    /// Optional display name supplied by Chromium metadata.
    pub display_name: Option<&'static str>,

    /// Whether Chromium marks this anchor for the EU Trusted List.
    pub eutl: bool,

    /// Whether the anchor certificate's validity period must be enforced.
    pub enforce_anchor_expiry: bool,

    /// Whether X.509 constraints encoded in the anchor must be enforced.
    pub enforce_anchor_constraints: bool,
}

// These functions are evaluated only by generated constants. Keeping the
// encoder here makes the metadata list the sole source of Trust Anchor ID bytes.
const fn encoded_trust_anchor_ids_len(anchors: &[TrustAnchor]) -> usize {
    let mut index = 0;
    let mut length = 0usize;
    while index < anchors.len() {
        let Some(id) = anchors[index].trust_anchor_id else {
            index += 1;
            continue;
        };
        assert!(!id.is_empty(), "Trust Anchor IDs must not be empty");
        assert!(
            id.len() <= 255,
            "Trust Anchor IDs must fit an 8-bit TLS length prefix"
        );
        length = match length.checked_add(id.len() + 1) {
            Some(length) => length,
            None => panic!("encoded Trust Anchor ID length overflow"),
        };
        index += 1;
    }
    assert!(
        length <= 65_535,
        "encoded Trust Anchor IDs must fit the TLS outer vector"
    );
    length
}

const fn encode_trust_anchor_ids<const N: usize>(anchors: &[TrustAnchor]) -> [u8; N] {
    let mut encoded = [0; N];
    let mut anchor_index = 0;
    let mut offset = 0;

    while anchor_index < anchors.len() {
        let Some(id) = anchors[anchor_index].trust_anchor_id else {
            anchor_index += 1;
            continue;
        };
        encoded[offset] = id.len().to_le_bytes()[0];
        offset += 1;

        let mut byte_index = 0;
        while byte_index < id.len() {
            encoded[offset] = id[byte_index];
            offset += 1;
            byte_index += 1;
        }
        anchor_index += 1;
    }

    assert!(offset == N, "encoded Trust Anchor ID length mismatch");
    encoded
}

include!("generated.rs");

/// Returns the published Trust Anchor ID associated with an exact certificate DER match.
#[must_use]
pub fn trust_anchor_id_for_certificate(certificate_der: &[u8]) -> Option<&'static [u8]> {
    TLS_TRUST_ANCHORS
        .iter()
        .find(|anchor| anchor.der == certificate_der)
        .and_then(|anchor| anchor.trust_anchor_id)
}
