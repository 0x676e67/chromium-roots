//! Typed Chrome Root Store protobuf decoding.
//!
//! The declarations mirror Chromium's checked-in root-store protobuf schema:
//! <https://chromium.googlesource.com/chromium/src/+/main/net/data/ssl/chrome_root_store/root_store.proto>.
//! The separate wire guard rejects fields that are not represented here before
//! prost performs typed value decoding.

use anyhow::{Context, Result, bail, ensure};
use prost::Message;

use crate::{ConstraintSet, RootStore, TrustAnchor, TrustAnchorKind, wire::validate_root_store};

/// Wire representation of a complete Chrome Root Store.
#[derive(Clone, PartialEq, Message)]
struct RootStoreMessage {
    /// Historical list of classical TLS trust anchors.
    #[prost(message, repeated, tag = "1")]
    trust_anchors: Vec<TrustAnchorMessage>,
    /// Monotonically increasing major store version.
    #[prost(int64, tag = "2")]
    version_major: i64,
    /// Certificates carrying explicit trust-purpose metadata.
    #[prost(message, repeated, tag = "3")]
    additional_certs: Vec<TrustAnchorMessage>,
    /// Merkle Tree Certificate anchors, retained for schema validation.
    #[prost(message, repeated, tag = "4")]
    mtc_anchors: Vec<MtcAnchorMessage>,
}

/// Wire representation of one classical certificate entry.
#[derive(Clone, PartialEq, Message)]
struct TrustAnchorMessage {
    /// DER certificate in components, or a source-only fingerprint in text data.
    #[prost(oneof = "certificate::Value", tags = "1, 2")]
    certificate: Option<certificate::Value>,
    /// Extended Validation policy object identifiers.
    #[prost(string, repeated, tag = "3")]
    ev_policy_oids: Vec<String>,
    /// Alternative sets of Chrome-specific constraints.
    #[prost(message, repeated, tag = "4")]
    constraints: Vec<ConstraintSetMessage>,
    /// Human-readable certificate name.
    #[prost(string, optional, tag = "5")]
    display_name: Option<String>,
    /// Whether the anchor may issue qualified website certificates.
    #[prost(bool, optional, tag = "6")]
    eutl: Option<bool>,
    /// Whether Chrome enforces the anchor certificate validity period.
    #[prost(bool, optional, tag = "8")]
    enforce_anchor_expiry: Option<bool>,
    /// Whether Chrome enforces constraints encoded in the anchor certificate.
    #[prost(bool, optional, tag = "9")]
    enforce_anchor_constraints: Option<bool>,
    /// Explicit TLS trust purpose for entries outside the historical root list.
    #[prost(bool, optional, tag = "10")]
    tls_trust_anchor: Option<bool>,
    /// Binary relative object identifier used by the TLS extension.
    #[prost(bytes = "vec", optional, tag = "11")]
    trust_anchor_id: Option<Vec<u8>>,
    /// Stable Chrome Root Store identifier.
    #[prost(int32, optional, tag = "12")]
    crs_root_id: Option<i32>,
}

/// Certificate alternatives in Chromium's source and component formats.
mod certificate {
    /// A component embeds DER, while Chromium's editable source may use a hash.
    #[derive(Clone, PartialEq, prost::Oneof)]
    pub(super) enum Value {
        /// Complete DER-encoded certificate.
        #[prost(bytes, tag = "1")]
        Der(Vec<u8>),
        /// Source-only SHA-256 fingerprint.
        #[prost(string, tag = "2")]
        Sha256Hex(String),
    }
}

/// Wire representation of one conjunctive constraint set.
#[derive(Clone, PartialEq, Message)]
struct ConstraintSetMessage {
    /// Latest accepted timestamp for at least one valid SCT.
    #[prost(int64, optional, tag = "1")]
    sct_not_after_sec: Option<i64>,
    /// Exclusive lower timestamp bound for every valid SCT.
    #[prost(int64, optional, tag = "2")]
    sct_all_after_sec: Option<i64>,
    /// Inclusive minimum Chrome version.
    #[prost(string, optional, tag = "3")]
    min_version: Option<String>,
    /// Exclusive maximum Chrome version.
    #[prost(string, optional, tag = "4")]
    max_version_exclusive: Option<String>,
    /// Permitted DNS subtrees for all leaf subject alternative names.
    #[prost(string, repeated, tag = "5")]
    permitted_dns_names: Vec<String>,
    /// Inclusive maximum Merkle Tree Certificate index.
    #[prost(uint64, optional, tag = "8")]
    index_not_after: Option<u64>,
    /// Exclusive minimum Merkle Tree Certificate index.
    #[prost(uint64, optional, tag = "9")]
    index_after: Option<u64>,
    /// Latest accepted leaf certificate validity start.
    #[prost(int64, optional, tag = "10")]
    validity_starts_not_after_sec: Option<i64>,
    /// Exclusive lower bound for the leaf certificate validity start.
    #[prost(int64, optional, tag = "11")]
    validity_starts_after_sec: Option<i64>,
}

/// Wire representation of a Merkle Tree Certificate anchor.
///
/// This crate currently publishes only classical X.509 anchors. Keeping this
/// message in the schema still detects changes anywhere in the signed payload.
#[derive(Clone, PartialEq, Message)]
struct MtcAnchorMessage {
    /// Binary log identifier.
    #[prost(bytes = "vec", optional, tag = "1")]
    log_id: Option<Vec<u8>>,
    /// Alternative sets of Chrome-specific constraints.
    #[prost(message, repeated, tag = "2")]
    constraints: Vec<ConstraintSetMessage>,
    /// Whether this entry is trusted for TLS.
    #[prost(bool, optional, tag = "3")]
    tls_trust_anchor: Option<bool>,
    /// Stable Chrome Root Store identifier.
    #[prost(int32, optional, tag = "4")]
    crs_root_id: Option<i32>,
}

/// Decodes the signed component payload into the public source model.
///
/// # Errors
///
/// Returns an error for malformed data, unknown schema fields, or invalid source values.
pub fn parse_root_store(input: &[u8]) -> Result<RootStore> {
    validate_root_store(input)?;
    let message = RootStoreMessage::decode(input).context("failed to decode crs.pb")?;

    let RootStoreMessage {
        trust_anchors,
        version_major,
        additional_certs,
        mtc_anchors: _,
    } = message;
    ensure!(version_major > 0, "version_major must be positive");

    let mut anchors = Vec::with_capacity(trust_anchors.len() + additional_certs.len());
    for anchor in trust_anchors {
        anchors.push(convert_anchor(anchor, TrustAnchorKind::Root)?);
    }
    for anchor in additional_certs {
        anchors.push(convert_anchor(anchor, TrustAnchorKind::Additional)?);
    }

    Ok(RootStore {
        version: version_major,
        anchors,
    })
}

/// Converts one wire certificate entry while rejecting source-only references.
fn convert_anchor(message: TrustAnchorMessage, kind: TrustAnchorKind) -> Result<TrustAnchor> {
    let der = match message.certificate {
        Some(certificate::Value::Der(der)) => der,
        Some(certificate::Value::Sha256Hex(_)) => {
            bail!("component RootStore anchor contains a source-only sha256_hex reference")
        }
        None => bail!("component RootStore anchor has no DER"),
    };

    let mut anchor = TrustAnchor::new(kind, der);
    anchor.ev_policy_oids = message.ev_policy_oids;
    anchor.constraints = message
        .constraints
        .into_iter()
        .map(convert_constraint)
        .collect();
    anchor.display_name = message.display_name;
    anchor.eutl = message.eutl.unwrap_or(false);
    anchor.enforce_anchor_expiry = message.enforce_anchor_expiry.unwrap_or(false);
    anchor.enforce_anchor_constraints = message.enforce_anchor_constraints.unwrap_or(false);
    if let Some(tls_trust_anchor) = message.tls_trust_anchor {
        anchor.tls_trust_anchor = tls_trust_anchor;
    }
    anchor.trust_anchor_id = message.trust_anchor_id;
    anchor.crs_root_id = message.crs_root_id;
    Ok(anchor)
}

/// Converts one wire constraint set without changing source order.
fn convert_constraint(message: ConstraintSetMessage) -> ConstraintSet {
    ConstraintSet {
        sct_not_after_sec: message.sct_not_after_sec,
        sct_all_after_sec: message.sct_all_after_sec,
        min_version: message.min_version,
        max_version_exclusive: message.max_version_exclusive,
        permitted_dns_names: message.permitted_dns_names,
        index_not_after: message.index_not_after,
        index_after: message.index_after,
        validity_starts_not_after_sec: message.validity_starts_not_after_sec,
        validity_starts_after_sec: message.validity_starts_after_sec,
    }
}
