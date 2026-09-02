//! Surveys the certificate, metadata, and Trust Anchor ID APIs.
//!
//! Run with `cargo run -p chromium-roots --example api_overview`.

use std::collections::BTreeSet;

use chromium_roots::{
    ENCODED_TRUST_ANCHOR_IDS, TLS_SERVER_ROOT_CERTS, TLS_TRUST_ANCHORS, TrustAnchorKind,
    trust_anchor_id_for_certificate,
};

fn lowercase_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";

    let mut encoded = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        encoded.push(char::from(DIGITS[usize::from(byte >> 4)]));
        encoded.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn main() {
    // TLS_SERVER_ROOT_CERTS is convenient for APIs that consume CertificateDer.
    // TLS_TRUST_ANCHORS retains the same DER alongside Chromium metadata.
    println!("TLS trust-anchor certificates: {}", TLS_TRUST_ANCHORS.len());
    println!(
        "CertificateDer entries: {}; metadata entries: {}",
        TLS_SERVER_ROOT_CERTS.len(),
        TLS_TRUST_ANCHORS.len()
    );

    // TLS_TRUST_ANCHORS retains the Chromium metadata associated with each DER.
    let root_entries = TLS_TRUST_ANCHORS
        .iter()
        .filter(|anchor| anchor.kind == TrustAnchorKind::Root)
        .count();
    let additional_entries = TLS_TRUST_ANCHORS
        .iter()
        .filter(|anchor| anchor.kind == TrustAnchorKind::Additional)
        .count();
    let expiring_anchors = TLS_TRUST_ANCHORS
        .iter()
        .filter(|anchor| anchor.enforce_anchor_expiry)
        .count();
    let constrained_anchors = TLS_TRUST_ANCHORS
        .iter()
        .filter(|anchor| anchor.enforce_anchor_constraints)
        .count();
    let anchors_with_chromium_rules = TLS_TRUST_ANCHORS
        .iter()
        .filter(|anchor| !anchor.constraints.is_empty())
        .count();
    println!(
        "metadata: {root_entries} roots, {additional_entries} additional anchors, \
         {expiring_anchors} expiry-enforced, {constrained_anchors} X.509-constrained, \
         {anchors_with_chromium_rules} with Chromium-specific rules"
    );

    // Scanning every certificate with trust_anchor_id_for_certificate computes
    // the complete set of IDs associated with this snapshot without relying on
    // a separate count constant. It cannot enumerate IDs allocated outside
    // Chromium because Trust Anchor IDs are not derived from certificate DER.
    let ids_found_by_certificate = TLS_TRUST_ANCHORS
        .iter()
        .filter_map(|anchor| trust_anchor_id_for_certificate(anchor.der))
        .collect::<BTreeSet<_>>();
    println!(
        "unique Trust Anchor IDs found across all snapshot certificates: {}",
        ids_found_by_certificate.len()
    );

    // A single exact DER lookup returns zero or one associated ID.
    if let Some(anchor) = TLS_TRUST_ANCHORS
        .iter()
        .find(|anchor| anchor.trust_anchor_id.is_some())
    {
        match trust_anchor_id_for_certificate(anchor.der) {
            Some(id) => println!(
                "exact DER lookup: SHA-256 {} -> Trust Anchor ID bytes {}",
                lowercase_hex(&anchor.sha256),
                lowercase_hex(id)
            ),
            None => println!("exact DER lookup unexpectedly found no ID"),
        }
    }

    // Count IDs from the metadata when needed. This describes the current
    // snapshot, not every Trust Anchor ID allocated worldwide.
    println!(
        "metadata ID entries: {}",
        TLS_TRUST_ANCHORS
            .iter()
            .filter_map(|anchor| anchor.trust_anchor_id)
            .count()
    );
    for id in TLS_TRUST_ANCHORS
        .iter()
        .filter_map(|anchor| anchor.trust_anchor_id)
    {
        println!("  {}", lowercase_hex(id));
    }

    // This is the concatenation of one-byte-length-prefixed IDs expected by
    // BoringSSL's requested-trust-anchor setter. It does not include the TLS
    // extension's outer two-byte vector length.
    println!(
        "BoringSSL length-prefixed Trust Anchor ID bytes: {}",
        ENCODED_TRUST_ANCHOR_IDS.len()
    );
}
