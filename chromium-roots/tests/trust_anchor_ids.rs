//! Validates Trust Anchor ID lookup and wire-format generation.

use chromium_roots::{
    ENCODED_TRUST_ANCHOR_IDS, TLS_SERVER_ROOT_CERTS, TLS_TRUST_ANCHORS,
    trust_anchor_id_for_certificate, trust_anchor_ids,
};

static COMPILED_TRUST_ANCHOR_IDS: [&[u8]; trust_anchor_ids().len()] = trust_anchor_ids();
static COMPILED_FIRST_LOOKUP: Option<&[u8]> =
    trust_anchor_id_for_certificate(TLS_TRUST_ANCHORS[0].der);

fn decode_wire_ids(mut encoded: &[u8]) -> Vec<&[u8]> {
    let mut ids = Vec::new();
    while let Some((&length, remaining)) = encoded.split_first() {
        let length = usize::from(length);
        assert_ne!(length, 0, "Trust Anchor IDs must not be empty");
        assert!(
            remaining.len() >= length,
            "truncated Trust Anchor ID wire list"
        );
        let (id, tail) = remaining.split_at(length);
        ids.push(id);
        encoded = tail;
    }
    ids
}

#[test]
fn trust_anchor_id_metadata_matches_wire_encoding() {
    let decoded = decode_wire_ids(ENCODED_TRUST_ANCHOR_IDS);
    let mapped = TLS_TRUST_ANCHORS
        .iter()
        .filter_map(|anchor| anchor.trust_anchor_id)
        .collect::<Vec<_>>();

    assert!(!decoded.is_empty());

    assert_eq!(mapped, decoded, "every published ID must map exactly once");
    assert_eq!(
        mapped.as_slice(),
        COMPILED_TRUST_ANCHOR_IDS.as_slice(),
        "compile-time collection must preserve every published ID"
    );

    let mut unique = mapped.clone();
    unique.sort_unstable();
    unique.dedup();
    assert_eq!(
        unique.len(),
        mapped.len(),
        "Trust Anchor IDs must be unique"
    );
}

#[test]
fn certificate_lookup_is_const_evaluable() {
    assert_eq!(COMPILED_FIRST_LOOKUP, TLS_TRUST_ANCHORS[0].trust_anchor_id);
}

#[test]
fn published_ids_only_match_exact_trusted_certificates() {
    let encoded_ids = decode_wire_ids(ENCODED_TRUST_ANCHOR_IDS);
    let mut matched_certificates = 0usize;

    for certificate in TLS_SERVER_ROOT_CERTS {
        if let Some(id) = trust_anchor_id_for_certificate(certificate.as_ref()) {
            matched_certificates += 1;
            assert!(encoded_ids.contains(&id));
        }
    }

    assert!(matched_certificates > 0);

    let certificate = TLS_SERVER_ROOT_CERTS
        .iter()
        .find(|certificate| trust_anchor_id_for_certificate(certificate.as_ref()).is_some())
        .expect("generated store has no certificate with a Trust Anchor ID");
    let mut changed_der = certificate.as_ref().to_vec();
    let final_byte = changed_der
        .last_mut()
        .expect("a DER certificate cannot be empty");
    *final_byte ^= 1;

    assert_eq!(trust_anchor_id_for_certificate(&changed_der), None);
}
