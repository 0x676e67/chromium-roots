//! Validates Trust Anchor ID lookup and wire-format generation.

use chromium_roots::{
    ENCODED_TRUST_ANCHOR_IDS, TLS_SERVER_ROOT_CERTS, TLS_TRUST_ANCHORS, TRUST_ANCHOR_ID_COUNT,
    trust_anchor_id_for_certificate, trust_anchor_ids,
};

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
fn trust_anchor_id_iterator_matches_wire_encoding() {
    let decoded = decode_wire_ids(ENCODED_TRUST_ANCHOR_IDS);
    let iterated = trust_anchor_ids().collect::<Vec<_>>();

    assert!(!decoded.is_empty());
    assert_eq!(iterated.len(), TRUST_ANCHOR_ID_COUNT);
    assert_eq!(iterated, decoded);

    let mut unique = iterated.clone();
    unique.sort_unstable();
    unique.dedup();
    assert_eq!(
        unique.len(),
        iterated.len(),
        "Trust Anchor IDs must be unique"
    );

    let mapped = TLS_TRUST_ANCHORS
        .iter()
        .filter_map(|anchor| anchor.trust_anchor_id)
        .collect::<Vec<_>>();
    assert_eq!(mapped, decoded, "every published ID must map exactly once");
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
