//! Validates every generated Chromium TLS root certificate.

// Test scope adapted from rustls/webpki-roots' webpki-root-certs smoke test:
// https://github.com/rustls/webpki-roots/blob/main/webpki-root-certs/tests/smoketest.rs

use chromium_root_certs::{TLS_SERVER_ROOT_CERTS, TLS_TRUST_ANCHORS};

#[test]
fn every_tls_root_is_a_valid_ca_and_webpki_anchor() {
    assert!(!TLS_SERVER_ROOT_CERTS.is_empty());
    assert_eq!(TLS_SERVER_ROOT_CERTS.len(), TLS_TRUST_ANCHORS.len());

    for (root, metadata) in TLS_SERVER_ROOT_CERTS.iter().zip(TLS_TRUST_ANCHORS) {
        assert_eq!(
            root.as_ref(),
            metadata.der,
            "certificate and metadata arrays must remain aligned"
        );
        let (remaining, certificate) =
            x509_parser::parse_x509_certificate(root.as_ref()).expect("invalid X.509 DER");
        assert!(remaining.is_empty(), "certificate has trailing DER");
        assert!(certificate.is_ca(), "certificate is not a CA");
        webpki::anchor_from_trusted_cert(root).expect("invalid WebPKI trust anchor");
    }
}
