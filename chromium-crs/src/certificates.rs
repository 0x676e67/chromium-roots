//! X.509 certificate and Trust Anchor ID validation.
//!
//! These checks run for downloaded candidates and again whenever generated
//! source is refreshed, so static output never bypasses input validation.

use anyhow::{Result, anyhow, ensure};
use sha2::{Digest, Sha256};
use x509_parser::parse_x509_certificate;

/// Parses one complete certificate and returns its SHA-256 fingerprint.
///
/// # Errors
///
/// Returns an error when the input is not one complete DER-encoded X.509 certificate.
pub fn validate_certificate_der(der: &[u8]) -> Result<[u8; 32]> {
    validate_certificate(der, false)
}

/// Parses one complete CA certificate and returns its SHA-256 fingerprint.
///
/// # Errors
///
/// Returns an error when the input is not one complete DER-encoded X.509 CA certificate.
pub fn validate_tls_trust_anchor_der(der: &[u8]) -> Result<[u8; 32]> {
    validate_certificate(der, true)
}

/// Validates one complete certificate with an optional CA requirement.
fn validate_certificate(der: &[u8], require_ca: bool) -> Result<[u8; 32]> {
    let (remainder, certificate) = parse_x509_certificate(der)
        .map_err(|error| anyhow!("invalid X.509 certificate: {error}"))?;
    ensure!(
        remainder.is_empty(),
        "trailing data after X.509 certificate"
    );
    if require_ca {
        ensure!(
            certificate.is_ca(),
            "TLS trust anchor is not a CA certificate"
        );
    }
    Ok(Sha256::digest(der).into())
}

/// Validates the content octets of a DER relative object identifier.
///
/// Trust Anchor IDs omit the DER tag and length before being placed in the TLS
/// vector, but each base-128 object identifier component must remain minimal.
///
/// # Errors
///
/// Returns an error when the identifier is empty or exceeds the TLS vector limit.
pub fn validate_trust_anchor_id(id: &[u8]) -> Result<()> {
    ensure!(!id.is_empty(), "Trust Anchor ID must not be empty");
    ensure!(
        u8::try_from(id.len()).is_ok(),
        "Trust Anchor ID exceeds 255 bytes"
    );

    // A component beginning with 0x80 has a redundant zero base-128 group.
    // The final byte of every component must clear the continuation bit.
    let mut component_start = true;
    for (index, byte) in id.iter().copied().enumerate() {
        ensure!(
            !(component_start && byte == 0x80),
            "Trust Anchor ID contains a non-minimal OID component"
        );
        component_start = byte & 0x80 == 0;
        ensure!(
            index + 1 != id.len() || component_start,
            "Trust Anchor ID ends inside an OID component"
        );
    }
    Ok(())
}
