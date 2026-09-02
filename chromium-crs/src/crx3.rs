//! Minimal CRX3 verifier for the Chrome PKI Metadata component.
//!
//! The signed-data layout and protobuf fields follow Chromium's crx3.proto and
//! verifier implementation:
//! <https://chromium.googlesource.com/chromium/src/+/main/components/crx_file/crx_verifier.cc>.

use std::{
    collections::BTreeSet,
    io::{Cursor, Read},
};

use anyhow::{Context, Result, bail, ensure};
use p256::ecdsa::{Signature as EcdsaSignature, VerifyingKey as EcdsaVerifyingKey};
use prost::Message;
use rsa::{
    RsaPublicKey,
    pkcs1v15::{Signature as RsaSignature, VerifyingKey as RsaVerifyingKey},
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use zip::ZipArchive;

use crate::{PKI_METADATA_COMPONENT_ID, validate_dotted_version};

const CRX_MAGIC: &[u8; 4] = b"Cr24";
const CRX_VERSION: u32 = 3;
const SIGNATURE_CONTEXT: &[u8] = b"CRX3 SignedData\0";
const MAX_HEADER_BYTES: usize = 1 << 20;
const MAX_ARCHIVE_BYTES: u64 = 4 << 20;
const MAX_MANIFEST_BYTES: u64 = 16 << 10;
const MAX_CRS_BYTES: u64 = 2 << 20;

// SHA-256 of the DER SubjectPublicKeyInfo pinned by Chromium's
// PKIMetadataComponentInstallerPolicy.
const PKI_METADATA_PUBLIC_KEY_SHA256: [u8; 32] = [
    0x45, 0xd8, 0xe9, 0xbd, 0x9d, 0x3c, 0x21, 0x88, 0x44, 0x6a, 0x82, 0x03, 0xde, 0x42, 0x99, 0x45,
    0x66, 0x25, 0xfe, 0xb3, 0xd1, 0xf8, 0x11, 0x65, 0xb4, 0x6f, 0xd3, 0x1b, 0x21, 0x89, 0xbe, 0x9c,
];

/// CRX3 header fields recognized by Chromium's verifier.
#[derive(Clone, PartialEq, Message)]
struct CrxFileHeader {
    /// RSA PKCS1 SHA-256 signature proofs.
    #[prost(message, repeated, tag = "2")]
    sha256_with_rsa: Vec<AsymmetricKeyProof>,
    /// P-256 SHA-256 signature proofs.
    #[prost(message, repeated, tag = "3")]
    sha256_with_ecdsa: Vec<AsymmetricKeyProof>,
    /// Optional verified-contents metadata not needed for package identity.
    #[prost(bytes = "vec", optional, tag = "4")]
    verified_contents: Option<Vec<u8>>,
    /// Serialized signed-data message covered by every proof.
    #[prost(bytes = "vec", optional, tag = "10000")]
    signed_header_data: Option<Vec<u8>>,
}

/// Public key and signature forming one CRX3 proof.
#[derive(Clone, PartialEq, Message)]
struct AsymmetricKeyProof {
    /// DER public-key information.
    #[prost(bytes = "vec", optional, tag = "1")]
    public_key: Option<Vec<u8>>,
    /// Algorithm-specific signature bytes.
    #[prost(bytes = "vec", optional, tag = "2")]
    signature: Option<Vec<u8>>,
}

/// Header data covered by every package signature.
#[derive(Clone, PartialEq, Message)]
struct SignedData {
    /// First 128 bits of the component signer public-key digest.
    #[prost(bytes = "vec", optional, tag = "1")]
    crx_id: Option<Vec<u8>>,
}

/// Authenticated files and provenance extracted from one package.
pub(super) struct VerifiedPackage {
    /// Version declared by the signed manifest.
    pub(super) component_version: String,
    /// Serialized Root Store payload.
    pub(super) crs: Vec<u8>,
    /// SHA-256 of the complete CRX3 package.
    pub(super) crx_sha256: [u8; 32],
    /// SHA-256 of the extracted Root Store payload.
    pub(super) crs_sha256: [u8; 32],
}

/// Verifies every recognized proof, requires Chromium's pinned key, and extracts the payload.
pub(super) fn verify_and_extract(crx: &[u8]) -> Result<VerifiedPackage> {
    ensure!(crx.len() >= 12, "CRX3 package is shorter than its prefix");
    ensure!(&crx[..4] == CRX_MAGIC, "CRX3 package has invalid magic");

    let version = u32::from_le_bytes(
        crx[4..8]
            .try_into()
            .context("CRX3 version field is truncated")?,
    );
    ensure!(version == CRX_VERSION, "unsupported CRX version {version}");

    let header_size = usize::try_from(u32::from_le_bytes(
        crx[8..12]
            .try_into()
            .context("CRX3 header size field is truncated")?,
    ))
    .context("CRX3 header size does not fit usize")?;
    ensure!(
        header_size <= MAX_HEADER_BYTES,
        "CRX3 header exceeds the {MAX_HEADER_BYTES}-byte limit"
    );
    let header_end = 12usize
        .checked_add(header_size)
        .context("CRX3 header offset overflow")?;
    ensure!(header_end < crx.len(), "CRX3 package has no ZIP payload");

    let header_bytes = &crx[12..header_end];
    for marker in [b"PK\x05\x06", b"PK\x06\x07", b"PK\x06\x06"] {
        ensure!(
            !header_bytes
                .windows(marker.len())
                .any(|window| window == marker),
            "CRX3 header contains a ZIP end marker"
        );
    }

    let header = CrxFileHeader::decode(header_bytes).context("invalid CRX3 protobuf header")?;
    let signed_header_data = header
        .signed_header_data
        .as_deref()
        .context("CRX3 header has no signed_header_data")?;
    let signed_data =
        SignedData::decode(signed_header_data).context("invalid CRX3 SignedData message")?;
    let declared_id = signed_data
        .crx_id
        .as_deref()
        .context("CRX3 SignedData has no crx_id")?;
    let expected_id = decode_component_id(PKI_METADATA_COMPONENT_ID)?;
    ensure!(
        declared_id == expected_id,
        "CRX3 package declares a different component ID"
    );
    ensure!(
        PKI_METADATA_PUBLIC_KEY_SHA256[..expected_id.len()] == expected_id,
        "pinned component key does not match the component ID"
    );

    let archive = &crx[header_end..];
    let signed_header_size = u32::try_from(signed_header_data.len())
        .context("CRX3 signed header is too large")?
        .to_le_bytes();
    let mut signed = Vec::with_capacity(
        SIGNATURE_CONTEXT.len()
            + signed_header_size.len()
            + signed_header_data.len()
            + archive.len(),
    );
    signed.extend_from_slice(SIGNATURE_CONTEXT);
    signed.extend_from_slice(&signed_header_size);
    signed.extend_from_slice(signed_header_data);
    signed.extend_from_slice(archive);

    let mut proof_count = 0usize;
    let mut found_component_key = false;
    for proof in &header.sha256_with_rsa {
        let key_hash = verify_rsa_proof(proof, &signed)?;
        proof_count = proof_count
            .checked_add(1)
            .context("CRX3 proof count overflow")?;
        found_component_key |= key_hash == PKI_METADATA_PUBLIC_KEY_SHA256;
    }
    for proof in &header.sha256_with_ecdsa {
        let key_hash = verify_ecdsa_proof(proof, &signed)?;
        proof_count = proof_count
            .checked_add(1)
            .context("CRX3 proof count overflow")?;
        found_component_key |= key_hash == PKI_METADATA_PUBLIC_KEY_SHA256;
    }
    ensure!(proof_count > 0, "CRX3 package contains no signature proofs");
    ensure!(
        found_component_key,
        "CRX3 package has no valid proof from the pinned PKI Metadata key"
    );

    let (manifest, crs) = extract_payload(archive)?;
    let component_version = manifest
        .get("version")
        .and_then(Value::as_str)
        .context("component manifest has no version")?;
    validate_dotted_version(component_version, "component version", None)?;

    Ok(VerifiedPackage {
        component_version: component_version.to_owned(),
        crx_sha256: Sha256::digest(crx).into(),
        crs_sha256: Sha256::digest(&crs).into(),
        crs,
    })
}

/// Verifies one RSA PKCS1 SHA-256 proof and returns the signer SPKI hash.
fn verify_rsa_proof(proof: &AsymmetricKeyProof, signed: &[u8]) -> Result<[u8; 32]> {
    let public_key = proof
        .public_key
        .as_deref()
        .context("CRX3 RSA proof has no public key")?;
    let signature = proof
        .signature
        .as_deref()
        .context("CRX3 RSA proof has no signature")?;
    let key = <RsaPublicKey as rsa::pkcs8::DecodePublicKey>::from_public_key_der(public_key)
        .context("CRX3 RSA proof has an invalid SPKI")?;
    let signature =
        RsaSignature::try_from(signature).context("CRX3 RSA signature has invalid length")?;
    rsa::signature::Verifier::verify(
        &RsaVerifyingKey::<rsa::sha2::Sha256>::new(key),
        signed,
        &signature,
    )
    .context("CRX3 RSA signature verification failed")?;
    Ok(Sha256::digest(public_key).into())
}

/// Verifies one P-256 SHA-256 proof and returns the signer SPKI hash.
fn verify_ecdsa_proof(proof: &AsymmetricKeyProof, signed: &[u8]) -> Result<[u8; 32]> {
    let public_key = proof
        .public_key
        .as_deref()
        .context("CRX3 ECDSA proof has no public key")?;
    let signature = proof
        .signature
        .as_deref()
        .context("CRX3 ECDSA proof has no signature")?;
    let key = <EcdsaVerifyingKey as p256::pkcs8::DecodePublicKey>::from_public_key_der(public_key)
        .context("CRX3 ECDSA proof has an invalid SPKI")?;
    let signature =
        EcdsaSignature::from_der(signature).context("CRX3 ECDSA signature is not DER")?;
    p256::ecdsa::signature::Verifier::verify(&key, signed, &signature)
        .context("CRX3 ECDSA signature verification failed")?;
    Ok(Sha256::digest(public_key).into())
}

/// Validates the ZIP directory, manifest, and bounded Root Store entry.
fn extract_payload(archive: &[u8]) -> Result<(Value, Vec<u8>)> {
    let mut archive =
        ZipArchive::new(Cursor::new(archive)).context("CRX3 payload is not a ZIP archive")?;
    let mut names = BTreeSet::new();
    let mut total_size = 0u64;

    for index in 0..archive.len() {
        let file = archive
            .by_index(index)
            .with_context(|| format!("failed to inspect ZIP entry {index}"))?;
        ensure!(
            file.enclosed_name().is_some(),
            "ZIP entry has an unsafe path {:?}",
            file.name()
        );
        ensure!(
            !file.encrypted(),
            "ZIP entry {:?} is encrypted",
            file.name()
        );
        ensure!(
            names.insert(file.name().to_owned()),
            "duplicate ZIP entry {:?}",
            file.name()
        );
        total_size = total_size
            .checked_add(file.size())
            .context("ZIP uncompressed size overflow")?;
        ensure!(
            total_size <= MAX_ARCHIVE_BYTES,
            "ZIP payload exceeds the {MAX_ARCHIVE_BYTES}-byte limit"
        );
    }

    let manifest_bytes = read_entry(&mut archive, "manifest.json", MAX_MANIFEST_BYTES)?;
    let manifest: Value =
        serde_json::from_slice(&manifest_bytes).context("component manifest is invalid JSON")?;
    ensure!(
        manifest.get("manifest_version").and_then(Value::as_u64) == Some(2),
        "component manifest_version is not 2"
    );
    ensure!(
        manifest.get("name").and_then(Value::as_str) == Some("pkiMetadata"),
        "component manifest has an unexpected name"
    );

    let crs = read_entry(&mut archive, "crs.pb", MAX_CRS_BYTES)?;
    ensure!(!crs.is_empty(), "component crs.pb is empty");
    Ok((manifest, crs))
}

/// Reads one regular ZIP entry under an independent uncompressed limit.
fn read_entry(archive: &mut ZipArchive<Cursor<&[u8]>>, name: &str, limit: u64) -> Result<Vec<u8>> {
    let mut file = archive
        .by_name(name)
        .with_context(|| format!("component ZIP has no {name}"))?;
    ensure!(file.is_file(), "component ZIP entry {name} is not a file");
    ensure!(
        file.size() <= limit,
        "component ZIP entry {name} exceeds the {limit}-byte limit"
    );

    let capacity = usize::try_from(file.size()).context("ZIP entry size does not fit usize")?;
    let mut bytes = Vec::with_capacity(capacity);
    file.by_ref()
        .take(limit.saturating_add(1))
        .read_to_end(&mut bytes)
        .with_context(|| format!("failed to read component ZIP entry {name}"))?;
    ensure!(
        u64::try_from(bytes.len()).unwrap_or(u64::MAX) <= limit,
        "component ZIP entry {name} exceeds the {limit}-byte limit"
    );
    Ok(bytes)
}

/// Converts Chrome's a-to-p extension identifier into its 16-byte digest prefix.
fn decode_component_id(id: &str) -> Result<[u8; 16]> {
    ensure!(id.len() == 32, "component ID must contain 32 characters");
    let mut decoded = [0u8; 16];
    for (output, pair) in decoded.iter_mut().zip(id.as_bytes().chunks_exact(2)) {
        let high = decode_component_nibble(pair[0])?;
        let low = decode_component_nibble(pair[1])?;
        *output = (high << 4) | low;
    }
    Ok(decoded)
}

/// Decodes one Chrome extension identifier nibble.
fn decode_component_nibble(value: u8) -> Result<u8> {
    match value {
        b'a'..=b'p' => Ok(value - b'a'),
        _ => bail!("component ID contains a character outside a-p"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn component_id_matches_pinned_public_key_hash() {
        let id = decode_component_id(PKI_METADATA_COMPONENT_ID).expect("valid component ID");
        assert_eq!(id, PKI_METADATA_PUBLIC_KEY_SHA256[..16]);
    }

    #[test]
    fn truncated_crx_is_rejected() {
        assert!(verify_and_extract(b"Cr24").is_err());
    }
}
