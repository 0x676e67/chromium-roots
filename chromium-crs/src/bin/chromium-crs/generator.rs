//! Deterministic Rust source generation from an authenticated Root Store.

#[path = "generator/codegen.rs"]
mod codegen;

use std::{collections::BTreeSet, fs, path::Path};

use anyhow::{Context, Result, bail, ensure};
use chromium_crs::{
    COMPONENT_UPDATE_URL, SourceMetadata, TrustAnchor, parse_root_store, validate_certificate_der,
    validate_tls_trust_anchor_der, validate_trust_anchor_id,
};

/// Certificate entry paired with its independently calculated fingerprint.
pub(super) struct ValidatedTrustAnchor<'a> {
    /// Original signed metadata.
    pub(super) metadata: &'a TrustAnchor,
    /// SHA-256 of the complete DER certificate.
    pub(super) sha256: [u8; 32],
    /// Index into the generated unique Trust Anchor ID list.
    pub(super) trust_anchor_id_index: Option<usize>,
}

/// Deterministic output and summary produced by the generator.
pub(crate) struct GeneratedLibrary {
    /// Formatted Rust source for the public data crate.
    pub(crate) source: String,
    /// Signed Chrome Root Store major version.
    pub(crate) root_store_version: i64,
    /// Number of classical X.509 TLS trust anchors.
    pub(crate) anchor_count: usize,
    /// Number of unique Trust Anchor IDs.
    pub(crate) id_count: usize,
}

/// Generates from the checked-in payload and verifies its provenance lock.
pub(crate) fn generate(root: &Path) -> Result<GeneratedLibrary> {
    let (source, expected_version) = read_source_lock(root)?;
    let crs = read_file(&root.join("chromium-crs/data/crs.pb"))?;
    let generated = generate_component(&source, &crs)?;
    ensure!(
        generated.root_store_version == expected_version,
        "SOURCE.toml version {expected_version} does not match component version {}",
        generated.root_store_version
    );
    Ok(generated)
}

/// Validates and generates a downloaded candidate before it is written.
pub(crate) fn generate_component(source: &SourceMetadata, crs: &[u8]) -> Result<GeneratedLibrary> {
    source.verify_payload(crs)?;
    let parsed = parse_root_store(crs)?;
    let (validated, trust_anchor_ids) = validate_anchors(&parsed.anchors)?;

    let encoded_ids_len = trust_anchor_ids.iter().try_fold(0usize, |length, id| {
        length
            .checked_add(1)
            .and_then(|length| length.checked_add(id.len()))
            .context("encoded Trust Anchor ID list length overflow")
    })?;
    // The extension's outer vector has a two-byte length field.
    ensure!(
        u16::try_from(encoded_ids_len).is_ok(),
        "encoded Trust Anchor ID list exceeds the TLS vector limit"
    );

    let source_code =
        codegen::generate_source(source, parsed.version, &validated, &trust_anchor_ids)?;

    Ok(GeneratedLibrary {
        source: source_code,
        root_store_version: parsed.version,
        anchor_count: validated.len(),
        id_count: trust_anchor_ids.len(),
    })
}

/// Validates every signed certificate and ID before selecting TLS anchors.
fn validate_anchors(
    anchors: &[TrustAnchor],
) -> Result<(Vec<ValidatedTrustAnchor<'_>>, Vec<&[u8]>)> {
    let mut seen_hashes = BTreeSet::new();
    let mut seen_ids = BTreeSet::new();
    let mut trust_anchor_ids = Vec::new();
    let mut validated = Vec::with_capacity(anchors.len());

    for anchor in anchors {
        let hash = if anchor.tls_trust_anchor {
            validate_tls_trust_anchor_der(&anchor.der)?
        } else {
            validate_certificate_der(&anchor.der)?
        };

        let trust_anchor_id_index = if let Some(id) = anchor.trust_anchor_id.as_deref() {
            validate_trust_anchor_id(id)?;
            ensure!(
                seen_ids.insert(id),
                "duplicate Trust Anchor ID {}",
                hex::encode(id)
            );

            if anchor.tls_trust_anchor {
                let index = trust_anchor_ids.len();
                trust_anchor_ids.push(id);
                Some(index)
            } else {
                None
            }
        } else {
            None
        };

        if anchor.tls_trust_anchor {
            ensure!(
                seen_hashes.insert(hash),
                "duplicate TLS trust anchor SHA-256 {}",
                hex::encode(hash)
            );
            validated.push(ValidatedTrustAnchor {
                metadata: anchor,
                sha256: hash,
                trust_anchor_id_index,
            });
        }
    }

    ensure!(
        !validated.is_empty(),
        "Root Store contains no TLS trust anchors"
    );
    Ok((validated, trust_anchor_ids))
}

/// Writes generated static data only when it differs.
pub(crate) fn write_generated_source(root: &Path, source: &str) -> Result<bool> {
    let path = root.join("chromium-root-certs/src/generated.rs");
    if fs::read_to_string(&path).ok().as_deref() == Some(source) {
        return Ok(false);
    }
    fs::write(&path, source).with_context(|| format!("failed to write {}", path.display()))?;
    Ok(true)
}

/// Ensures the public static data matches the checked-in component.
pub(crate) fn ensure_generated_source_current(root: &Path, source: &str) -> Result<()> {
    let path = root.join("chromium-root-certs/src/generated.rs");
    let checked_in =
        fs::read_to_string(&path).with_context(|| format!("failed to read {}", path.display()))?;
    ensure!(
        checked_in == source,
        "chromium-root-certs/src/generated.rs is stale; run cargo run -p chromium-crs -- generate"
    );
    Ok(())
}

/// Reads one pinned input with path-aware errors.
fn read_file(path: &Path) -> Result<Vec<u8>> {
    fs::read(path).with_context(|| format!("failed to read {}", path.display()))
}

/// Parses the deliberately small, generated provenance lock format.
fn read_source_lock(root: &Path) -> Result<(SourceMetadata, i64)> {
    let path = root.join("chromium-crs/data/SOURCE.toml");
    let contents =
        fs::read_to_string(&path).with_context(|| format!("failed to read {}", path.display()))?;

    parse_source_lock(&contents)
}

/// Parses and validates the deliberately small provenance lock format.
fn parse_source_lock(contents: &str) -> Result<(SourceMetadata, i64)> {
    let mut component_id = None;
    let mut component_version = None;
    let mut browser_version = None;
    let mut package_hash = None;
    let mut payload_hash = None;
    let mut root_store_version = None;
    let mut update_url = None;

    for raw_line in contents.lines() {
        let line = raw_line.split('#').next().unwrap_or_default().trim();
        if line.is_empty() {
            continue;
        }
        let Some((name, value)) = line.split_once('=') else {
            bail!("invalid SOURCE.toml line {raw_line:?}");
        };
        let name = name.trim();
        let value = value.trim();
        match name {
            "component_id" => {
                set_once(&mut component_id, parse_lock_string(value, name)?, name)?;
            }
            "component_version" => {
                set_once(
                    &mut component_version,
                    parse_lock_string(value, name)?,
                    name,
                )?;
            }
            "browser_version" => {
                set_once(&mut browser_version, parse_lock_string(value, name)?, name)?;
            }
            "crx_sha256" => {
                set_once(&mut package_hash, parse_lock_hash(value, name)?, name)?;
            }
            "crs_sha256" => {
                set_once(&mut payload_hash, parse_lock_hash(value, name)?, name)?;
            }
            "root_store_version" => {
                let version = value.parse().context("invalid locked Root Store version")?;
                set_once(&mut root_store_version, version, name)?;
            }
            "source" => {
                set_once(&mut update_url, parse_lock_string(value, name)?, name)?;
            }
            _ => bail!("unsupported SOURCE.toml field {name:?}"),
        }
    }

    ensure!(
        update_url.context("SOURCE.toml has no source")? == COMPONENT_UPDATE_URL,
        "SOURCE.toml source does not match the pinned component endpoint"
    );
    let source = SourceMetadata::new(
        component_id.context("SOURCE.toml has no component_id")?,
        component_version.context("SOURCE.toml has no component_version")?,
        browser_version.context("SOURCE.toml has no browser_version")?,
        package_hash.context("SOURCE.toml has no crx_sha256")?,
        payload_hash.context("SOURCE.toml has no crs_sha256")?,
    )?;

    Ok((
        source,
        root_store_version.context("SOURCE.toml has no root_store_version")?,
    ))
}

/// Stores a lock field exactly once.
fn set_once<T>(slot: &mut Option<T>, value: T, name: &str) -> Result<()> {
    ensure!(slot.is_none(), "SOURCE.toml field {name} is duplicated");
    *slot = Some(value);
    Ok(())
}

/// Parses one quoted lock string without supporting escape sequences.
fn parse_lock_string(value: &str, name: &str) -> Result<String> {
    ensure!(
        value.len() >= 2 && value.starts_with('"') && value.ends_with('"'),
        "SOURCE.toml field {name} must be a quoted string"
    );
    let value = &value[1..value.len() - 1];
    ensure!(
        !value.contains(['"', '\\']),
        "SOURCE.toml field {name} contains unsupported escaping"
    );
    Ok(value.to_owned())
}

/// Parses one locked SHA-256 value from hexadecimal.
fn parse_lock_hash(value: &str, name: &str) -> Result<[u8; 32]> {
    let value = parse_lock_string(value, name)?;
    let bytes = hex::decode(&value).with_context(|| format!("invalid {name} hex"))?;
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("SOURCE.toml field {name} must contain 32 bytes"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_SOURCE_LOCK: &str = r#"
component_id = "efniojlnjndmcbiieegkicadnoecjjef"
component_version = "1759"
browser_version = "152.0.7977.64"
crx_sha256 = "0000000000000000000000000000000000000000000000000000000000000000"
crs_sha256 = "1111111111111111111111111111111111111111111111111111111111111111"
root_store_version = 39
source = "https://clients2.google.com/service/update2/crx"
"#;

    fn workspace_root() -> &'static Path {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("maintenance package manifest must have a workspace parent")
    }

    fn checked_in_anchors() -> Vec<TrustAnchor> {
        let crs = read_file(&workspace_root().join("chromium-crs/data/crs.pb"))
            .expect("checked-in Root Store must be readable");
        parse_root_store(&crs)
            .expect("checked-in Root Store must parse")
            .anchors
    }

    #[test]
    fn checked_in_component_generates_current_source_model() {
        let generated = generate(workspace_root()).expect("checked-in Root Store must generate");

        assert!(generated.root_store_version > 0);
        assert!(generated.anchor_count > 0);
        assert!(!generated.source.is_empty());
    }

    #[test]
    fn non_tls_certificates_are_validated_before_filtering() {
        let mut anchors = checked_in_anchors();
        let anchor = anchors
            .iter_mut()
            .find(|anchor| !anchor.tls_trust_anchor)
            .expect("checked-in component must contain a non-TLS certificate");
        anchor.der.clear();

        let error = validate_anchors(&anchors)
            .err()
            .expect("invalid non-TLS certificate must be rejected");
        assert!(error.to_string().contains("invalid X.509 certificate"));
    }

    #[test]
    fn duplicate_trust_anchor_ids_are_rejected() {
        let mut anchors = checked_in_anchors();
        let source_index = anchors
            .iter()
            .position(|anchor| anchor.trust_anchor_id.is_some())
            .expect("checked-in component must contain a Trust Anchor ID");
        let duplicate_index = (0..anchors.len())
            .find(|index| *index != source_index)
            .expect("checked-in component must contain multiple certificates");
        anchors[duplicate_index].trust_anchor_id = anchors[source_index].trust_anchor_id.clone();

        let error = validate_anchors(&anchors)
            .err()
            .expect("duplicate Trust Anchor ID must be rejected");
        assert!(error.to_string().contains("duplicate Trust Anchor ID"));
    }

    #[test]
    fn source_lock_requires_unique_fields_and_the_pinned_endpoint() {
        let (source, version) =
            parse_source_lock(VALID_SOURCE_LOCK).expect("canonical source lock must parse");
        assert_eq!(
            source.component_id(),
            chromium_crs::PKI_METADATA_COMPONENT_ID
        );
        assert_eq!(version, 39);

        let duplicate = format!("{VALID_SOURCE_LOCK}source = \"{COMPONENT_UPDATE_URL}\"\n");
        let error =
            parse_source_lock(&duplicate).expect_err("duplicate source field must be rejected");
        assert!(error.to_string().contains("is duplicated"));

        let changed = VALID_SOURCE_LOCK.replace(
            COMPONENT_UPDATE_URL,
            "https://example.com/service/update2/crx",
        );
        let error =
            parse_source_lock(&changed).expect_err("changed component endpoint must be rejected");
        assert!(error.to_string().contains("pinned component endpoint"));
    }
}
