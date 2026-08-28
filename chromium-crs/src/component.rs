//! Chrome PKI Metadata component download.
//!
//! HTTPS protects transport, while the CRX3 verifier independently authenticates
//! the component identity and payload before callers receive a snapshot.

use std::io::Read;

use anyhow::{Context, Result, bail, ensure};
use serde_json::Value;

use crate::{
    PKI_METADATA_COMPONENT_ID, SourceMetadata,
    crx3::{self, VerifiedPackage},
    validate_dotted_version,
};

const VERSION_HISTORY_URL: &str = "https://versionhistory.googleapis.com/v1/chrome/platforms/linux/channels/stable/versions?page_size=1&order_by=version%20desc";
/// Chrome component update endpoint recorded in snapshot provenance.
pub const COMPONENT_UPDATE_URL: &str = "https://clients2.google.com/service/update2/crx";
const MAX_JSON_BYTES: u64 = 1 << 20;
const MAX_CRX_BYTES: u64 = 8 << 20;
const MAX_REDIRECTS: usize = 8;

/// Authenticated candidate downloaded from Chrome's component service.
pub struct ComponentSnapshot {
    browser_version: String,
    component_version: String,
    crx_sha256: [u8; 32],
    crs_sha256: [u8; 32],
    crs: Vec<u8>,
}

impl ComponentSnapshot {
    /// Returns the Chrome Stable version used in the component request.
    #[must_use]
    pub fn browser_version(&self) -> &str {
        &self.browser_version
    }

    /// Returns the version declared by the signed component manifest.
    #[must_use]
    pub fn component_version(&self) -> &str {
        &self.component_version
    }

    /// Returns the SHA-256 digest of the complete verified package.
    #[must_use]
    pub fn crx_sha256(&self) -> &[u8; 32] {
        &self.crx_sha256
    }

    /// Returns the SHA-256 digest of the extracted Root Store payload.
    #[must_use]
    pub fn crs_sha256(&self) -> &[u8; 32] {
        &self.crs_sha256
    }

    /// Returns the serialized Root Store payload.
    #[must_use]
    pub fn crs(&self) -> &[u8] {
        &self.crs
    }

    /// Creates validated provenance for the shared generator.
    ///
    /// # Errors
    ///
    /// Returns an error if the downloaded component identity is not the pinned identity.
    pub fn source_metadata(&self) -> Result<SourceMetadata> {
        SourceMetadata::new(
            PKI_METADATA_COMPONENT_ID.to_owned(),
            self.component_version.clone(),
            self.browser_version.clone(),
            self.crx_sha256,
            self.crs_sha256,
        )
    }
}

/// Resolves Chrome Stable and downloads its current PKI Metadata component.
///
/// # Errors
///
/// Returns an error if discovery, download, authentication, or archive extraction fails.
pub fn download_latest() -> Result<ComponentSnapshot> {
    let browser_version = latest_stable_browser_version()?;
    let request_url = format!(
        "{COMPONENT_UPDATE_URL}?response=redirect&prodversion={browser_version}&\
         acceptformat=crx3&x=id%3D{PKI_METADATA_COMPONENT_ID}%26uc"
    );
    let crx = download_component_crx(&request_url)?;
    let VerifiedPackage {
        component_version,
        crs,
        crx_sha256,
        crs_sha256,
    } = crx3::verify_and_extract(&crx)?;

    Ok(ComponentSnapshot {
        browser_version,
        component_version,
        crx_sha256,
        crs_sha256,
        crs,
    })
}

/// Reads one four-component Linux Stable version from the Google version-history service.
fn latest_stable_browser_version() -> Result<String> {
    let mut response = ureq::get(VERSION_HISTORY_URL)
        .call()
        .context("failed to query the Chrome VersionHistory API")?;
    ensure!(
        response.status().is_success(),
        "Chrome VersionHistory API returned {}",
        response.status()
    );
    let body = read_limited(
        response.body_mut().as_reader(),
        MAX_JSON_BYTES,
        "Chrome VersionHistory response",
    )?;
    let value: Value = serde_json::from_slice(&body).context("invalid VersionHistory JSON")?;
    let version = value
        .get("versions")
        .and_then(Value::as_array)
        .and_then(|versions| versions.first())
        .and_then(|version| version.get("version"))
        .and_then(Value::as_str)
        .context("VersionHistory response has no stable Chrome version")?;
    validate_dotted_version(version, "Chrome version", Some(4))?;
    Ok(version.to_owned())
}

/// Follows only approved HTTPS redirects and enforces a package size limit.
fn download_component_crx(request_url: &str) -> Result<Vec<u8>> {
    let agent: ureq::Agent = ureq::config::Config::builder()
        .max_redirects(0)
        .build()
        .into();
    let mut current = request_url.to_owned();

    for _ in 0..MAX_REDIRECTS {
        ensure_allowed_download_url(&current)?;
        let response = agent
            .get(&current)
            .header("User-Agent", "chromium-crs/0.1")
            .call();

        let mut response = match response {
            Ok(response) => response,
            Err(error) => {
                if let Some(mirror) = edge_mirror_url(&current) {
                    current = mirror;
                    continue;
                }
                return Err(error).with_context(|| format!("failed to download {current}"));
            }
        };

        if response.status().is_redirection() {
            let location = response
                .headers()
                .get("location")
                .context("component redirect has no Location header")?
                .to_str()
                .context("component redirect Location is not valid text")?;
            current = resolve_redirect(&current, location)?;
            continue;
        }

        ensure!(
            response.status().is_success(),
            "component server returned {} for {current}",
            response.status()
        );
        return read_limited(
            response.body_mut().as_reader(),
            MAX_CRX_BYTES,
            "PKI Metadata CRX3 package",
        );
    }

    bail!("component download exceeded {MAX_REDIRECTS} redirects")
}

/// Resolves absolute HTTPS and same-authority absolute-path redirects.
fn resolve_redirect(current: &str, location: &str) -> Result<String> {
    if location.starts_with("https://") {
        return Ok(location.to_owned());
    }
    if let Some(path) = location.strip_prefix('/') {
        let authority = current
            .strip_prefix("https://")
            .and_then(|url| url.split('/').next())
            .context("cannot resolve relative component redirect")?;
        return Ok(format!("https://{authority}/{path}"));
    }
    bail!("unsupported component redirect {location:?}")
}

/// Restricts downloads to Chrome component service and CDN authorities.
fn ensure_allowed_download_url(url: &str) -> Result<()> {
    const ALLOWED_PREFIXES: &[&str] = &[
        "https://clients2.google.com/",
        "https://www.google.com/dl/",
        "https://dl.google.com/",
        "https://edgedl.me.gvt1.com/edgedl/",
        "https://redirector.gvt1.com/edgedl/",
    ];
    ensure!(
        ALLOWED_PREFIXES
            .iter()
            .any(|prefix| url.starts_with(prefix)),
        "component redirect uses an unexpected URL {url:?}"
    );
    Ok(())
}

/// Maps Google download hosts to the equivalent edge CDN after transport errors.
fn edge_mirror_url(url: &str) -> Option<String> {
    url.strip_prefix("https://dl.google.com/")
        .or_else(|| url.strip_prefix("https://www.google.com/dl/"))
        .map(|path| format!("https://edgedl.me.gvt1.com/edgedl/{path}"))
}

/// Reads at most one byte beyond a limit so oversized responses are detected.
fn read_limited(reader: impl Read, limit: u64, label: &str) -> Result<Vec<u8>> {
    let mut reader = reader.take(limit.saturating_add(1));
    let mut bytes = Vec::new();
    reader
        .read_to_end(&mut bytes)
        .with_context(|| format!("failed to read {label}"))?;
    ensure!(
        u64::try_from(bytes.len()).unwrap_or(u64::MAX) <= limit,
        "{label} exceeds the {limit}-byte limit"
    );
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mirror_rewrites_google_download_hosts() {
        assert_eq!(
            edge_mirror_url("https://dl.google.com/release2/file.crx3").as_deref(),
            Some("https://edgedl.me.gvt1.com/edgedl/release2/file.crx3")
        );
        assert_eq!(edge_mirror_url("https://example.com/file.crx3"), None);
    }

    #[test]
    fn chrome_versions_require_four_numeric_components() {
        assert!(validate_dotted_version("150.0.7871.175", "version", Some(4)).is_ok());
        assert!(validate_dotted_version("150.latest", "version", Some(4)).is_err());
    }

    #[test]
    fn component_download_urls_are_strictly_allowlisted() {
        for url in [
            "https://clients2.google.com/service/update2/crx",
            "https://www.google.com/dl/release2/file.crx3",
            "https://dl.google.com/release2/file.crx3",
            "https://edgedl.me.gvt1.com/edgedl/release2/file.crx3",
            "https://redirector.gvt1.com/edgedl/release2/file.crx3",
        ] {
            assert!(
                ensure_allowed_download_url(url).is_ok(),
                "expected allowlisted URL: {url}"
            );
        }

        for url in [
            "http://clients2.google.com/service/update2/crx",
            "https://clients2.google.com.evil.example/service/update2/crx",
            "https://clients2.google.com@evil.example/service/update2/crx",
            "https://dl.google.com:443/release2/file.crx3",
            "https://example.com/https://clients2.google.com/",
        ] {
            assert!(
                ensure_allowed_download_url(url).is_err(),
                "expected rejected URL: {url}"
            );
        }
    }
}
