//! Connects to the TLS inspection endpoint with the Chromium Root Store.
//!
//! The example configures `BoringSSL` through the published `btls-sys` FFI binding.
//! It enforces Chromium's anchor-expiry and X.509 anchor-constraint flags, but
//! does not reproduce Chromium's separate SCT, browser-version, or DNS rules.

use std::{
    error::Error,
    io::{self, Read, Write},
    net::TcpStream,
    time::Duration,
};

use btls::{
    ssl::{SslConnector, SslContextBuilder, SslMethod},
    stack::Stack,
    x509::{
        X509, X509StoreContext, X509StoreContextRef,
        store::{X509Store, X509StoreBuilder},
    },
};
use chromium_roots::{ENCODED_TRUST_ANCHOR_IDS, TLS_TRUST_ANCHORS, TrustAnchorKind};
use foreign_types_shared::ForeignTypeRef;

const HOST: &str = "pingly.us.kg";
const ADDRESS: &str = "pingly.us.kg:443";

#[expect(
    unsafe_code,
    reason = "btls-sys exposes BoringSSL trust anchor configuration as unsafe FFI"
)]
fn set_requested_trust_anchors(context: &mut SslContextBuilder) -> io::Result<()> {
    // SAFETY: the context is valid for the duration of the call, and the set1
    // API copies the complete static ID slice before returning.
    let accepted = unsafe {
        btls_sys::SSL_CTX_set1_requested_trust_anchors(
            context.as_ptr(),
            ENCODED_TRUST_ANCHOR_IDS.as_ptr(),
            ENCODED_TRUST_ANCHOR_IDS.len(),
        ) == 1
    };
    if accepted {
        Ok(())
    } else {
        Err(io::Error::other(
            "BoringSSL rejected the generated Trust Anchor ID list",
        ))
    }
}

fn lowercase_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";

    let mut encoded = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        encoded.push(char::from(DIGITS[usize::from(byte >> 4)]));
        encoded.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn build_certificate_store() -> Result<(X509Store, Vec<X509>), Box<dyn Error>> {
    let mut store = X509StoreBuilder::new()?;
    let mut constrained_anchors = Vec::new();

    for anchor in TLS_TRUST_ANCHORS {
        let certificate = X509::from_der(anchor.der)?;

        if anchor.enforce_anchor_expiry || anchor.enforce_anchor_constraints {
            // btls exposes BoringSSL's legacy X509_STORE API, not the C++
            // CertificateTrust API used by Chromium. In the current snapshot,
            // every constrained anchor is an expiring subordinate CA. Supplying
            // it as an untrusted intermediate makes the legacy verifier apply
            // its validity period and X.509 constraints instead of exempting it
            // as the terminal trust anchor. Reject future combinations this
            // workaround cannot represent exactly.
            if !anchor.enforce_anchor_expiry
                || !anchor.enforce_anchor_constraints
                || anchor.kind != TrustAnchorKind::Additional
            {
                return Err(io::Error::other(format!(
                    "cannot safely represent Chromium anchor flags for SHA-256 {}",
                    lowercase_hex(&anchor.sha256)
                ))
                .into());
            }
            constrained_anchors.push(certificate);
        } else {
            store.add_cert(certificate)?;
        }
    }

    Ok((store.build(), constrained_anchors))
}

#[expect(
    unsafe_code,
    reason = "btls does not expose X509_VERIFY_PARAM_set1 through its safe API"
)]
fn copy_verification_parameters(
    source: &X509StoreContextRef,
    destination: &mut X509StoreContextRef,
) -> bool {
    // SAFETY: both contexts are initialized and remain alive for this call.
    // X509_VERIFY_PARAM_set1 copies the source parameters into the destination.
    unsafe {
        let source = btls_sys::X509_STORE_CTX_get0_param(source.as_ptr());
        let destination = btls_sys::X509_STORE_CTX_get0_param(destination.as_ptr());
        !source.is_null()
            && !destination.is_null()
            && btls_sys::X509_VERIFY_PARAM_set1(destination, source) == 1
    }
}

fn verify_with_constrained_anchors(
    context: &mut X509StoreContextRef,
    store: &X509Store,
    constrained_anchors: &[X509],
) -> bool {
    let Some(leaf) = context.cert() else {
        return false;
    };
    let Ok(mut untrusted) = Stack::new() else {
        return false;
    };

    if let Some(peer_intermediates) = context.untrusted() {
        for certificate in peer_intermediates {
            if untrusted.push(certificate.to_owned()).is_err() {
                return false;
            }
        }
    }
    for anchor in constrained_anchors {
        if untrusted.push(anchor.clone()).is_err() {
            return false;
        }
    }

    let Ok(mut verifier) = X509StoreContext::new() else {
        return false;
    };
    verifier
        .init(store, leaf, &untrusted, |verifier| {
            Ok(copy_verification_parameters(context, verifier)
                && verifier.verify_cert().unwrap_or(false))
        })
        .unwrap_or(false)
}

fn main() -> Result<(), Box<dyn Error>> {
    let (store, constrained_anchors) = build_certificate_store()?;
    let direct_anchor_count = TLS_TRUST_ANCHORS.len() - constrained_anchors.len();
    let constrained_anchor_count = constrained_anchors.len();

    let mut connector = SslConnector::builder(SslMethod::tls())?;
    connector.set_verify_cert_store(store.clone())?;
    connector.set_cert_verify_callback(move |context| {
        verify_with_constrained_anchors(context, &store, &constrained_anchors)
    });

    set_requested_trust_anchors(&mut connector)?;

    let connector = connector.build();
    let tcp = TcpStream::connect(ADDRESS)?;
    tcp.set_read_timeout(Some(Duration::from_secs(30)))?;
    tcp.set_write_timeout(Some(Duration::from_secs(30)))?;
    let mut tls = connector.connect(HOST, tcp)?;

    tls.write_all(
        b"GET /api/tls HTTP/1.1\r\nHost: pingly.us.kg\r\nAccept: application/json\r\nConnection: close\r\n\r\n",
    )?;

    let mut response = String::new();
    tls.read_to_string(&mut response)?;

    if !response.starts_with("HTTP/1.1 200 ") && !response.starts_with("HTTP/1.0 200 ") {
        return Err(io::Error::other("TLS inspection endpoint did not return HTTP 200").into());
    }
    let (_, body) = response
        .split_once("\r\n\r\n")
        .ok_or_else(|| io::Error::other("TLS inspection response has no header terminator"))?;
    if !body.contains("\"trust_anchors\"") {
        return Err(io::Error::other(
            "TLS inspection response does not report the trust_anchors extension",
        )
        .into());
    }
    for id in TLS_TRUST_ANCHORS
        .iter()
        .filter_map(|anchor| anchor.trust_anchor_id)
    {
        let encoded = lowercase_hex(id);
        if !body.contains(&encoded) {
            return Err(io::Error::other(format!(
                "TLS inspection response is missing Trust Anchor ID {encoded}"
            ))
            .into());
        }
    }

    println!(
        "configured {direct_anchor_count} direct Chromium anchors, \
         {constrained_anchor_count} constrained anchors, and {} encoded Trust Anchor ID bytes",
        ENCODED_TRUST_ANCHOR_IDS.len()
    );
    println!("{response}");

    Ok(())
}
