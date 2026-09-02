//! Connects to the TLS inspection endpoint with the Chromium Root Store.
//!
//! The example configures BoringSSL through the published btls-sys FFI binding.

use std::error::Error;
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use btls::ssl::{SslConnector, SslContextBuilder, SslMethod};
use btls::x509::X509;
use btls::x509::store::X509StoreBuilder;
use chromium_roots::{ENCODED_TRUST_ANCHOR_IDS, TLS_SERVER_ROOT_CERTS, trust_anchor_ids};

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

fn main() -> Result<(), Box<dyn Error>> {
    let mut store = X509StoreBuilder::new()?;
    for root in TLS_SERVER_ROOT_CERTS {
        store.add_cert(X509::from_der(root.as_ref())?)?;
    }

    let mut connector = SslConnector::builder(SslMethod::tls())?;
    connector.set_verify_cert_store(store.build())?;

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
    for id in trust_anchor_ids() {
        let encoded = lowercase_hex(id);
        if !body.contains(&encoded) {
            return Err(io::Error::other(format!(
                "TLS inspection response is missing Trust Anchor ID {encoded}"
            ))
            .into());
        }
    }

    println!(
        "configured {} Chromium roots and {} encoded Trust Anchor ID bytes",
        TLS_SERVER_ROOT_CERTS.len(),
        ENCODED_TRUST_ANCHOR_IDS.len()
    );
    println!("{response}");

    Ok(())
}
