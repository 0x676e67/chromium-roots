//! Connects to the TLS inspection endpoint with the Chromium Root Store.
//!
//! The example configures BoringSSL through the published btls-sys FFI binding.

use std::error::Error;
use std::io::{Read, Write};
use std::net::TcpStream;

use btls::ssl::{SslConnector, SslContextBuilder, SslMethod};
use btls::x509::X509;
use btls::x509::store::X509StoreBuilder;
use chromium_root_certs::{ENCODED_TRUST_ANCHOR_IDS, TLS_SERVER_ROOT_CERTS};

const HOST: &str = "pingly.us.kg";
const ADDRESS: &str = "pingly.us.kg:443";

#[expect(
    unsafe_code,
    reason = "btls-sys exposes BoringSSL trust anchor configuration as unsafe FFI"
)]
fn set_requested_trust_anchors(context: &SslContextBuilder) -> bool {
    // SAFETY: the context is valid for the duration of the call, and the set1
    // API copies the complete static ID slice before returning.
    unsafe {
        btls_sys::SSL_CTX_set1_requested_trust_anchors(
            context.as_ptr(),
            ENCODED_TRUST_ANCHOR_IDS.as_ptr(),
            ENCODED_TRUST_ANCHOR_IDS.len(),
        ) == 1
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let mut store = X509StoreBuilder::new()?;
    for root in TLS_SERVER_ROOT_CERTS {
        store.add_cert(X509::from_der(root.as_ref())?)?;
    }

    let mut connector = SslConnector::builder(SslMethod::tls())?;
    connector.set_verify_cert_store(store.build())?;

    if !set_requested_trust_anchors(&connector) {
        return Err(
            std::io::Error::other("BoringSSL rejected the generated Trust Anchor ID list").into(),
        );
    }

    let connector = connector.build();
    let tcp = TcpStream::connect(ADDRESS)?;
    let mut tls = connector.connect(HOST, tcp)?;

    tls.write_all(
        b"GET /api/tls HTTP/1.1\r\nHost: pingly.us.kg\r\nAccept: application/json\r\nConnection: close\r\n\r\n",
    )?;

    let mut response = String::new();
    tls.read_to_string(&mut response)?;

    println!(
        "configured {} Chromium roots and {} encoded Trust Anchor ID bytes",
        TLS_SERVER_ROOT_CERTS.len(),
        ENCODED_TRUST_ANCHOR_IDS.len()
    );
    println!("{response}");

    Ok(())
}
