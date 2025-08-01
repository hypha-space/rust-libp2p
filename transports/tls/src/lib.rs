// Copyright 2021 Parity Technologies (UK) Ltd.
// Copyright 2022 Protocol Labs.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.

//! TLS configuration based on libp2p TLS specs.
//!
//! See <https://github.com/libp2p/specs/blob/master/tls/tls.md>.

#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]

pub mod certificate;
mod upgrade;
mod verifier;

use std::sync::Arc;

use ed25519_dalek::{
    pkcs8::{self, DecodePrivateKey},
    SigningKey,
};
pub use futures_rustls::TlsStream;
pub use rustls::pki_types::{CertificateDer, CertificateRevocationListDer, PrivateKeyDer};
use rustls::{client::WebPkiServerVerifier, server::WebPkiClientVerifier, RootCertStore};
use thiserror::Error;
pub use upgrade::{Config, UpgradeError};

use crate::verifier::ServerCertVerifierWithUnspecifiedName;

/// Create a TLS client configuration for libp2p.
pub fn make_client_config(
    cert_chain: Vec<CertificateDer<'static>>,
    private_key: PrivateKeyDer<'static>,
    ca_certs: Vec<CertificateDer<'static>>,
    crls: Vec<CertificateRevocationListDer<'static>>,
) -> Result<rustls::ClientConfig, certificate::GenError> {
    // Create root cert store with CA certificates
    let mut root_store = RootCertStore::empty();
    for ca_cert in &ca_certs {
        root_store.add(ca_cert.clone()).unwrap();
    }

    let mut provider = rustls::crypto::ring::default_provider();
    provider.cipher_suites = verifier::CIPHERSUITES.to_vec();

    let server_verifier = WebPkiServerVerifier::builder(Arc::new(root_store))
        .with_crls(crls)
        .build()
        .unwrap();

    let server_verifier = Arc::new(ServerCertVerifierWithUnspecifiedName::new(server_verifier));

    // TODO: Add CRL validation for server certificates.
    Ok(rustls::ClientConfig::builder_with_provider(provider.into())
        .with_protocol_versions(verifier::PROTOCOL_VERSIONS)
        .expect("Cipher suites and kx groups are configured; qed")
        .dangerous()
        .with_custom_certificate_verifier(server_verifier)
        .with_client_auth_cert(cert_chain, private_key)
        .unwrap())
}

/// Create a TLS server configuration for libp2p.
pub fn make_server_config(
    cert_chain: Vec<CertificateDer<'static>>,
    private_key: PrivateKeyDer<'static>,
    ca_certs: Vec<CertificateDer<'static>>,
    crls: Vec<CertificateRevocationListDer<'static>>,
) -> Result<rustls::ServerConfig, certificate::GenError> {
    // Create root cert store with CA certificates
    let mut root_store = RootCertStore::empty();
    for ca_cert in &ca_certs {
        root_store.add(ca_cert.clone()).unwrap();
    }

    let mut provider = rustls::crypto::ring::default_provider();
    provider.cipher_suites = verifier::CIPHERSUITES.to_vec();

    // Create verifier that requires and validates client certificates
    let client_verifier = WebPkiClientVerifier::builder(Arc::new(root_store))
        .with_crls(crls)
        .build()
        .unwrap();

    let crypto = rustls::ServerConfig::builder_with_provider(provider.into())
        .with_protocol_versions(verifier::PROTOCOL_VERSIONS)
        .expect("Cipher suites and kx groups are configured; qed")
        .with_client_cert_verifier(client_verifier)
        .with_single_cert(cert_chain, private_key)
        .unwrap();

    Ok(crypto)
}

/// Errors that can occur when parsing certificates.
#[derive(Error, Debug)]
pub enum ParseError {
    /// Invalid certificate format
    #[error("Invalid certificate format")]
    InvalidFormat,
    /// Decoding error
    #[error("Decoding error")]
    Decoding(#[from] libp2p_identity::DecodingError),
    /// Parse error
    #[error("PKCS8 error")]
    Parse(#[from] pkcs8::Error),
}

/// Create a libp2p identity from a private key
pub fn identity_from_private_key(
    private_key: &rustls::pki_types::PrivateKeyDer<'static>,
) -> Result<libp2p_identity::Keypair, ParseError> {
    match private_key {
        PrivateKeyDer::Pkcs8(key) => {
            let key = SigningKey::from_pkcs8_der(key.secret_pkcs8_der())?;

            libp2p_identity::Keypair::ed25519_from_bytes(key.to_bytes())
                .map_err(ParseError::Decoding)
        }
        _ => Err(ParseError::InvalidFormat),
    }
}
