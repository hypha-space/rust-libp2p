use std::marker::PhantomData;

use super::*;
use crate::SwarmBuilder;

pub struct IdentityPhase {}

impl SwarmBuilder<NoProviderSpecified, IdentityPhase> {
    // pub fn with_new_identity() -> SwarmBuilder<NoProviderSpecified, ProviderPhase> {
    //     SwarmBuilder::with_existing_identity(libp2p_identity::Keypair::generate_ed25519())
    // }

    pub fn with_existing_identity(
        cert_chain: Vec<CertificateDer<'static>>,
        private_key: PrivateKeyDer<'static>,
        ca_certs: Vec<CertificateDer<'static>>,
        crls: Vec<CertificateRevocationListDer<'static>>,
    ) -> SwarmBuilder<NoProviderSpecified, ProviderPhase> {
        SwarmBuilder {
            cert_chain,
            private_key,
            ca_certs,
            crls,
            phantom: PhantomData,
            phase: ProviderPhase {},
        }
    }
}
