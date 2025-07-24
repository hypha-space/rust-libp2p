use std::{convert::Infallible, marker::PhantomData};

use libp2p_swarm::NetworkBehaviour;

use super::*;
use crate::SwarmBuilder;

pub struct BehaviourPhase<T, R> {
    pub(crate) relay_behaviour: R,
    pub(crate) transport: T,
}

#[cfg(feature = "relay")]
impl<T, Provider> SwarmBuilder<Provider, BehaviourPhase<T, libp2p_relay::client::Behaviour>> {
    pub fn with_behaviour<B, R: TryIntoBehaviour<B>>(
        self,
        constructor: impl FnOnce(&libp2p_identity::Keypair, libp2p_relay::client::Behaviour) -> R,
    ) -> Result<SwarmBuilder<Provider, SwarmPhase<T, B>>, R::Error> {
        let keypair = libp2p_tls::identity_from_private_key(&self.private_key).unwrap();

        Ok(SwarmBuilder {
            phase: SwarmPhase {
                behaviour: constructor(&keypair, self.phase.relay_behaviour)
                    .try_into_behaviour()?,
                transport: self.phase.transport,
            },
            cert_chain: self.cert_chain,
            private_key: self.private_key,
            ca_certs: self.ca_certs,
            crls: self.crls,
            phantom: PhantomData,
        })
    }
}

impl<T, Provider> SwarmBuilder<Provider, BehaviourPhase<T, NoRelayBehaviour>> {
    pub fn with_behaviour<B, R: TryIntoBehaviour<B>>(
        self,
        constructor: impl FnOnce(&libp2p_identity::Keypair) -> R,
    ) -> Result<SwarmBuilder<Provider, SwarmPhase<T, B>>, R::Error> {
        // Discard `NoRelayBehaviour`.
        let _ = self.phase.relay_behaviour;

        let keypair = libp2p_tls::identity_from_private_key(&self.private_key).unwrap();

        Ok(SwarmBuilder {
            phase: SwarmPhase {
                behaviour: constructor(&keypair).try_into_behaviour()?,
                transport: self.phase.transport,
            },
            cert_chain: self.cert_chain,
            private_key: self.private_key,
            ca_certs: self.ca_certs,
            crls: self.crls,
            phantom: PhantomData,
        })
    }
}

pub trait TryIntoBehaviour<B>: private::Sealed<Self::Error> {
    type Error;

    fn try_into_behaviour(self) -> Result<B, Self::Error>;
}

impl<B> TryIntoBehaviour<B> for B
where
    B: NetworkBehaviour,
{
    type Error = Infallible;

    fn try_into_behaviour(self) -> Result<B, Self::Error> {
        Ok(self)
    }
}

impl<B> TryIntoBehaviour<B> for Result<B, Box<dyn std::error::Error + Send + Sync>>
where
    B: NetworkBehaviour,
{
    type Error = BehaviourError;

    fn try_into_behaviour(self) -> Result<B, Self::Error> {
        self.map_err(BehaviourError)
    }
}

mod private {
    pub trait Sealed<Error> {}
}

impl<B: NetworkBehaviour> private::Sealed<Infallible> for B {}

impl<B: NetworkBehaviour> private::Sealed<BehaviourError>
    for Result<B, Box<dyn std::error::Error + Send + Sync>>
{
}

#[derive(Debug, thiserror::Error)]
#[error("failed to build behaviour: {0}")]
pub struct BehaviourError(Box<dyn std::error::Error + Send + Sync + 'static>);
