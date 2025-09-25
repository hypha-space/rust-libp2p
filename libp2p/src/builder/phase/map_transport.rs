use std::marker::PhantomData;

use super::*;
use crate::SwarmBuilder;

impl<Provider, T: AuthenticatedMultiplexedTransport> SwarmBuilder<Provider, QuicPhase<T>> {
    /// Map the current transport to another transport.
    ///
    /// This is a low-level escape hatch primarily intended for custom adapters, or
    /// instrumentation/telemetry layers. Prefer the
    /// dedicated builder helpers (like `with_bandwidth_metrics`)
    /// where possible.
    pub fn map_transport<U, F>(
        self,
        f: F,
    ) -> SwarmBuilder<Provider, QuicPhase<impl AuthenticatedMultiplexedTransport>>
    where
        U: AuthenticatedMultiplexedTransport,
        F: FnOnce(T) -> U,
    {
        SwarmBuilder {
            cert_chain: self.cert_chain,
            private_key: self.private_key,
            ca_certs: self.ca_certs,
            crls: self.crls,
            phantom: PhantomData,
            phase: QuicPhase {
                transport: f(self.phase.transport),
            },
        }
    }
}

impl<Provider, T: AuthenticatedMultiplexedTransport>
    SwarmBuilder<Provider, OtherTransportPhase<T>>
{
    pub fn map_transport<U, F>(
        self,
        f: F,
    ) -> SwarmBuilder<Provider, OtherTransportPhase<impl AuthenticatedMultiplexedTransport>>
    where
        U: AuthenticatedMultiplexedTransport,
        F: FnOnce(T) -> U,
    {
        SwarmBuilder {
            cert_chain: self.cert_chain,
            private_key: self.private_key,
            ca_certs: self.ca_certs,
            crls: self.crls,
            phantom: PhantomData,
            phase: OtherTransportPhase {
                transport: f(self.phase.transport),
            },
        }
    }
}

impl<Provider, T: AuthenticatedMultiplexedTransport> SwarmBuilder<Provider, DnsPhase<T>> {
    pub fn map_transport<U, F>(
        self,
        f: F,
    ) -> SwarmBuilder<Provider, DnsPhase<impl AuthenticatedMultiplexedTransport>>
    where
        U: AuthenticatedMultiplexedTransport,
        F: FnOnce(T) -> U,
    {
        SwarmBuilder {
            cert_chain: self.cert_chain,
            private_key: self.private_key,
            ca_certs: self.ca_certs,
            crls: self.crls,
            phantom: PhantomData,
            phase: DnsPhase {
                transport: f(self.phase.transport),
            },
        }
    }
}

impl<Provider, T: AuthenticatedMultiplexedTransport> SwarmBuilder<Provider, WebsocketPhase<T>> {
    pub fn map_transport<U, F>(
        self,
        f: F,
    ) -> SwarmBuilder<Provider, WebsocketPhase<impl AuthenticatedMultiplexedTransport>>
    where
        U: AuthenticatedMultiplexedTransport,
        F: FnOnce(T) -> U,
    {
        SwarmBuilder {
            cert_chain: self.cert_chain,
            private_key: self.private_key,
            ca_certs: self.ca_certs,
            crls: self.crls,
            phantom: PhantomData,
            phase: WebsocketPhase {
                transport: f(self.phase.transport),
            },
        }
    }
}

impl<Provider, T: AuthenticatedMultiplexedTransport> SwarmBuilder<Provider, RelayPhase<T>> {
    pub fn map_transport<U, F>(
        self,
        f: F,
    ) -> SwarmBuilder<Provider, RelayPhase<impl AuthenticatedMultiplexedTransport>>
    where
        U: AuthenticatedMultiplexedTransport,
        F: FnOnce(T) -> U,
    {
        SwarmBuilder {
            cert_chain: self.cert_chain,
            private_key: self.private_key,
            ca_certs: self.ca_certs,
            crls: self.crls,
            phantom: PhantomData,
            phase: RelayPhase {
                transport: f(self.phase.transport),
            },
        }
    }
}

impl<Provider, T: AuthenticatedMultiplexedTransport, R>
    SwarmBuilder<Provider, BandwidthMetricsPhase<T, R>>
{
    pub fn map_transport<U, F>(
        self,
        f: F,
    ) -> SwarmBuilder<Provider, BandwidthMetricsPhase<impl AuthenticatedMultiplexedTransport, R>>
    where
        U: AuthenticatedMultiplexedTransport,
        F: FnOnce(T) -> U,
    {
        SwarmBuilder {
            cert_chain: self.cert_chain,
            private_key: self.private_key,
            ca_certs: self.ca_certs,
            crls: self.crls,
            phantom: PhantomData,
            phase: BandwidthMetricsPhase {
                relay_behaviour: self.phase.relay_behaviour,
                transport: f(self.phase.transport),
            },
        }
    }
}

impl<Provider, T: AuthenticatedMultiplexedTransport, R>
    SwarmBuilder<Provider, BehaviourPhase<T, R>>
{
    pub fn map_transport<U, F>(
        self,
        f: F,
    ) -> SwarmBuilder<Provider, BehaviourPhase<impl AuthenticatedMultiplexedTransport, R>>
    where
        U: AuthenticatedMultiplexedTransport,
        F: FnOnce(T) -> U,
    {
        SwarmBuilder {
            cert_chain: self.cert_chain,
            private_key: self.private_key,
            ca_certs: self.ca_certs,
            crls: self.crls,
            phantom: PhantomData,
            phase: BehaviourPhase {
                relay_behaviour: self.phase.relay_behaviour,
                transport: f(self.phase.transport),
            },
        }
    }
}

impl<Provider, T: AuthenticatedMultiplexedTransport, B> SwarmBuilder<Provider, SwarmPhase<T, B>> {
    pub fn map_transport<U, F>(
        self,
        f: F,
    ) -> SwarmBuilder<Provider, SwarmPhase<impl AuthenticatedMultiplexedTransport, B>>
    where
        U: AuthenticatedMultiplexedTransport,
        F: FnOnce(T) -> U,
    {
        SwarmBuilder {
            cert_chain: self.cert_chain,
            private_key: self.private_key,
            ca_certs: self.ca_certs,
            crls: self.crls,
            phantom: PhantomData,
            phase: SwarmPhase {
                behaviour: self.phase.behaviour,
                transport: f(self.phase.transport),
            },
        }
    }
}
