// Copyright 2017-2020 Parity Technologies (UK) Ltd.
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

//! Future that drives a QUIC connection until is has performed its TLS handshake.

use std::{
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use ed25519_dalek::{pkcs8::DecodePublicKey, VerifyingKey};
use futures::{
    future::{select, Either, FutureExt, Select},
    prelude::*,
};
use futures_timer::Delay;
use libp2p_identity::{PeerId, PublicKey};
use libp2p_tls::CertificateDer;
use webpki::EndEntityCert;

use crate::{Connection, ConnectionError, Error};

/// A QUIC connection currently being negotiated.
#[derive(Debug)]
pub struct Connecting {
    connecting: Select<quinn::Connecting, Delay>,
}

impl Connecting {
    pub(crate) fn new(connection: quinn::Connecting, timeout: Duration) -> Self {
        Connecting {
            connecting: select(connection, Delay::new(timeout)),
        }
    }
}

impl Connecting {
    /// Returns the address of the node we're connected to.
    /// Panics if the connection is still handshaking.
    fn remote_peer_id(connection: &quinn::Connection) -> PeerId {
        let identity = connection
            .peer_identity()
            .expect("connection got identity because it passed TLS handshake; qed");
        let certificates: Box<Vec<CertificateDer>> =
            identity.downcast().expect("we rely on rustls feature; qed");
        let end_entity = certificates
            .first()
            .expect("there should be exactly one certificate; qed");

        let end_entity_cert =
            EndEntityCert::try_from(end_entity).expect("the certificate is parseable");

        let spki_der = end_entity_cert.subject_public_key_info();

        let verifying_key = VerifyingKey::from_public_key_der(spki_der.as_ref())
            .expect("the verifying key is extracted");

        let ed25519_public =
            libp2p_identity::ed25519::PublicKey::try_from_bytes(verifying_key.as_bytes())
                .expect("a public key");

        let public_key = PublicKey::from(ed25519_public);

        public_key.to_peer_id()
    }
}

impl Future for Connecting {
    type Output = Result<(PeerId, Connection), Error>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let connection = match futures::ready!(self.connecting.poll_unpin(cx)) {
            Either::Right(_) => return Poll::Ready(Err(Error::HandshakeTimedOut)),
            Either::Left((connection, _)) => connection.map_err(ConnectionError)?,
        };

        let peer_id = Self::remote_peer_id(&connection);
        let muxer = Connection::new(connection);
        Poll::Ready(Ok((peer_id, muxer)))
    }
}
