//! The high level API for pairwise channels.
//!
//! ┌─────────────┐                      ┌─────────────┐
//! │  Requester  │                      │  Responder  │
//! └──────┬──────┘                      └──────┬──────┘
//!        │              ┌──────┐              │
//!        ├──────────────┤ Dial ├─────────────▶│
//!        │              └──────┘              │
//!        │                                    │
//!        │              ┌───────┐             │
//!        │◀─────────────┤Connect├─────────────┤
//!        │              └───────┘             │
//!        │                                    │
//!        │           ┌──────────────┐         │
//!        ├───────────┤CounterConnect├────────▶│
//!        │           └──────────────┘         │
//!        │                                    │
//!        │              ┌───────┐             │
//!        │◀─────────────┤  Ack  ├─────────────┤
//!        │              └───────┘             │
//!        │                                    │
//! ┌──────┴──────┐                      ┌──────┴──────┐
//! │  Requester  │                      │  Responder  │
//! └─────────────┘                      └─────────────┘

use super::{
    ack::Ack, connect::Connect, counter_connect::CounterConnect, dial::Dial,
    disconnect::Disconnect, hash::Hash, signed::Signed,
};
use ed25519_dalek::{SigningKey, VerifyingKey};
use std::collections::{HashMap, HashSet};
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Incoming {
    Connecting(Hash<Signed<Connect>>),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Outgoing {
    Dialled(Hash<Signed<Dial>>),
    CounterConnecting(Hash<Signed<CounterConnect>>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Manager {
    /// The manager's verifying key.
    pub verifier: VerifyingKey,

    /// The manager's signing key.
    pub signer: SigningKey,

    /// State of current incoming handshakes.
    pub incoming: HashMap<VerifyingKey, Incoming>,

    /// State of current outgoing handshakes.
    pub outgoing: HashMap<VerifyingKey, Outgoing>,

    /// Peers that have successfully authenticated.
    pub confirmed: HashSet<VerifyingKey>,
}

impl Manager {
    pub fn new<R: rand::CryptoRng + rand::RngCore + Clone>(csprng: &mut R) -> Self {
        let signer = SigningKey::generate(csprng);

        Self {
            verifier: VerifyingKey::from(&signer),
            signer,
            incoming: HashMap::new(),
            outgoing: HashMap::new(),
            confirmed: HashSet::new(),
        }
    }

    pub fn dial<R: rand::CryptoRng + rand::Rng>(
        &mut self,
        to: &VerifyingKey,
        csprng: &mut R,
    ) -> Result<Signed<Dial>, signature::Error> {
        let challenge: u128 = csprng.gen();
        let signed = Signed::try_sign(Dial { to: *to, challenge }, &self.signer)?;
        let hash = Hash::hash(&signed);
        self.outgoing.insert(*to, Outgoing::Dialled(hash));
        Ok(signed)
    }

    pub fn receive_dial(
        &mut self,
        dial: &Signed<Dial>,
    ) -> Result<Signed<Connect>, ReceiveDialError> {
        dial.verify()?;

        if self.incoming.contains_key(&dial.verifier) {
            return Err(ReceiveDialError::DuplicateHandshake);
        }

        if self.confirmed.contains(&dial.verifier) {
            return Err(ReceiveDialError::DuplicateSession);
        }

        let d_hash: Hash<Signed<Dial>> = Hash::hash(dial);
        let signed = Signed::try_sign(Connect(d_hash), &self.signer)?;
        let s_hash: Hash<Signed<Connect>> = Hash::hash(&signed);

        self.incoming
            .insert(dial.verifier, Incoming::Connecting(s_hash));

        Ok(signed)
    }

    pub fn receive_connect(
        &mut self,
        connect: &Signed<Connect>,
    ) -> Result<Signed<CounterConnect>, ReceiveConnectError> {
        connect.verify()?;

        match self.outgoing.get(&connect.verifier) {
            Some(Outgoing::Dialled(d)) if d == &connect.payload.0 => {}
            _ => return Err(ReceiveConnectError::UnknownHandshake),
        };

        let connect_hash = Hash::hash(connect);
        let cc: Signed<CounterConnect> =
            Signed::try_sign(CounterConnect(connect_hash), &self.signer)?;
        let cc_hash: Hash<Signed<CounterConnect>> = Hash::hash(&cc);

        self.outgoing
            .insert(connect.verifier, Outgoing::CounterConnecting(cc_hash));

        Ok(cc)
    }

    pub fn receive_counter_connect(
        &mut self,
        counter_connect: &Signed<CounterConnect>,
    ) -> Result<Signed<Ack>, ReceiveConnectError> {
        counter_connect.verify()?;

        match self.incoming.get(&counter_connect.verifier) {
            Some(Incoming::Connecting(d)) if d == &counter_connect.payload.0 => {}
            _ => return Err(ReceiveConnectError::UnknownHandshake),
        };

        let ack = Signed::try_sign(Ack, &self.signer)?;
        self.confirmed.insert(counter_connect.verifier);

        Ok(ack)
    }

    pub fn receive_ack(&mut self, ack: &Signed<Ack>) -> Result<(), ReceiveAckError> {
        ack.verify()?;

        if self.outgoing.remove(&ack.verifier).is_none() {
            return Err(ReceiveAckError::UnknownHandshake);
        }

        self.confirmed.insert(ack.verifier);

        Ok(())
    }

    pub fn disconnect(
        &mut self,
        peer: VerifyingKey,
    ) -> Result<Signed<Disconnect>, signature::Error> {
        Signed::try_sign(Disconnect(peer), &self.signer)
    }

    pub fn receive_disconnect(
        &mut self,
        disconnect: &Signed<Disconnect>,
    ) -> Result<(), signature::Error> {
        disconnect.verify()?;

        self.outgoing.remove(&disconnect.verifier);
        self.incoming.remove(&disconnect.verifier);
        self.confirmed.remove(&disconnect.verifier);

        Ok(())
    }
}

#[derive(Debug, Error)]
pub enum ReceiveDialError {
    #[error("Invalid signature")]
    InvalidSignature(#[from] signature::Error),

    #[error("Duplicate handshake")]
    DuplicateHandshake,

    #[error("Duplicate session")]
    DuplicateSession,
}

#[derive(Debug, Error)]
pub enum ReceiveConnectError {
    #[error("Invalid signature")]
    InvalidSignature(#[from] signature::Error),

    #[error("Handshake challenge conflict")]
    HandshakeChallengeConflict,

    #[error("Unknown handshake")]
    UnknownHandshake,
}

#[derive(Debug, Error)]
pub enum ReceiveAckError {
    #[error("Invalid signature")]
    InvalidSignature(#[from] signature::Error),

    #[error("Unknown handshake")]
    UnknownHandshake,
}
