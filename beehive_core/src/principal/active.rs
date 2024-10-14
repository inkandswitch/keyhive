//! The current user agent (which can sign and encrypt).

use super::{document::Document, individual::Individual, traits::Verifiable};
use crate::{
    access::Access,
    crypto::{
        digest::Digest, encrypted::Encrypted, share_key::ShareKey, signed::Signed, siv::Siv,
        symmetric_key::SymmetricKey,
    },
    principal::{
        agent::Agent,
        group::operation::{delegation::Delegation, revocation::Revocation},
        membered::Membered,
    },
};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::Serialize;
use std::{collections::BTreeMap, fmt::Debug};

/// The current user agent (which can sign and encrypt).
#[derive(Clone)]
pub struct Active {
    /// The signing key of the active agent.
    pub signer: SigningKey,

    /// The encryption "sharing" key pairs that the active agent has.
    /// This includes the secret keys for ECDH.
    pub share_key_pairs: BTreeMap<ShareKey, x25519_dalek::StaticSecret>,
}

impl Active {
    pub fn new(signer: SigningKey) -> Self {
        Self {
            signer,
            share_key_pairs: BTreeMap::new(), // FIXME
        }
    }

    pub fn as_individual(&self) -> Individual {
        self.id().into()
    }

    pub fn as_agent<T: Clone + Ord + Serialize>(&self) -> Agent<T> {
        self.as_individual().into()
    }

    /// Generate a new active agent with a random key pair.
    pub fn generate() -> Self {
        let signer = SigningKey::generate(&mut rand::thread_rng());
        Self::new(signer)
    }

    /// Sign a payload.
    pub fn sign<U: Serialize + Clone>(&self, payload: U) -> Signed<U> {
        Signed::<U>::sign(payload, &self.signer)
    }

    pub fn get_capability<'a, T: Serialize + Clone + Ord + Serialize>(
        &'a self,
        subject: &'a Membered<'a, T>,
        min: Access,
    ) -> Option<&'a Signed<Delegation<T>>> {
        subject.get(&self.as_agent()).and_then(|cap| {
            if cap.payload.can >= min {
                Some(cap)
            } else {
                None
            }
        })
    }

    // FIXME put this on Capability?
    pub fn make_delegation<'a, T: Clone + Ord + Serialize>(
        &'a self,
        subject: &'a Membered<'a, T>,
        attenuate: Access,
        delegate: &'a Agent<'a, T>,
        after_revocations: Vec<&'a Signed<Revocation<'a, T>>>,
        after_content: Vec<(&'a Document<'a, T>, Digest<T>)>,
    ) -> Result<Signed<Delegation<'a, T>>, DelegationError> {
        let proof = self.get_capability(&subject, attenuate).expect("FIXME");

        if attenuate > proof.payload.can {
            return Err(DelegationError::Escelation);
        }

        let delegation = self.sign(Delegation {
            can: attenuate,
            delegate,
            proof: Some(proof),
            after_revocations,
            after_content,
        });

        // FIXME would be nice to IVM here, but lifetimes

        Ok(delegation)
    }

    pub fn encrypt_to<'a, T: Clone + Ord + Serialize>(
        &self,
        doc: &Document<'a, T>,
        to: &Individual,
        message: &mut [u8],
    ) -> Encrypted<&[u8]> {
        let recipient_share_pk = doc.reader_keys.get(to).expect("FIXME");
        let our_pk = doc
            .reader_keys
            .get(&Individual::from(self.id()))
            .expect("FIXME");

        let our_sk = self.share_key_pairs.get(our_pk).expect("FIXME");

        let key: SymmetricKey = our_sk
            .diffie_hellman(&recipient_share_pk.clone().into())
            .into();

        let nonce = Siv::new(&key, message, doc);
        let bytes: Vec<u8> = key.encrypt(nonce, message).expect("FIXME").to_vec();

        Encrypted::new(nonce.clone().into(), bytes)
    }
}

// FIXME move to Delegation?
/// Errors that can occur when using an active agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DelegationError {
    /// The active agent is trying to delegate a capability that they do not have.
    Escelation,
}

impl std::fmt::Display for Active {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.id())
    }
}

impl Debug for Active {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let keypairs_hidden_secret_keys: Vec<(&ShareKey, &str)> = self
            .share_key_pairs
            .iter()
            .map(|(pk, _sk)| (pk, "<SecretKey>"))
            .collect();

        f.debug_struct("Active")
            .field("id", &self.id())
            .field("signer", &"<Signer>")
            .field("share_key_pairs", &keypairs_hidden_secret_keys)
            .finish()
    }
}

impl<'a, T: Clone + Ord + Serialize> From<Active> for Agent<'a, T> {
    fn from(active: Active) -> Self {
        Agent::Individual(active.id().into())
    }
}

impl From<Active> for Individual {
    fn from(active: Active) -> Self {
        active.id().into()
    }
}

impl Verifiable for Active {
    fn verifying_key(&self) -> VerifyingKey {
        self.signer.verifying_key()
    }
}

impl Signer<Signature> for Active {
    fn try_sign(&self, message: &[u8]) -> Result<Signature, signature::Error> {
        self.signer.try_sign(message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign() {
        let active = Active::generate();
        let message = "hello world".as_bytes();
        let signed = active.sign(message);

        assert!(signed.verify().is_ok());
    }
}
