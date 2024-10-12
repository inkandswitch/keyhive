//! The current user agent (which can sign and encrypt).

use super::{document::Document, individual::Individual, traits::Verifiable};
use crate::{
    access::Access,
    crypto::{
        encrypted::Encrypted, hash::Hash, share_key::ShareKey, signed::Signed, siv::Siv,
        symmetric_key::SymmetricKey,
    },
    principal::{
        agent::Agent,
        group::operation::{delegation::Delegation, revocation::Revocation},
    },
};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
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

    /// Generate a new active agent with a random key pair.
    pub fn generate() -> Self {
        let signer = SigningKey::generate(&mut rand::thread_rng());
        Self::new(signer)
    }

    /// Sign a payload.
    pub fn sign<U: Clone + std::hash::Hash>(&self, payload: U) -> Signed<U>
    where
        Vec<u8>: From<U>, // FIXME swap for serde? also maybe impl signature::signer?
    {
        Signed::<U>::sign(payload, &self.signer)
    }

    // FIXME put this on Capability?
    pub fn delegate<'a, T: std::hash::Hash + Clone>(
        &self,
        proof: &mut Signed<Delegation<'a, T>>,
        attenuate: Access,
        to: &Agent<'a, T>,
        after_revocations: Vec<&'a Signed<Revocation<'a, T>>>,
        after_content: Vec<(&Document<'a, T>, Hash<T>)>,
    ) -> Result<Signed<Delegation<'a, T>>, DelegationError> {
        if attenuate > proof.payload.can {
            return Err(DelegationError::Escelation);
        }

        let delegation = self.sign(Delegation {
            can: attenuate,
            delegate: to,
            proof: Some(proof),
            after_revocations,
            after_content,
        });

        proof.subject.add_member(delegation.clone());

        Ok(delegation)
    }

    pub fn encrypt_to<'a, T: std::hash::Hash + Clone>(
        &self,
        doc: &Document<'a, T>,
        to: &Individual,
        message: &mut [u8],
    ) -> Encrypted<&[u8]> {
        let recipient_share_pk = doc.reader_keys.get(to).expect("FIXME");
        let our_pk = doc.reader_keys.get(&self.id().into()).expect("FIXME");
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

impl<'a, T: std::hash::Hash + Clone> From<Active> for Agent<'a, T> {
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

// FIXME test
impl std::hash::Hash for Active {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        state.write(self.signer.to_bytes().as_ref());

        for (pk, sk) in self.share_key_pairs.iter() {
            state.write(pk.as_bytes().as_ref());
            state.write(sk.as_bytes().as_ref());
        }

        state.finish();
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
