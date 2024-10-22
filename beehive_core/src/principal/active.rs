//! The current user agent (which can sign and encrypt).

use super::{
    document::{id::DocumentId, Document},
    individual::{id::IndividualId, Individual},
    verifiable::Verifiable,
};
use crate::{
    access::Access,
    content::reference::ContentRef,
    crypto::{
        encrypted::Encrypted, share_key::ShareKey, signed::Signed, siv::Siv,
        symmetric_key::SymmetricKey,
    },
    principal::{
        agent::{Agent, AgentId},
        group::operation::{delegation::Delegation, revocation::Revocation},
        membered::Membered,
    },
};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::Serialize;
use std::{collections::BTreeMap, fmt::Debug};

/// The current user agent (which can sign and encrypt).
#[derive(Clone, Serialize)]
pub struct Active {
    /// The signing key of the active agent.
    pub signer: SigningKey,

    /// The encryption "sharing" key pairs that the active agent has.
    /// This includes the secret keys for ECDH.
    pub share_key_pairs: BTreeMap<ShareKey, x25519_dalek::StaticSecret>, // FIXME generalize to use e.g. KMS

    pub individual: Individual,
}

impl Active {
    pub fn generate(signer: SigningKey) -> Self {
        Self {
            individual: Individual::generate(&signer),
            share_key_pairs: BTreeMap::new(),
            signer,
        }
    }

    pub fn id(&self) -> IndividualId {
        self.individual.id()
    }

    pub fn agent_id(&self) -> AgentId {
        AgentId::IndividualId(self.id().into())
    }

    /// Sign a payload.
    pub fn sign<U: Serialize>(&self, payload: U) -> Signed<U> {
        Signed::<U>::sign(payload, &self.signer)
    }

    pub fn get_capability<'a, T: ContentRef>(
        &'a self,
        subject: &'a Membered<'a, T>,
        min: Access,
    ) -> Option<&'a Signed<Delegation<T>>> {
        subject.get_capability(&self.agent_id()).and_then(|cap| {
            if cap.payload().can >= min {
                Some(cap)
            } else {
                None
            }
        })
    }

    // FIXME replace with delegate_to
    pub fn make_delegation<'a, T: ContentRef>(
        &'a self,
        subject: &'a Membered<'a, T>,
        attenuate: Access,
        delegate: Agent<'a, T>,
        after_revocations: Vec<&'a Signed<Revocation<T>>>,
        after_content: BTreeMap<DocumentId, (&'a Document<T>, Vec<T>)>,
    ) -> Result<Signed<Delegation<T>>, DelegationError> {
        let proof = self.get_capability(&subject, attenuate).expect("FIXME");

        if attenuate > proof.payload().can {
            return Err(DelegationError::Escelation);
        }

        let delegation = self.sign(Delegation {
            delegate,
            can: attenuate,
            proof: Some(proof),
            after_revocations,
            after_content,
        });

        // FIXME IVM

        Ok(delegation)
    }

    pub fn encrypt_to<'a, T: ContentRef>(
        &self,
        doc: &Document<'a, T>,
        to: &Individual,
        message: &mut [u8],
    ) -> Encrypted<&[u8]> {
        let recipient_share_pk = doc.reader_keys.get(&to.id()).expect("FIXME");
        let our_pk = doc.reader_keys.get(&self.id()).expect("FIXME");

        let our_sk = self.share_key_pairs.get(&our_pk.1).expect("FIXME");

        let key: SymmetricKey = our_sk.diffie_hellman(&recipient_share_pk.1.into()).into();

        let nonce = Siv::new(&key, message, doc);
        let bytes: Vec<u8> = key.encrypt(nonce, message).expect("FIXME").to_vec();

        Encrypted::new(nonce.into(), bytes)
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
        std::fmt::Display::fmt(&self.id(), f)
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

impl std::hash::Hash for Active {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.id().hash(state);
        self.signer.to_bytes().hash(state);
        for pk in self.share_key_pairs.keys() {
            pk.hash(state);
        }
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
impl PartialEq for Active {
    fn eq(&self, other: &Self) -> bool {
        self.id() == other.id()
            && self.signer.to_bytes() == other.signer.to_bytes()
            && self
                .share_key_pairs
                .iter()
                .zip(other.share_key_pairs.iter())
                .all(|((pk1, sk1), (pk2, sk2))| pk1 == pk2 && sk1.to_bytes() == sk2.to_bytes())
    }
}

impl Eq for Active {}

// FIXME test
impl PartialOrd for Active {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        match self.id().partial_cmp(&other.id()) {
            Some(std::cmp::Ordering::Equal) => {
                match self.signer.to_bytes().partial_cmp(&other.signer.to_bytes()) {
                    Some(std::cmp::Ordering::Equal) => self
                        .share_key_pairs
                        .iter()
                        .zip(other.share_key_pairs.iter())
                        .map(|((pk1, sk1), (pk2, sk2))| {
                            pk1.partial_cmp(pk2).and_then(|pk_cmp| {
                                sk1.to_bytes()
                                    .partial_cmp(&sk2.to_bytes())
                                    .and_then(|sk_cmp| pk_cmp.partial_cmp(&sk_cmp))
                            })
                        })
                        .find(|cmp| *cmp != Some(std::cmp::Ordering::Equal))
                        .unwrap_or(Some(std::cmp::Ordering::Equal)),
                    cmp => cmp,
                }
            }
            cmp => cmp,
        }
    }
}

// FIXME test
impl Ord for Active {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.partial_cmp(other)
            .expect("Nothnig should prevent Active from being orderable")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign() {
        let signer = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
        let active = Active::generate(signer);
        let message = "hello world".as_bytes();
        let signed = active.sign(message);

        assert!(signed.verify().is_ok());
    }
}
