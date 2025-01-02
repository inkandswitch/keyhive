//! The current user agent (which can sign and encrypt).

use super::{
    agent::{Agent, AgentId},
    document::{id::DocumentId, Document},
    group::operation::{
        delegation::{Delegation, DelegationError},
        revocation::Revocation,
    },
    identifier::Identifier,
    individual::{id::IndividualId, op::KeyOp, Individual},
    membered::Membered,
    verifiable::Verifiable,
};
use crate::{
    access::Access,
    content::reference::ContentRef,
    crypto::{
        share_key::{ShareKey, ShareSecretKey},
        signed::{Signed, SigningError},
        signer::ed_signer::EdSigner,
    },
};
use dupe::Dupe;
use ed25519_dalek::{Signature, Signer, VerifyingKey};
use serde::Serialize;
use std::{cell::RefCell, collections::BTreeMap, fmt::Debug, rc::Rc};
use thiserror::Error;

/// The current user agent (which can sign and encrypt).
#[derive(Clone, Serialize, PartialEq, Eq)]
pub struct Active<S: EdSigner> {
    /// The signing key of the active agent.
    pub signer: S,

    // // FIXME generalize to use e.g. KMS
    // // FIXME include timestamp for next PCS update
    // /// The encryption "sharing" key pairs that the active agent has.
    // /// This includes the secret keys for ECDH.
    // FIXME: Can we remove this since we're using the Individual's map?
    pub prekey_pairs: BTreeMap<ShareKey, ShareSecretKey>, // FIXME generalize to use e.g. KMS

    /// The [`Individual`] representation (how others see this agent).
    pub individual: Individual,
}

impl<S: EdSigner> Active<S> {
    pub fn generate<R: rand::CryptoRng + rand::RngCore>(
        signer: S,
        csprng: &mut R,
    ) -> Result<Self, SigningError> {
        let mut individual = Individual::new(signer.verifying_key().into());
        let mut prekey_pairs = BTreeMap::new();

        (0..7).try_for_each(|_| {
            let sk = ShareSecretKey::generate(csprng);
            let pk = sk.share_key();
            let op = Signed::try_sign(KeyOp::add(pk), &signer)?;

            prekey_pairs.insert(pk, sk);
            individual
                .receive_prekey_op(op)
                .expect("insertion of fresh prekey by the correct signer should work");

            Ok::<(), SigningError>(())
        })?;

        Ok(Self {
            individual,
            prekey_pairs,
            signer,
        })
    }

    pub fn id(&self) -> IndividualId {
        self.individual.id()
    }

    pub fn agent_id(&self) -> AgentId {
        AgentId::IndividualId(self.id())
    }

    pub fn pick_prekey(&self, doc_id: DocumentId) -> ShareKey {
        self.individual.pick_prekey(doc_id)
    }

    pub fn rotate_prekey<R: rand::CryptoRng + rand::RngCore>(
        &mut self,
        prekey: ShareKey,
        csprng: &mut R,
    ) -> Result<ShareKey, SigningError> {
        self.individual.rotate_prekey(prekey, &self.signer, csprng)
    }

    pub fn expand_prekeys<R: rand::CryptoRng + rand::RngCore>(
        &mut self,
        csprng: &mut R,
    ) -> Result<ShareKey, SigningError> {
        self.individual.expand_prekeys(&self.signer, csprng)
    }

    /// Sign a payload.
    pub fn try_sign<U: Serialize>(&self, payload: U) -> Result<Signed<U>, SigningError> {
        Signed::<U>::try_sign(payload, &self.signer)
    }

    pub fn get_capability<T: ContentRef>(
        &self,
        subject: Membered<T, S>,
        min: Access,
    ) -> Option<Rc<Signed<Delegation<T, S>>>> {
        subject.get_capability(&self.agent_id()).and_then(|cap| {
            if cap.payload().can >= min {
                Some(cap)
            } else {
                None
            }
        })
    }

    // FIXME replace with delegate_to
    pub fn make_delegation<T: ContentRef>(
        &self,
        subject: Membered<T, S>,
        attenuate: Access,
        delegate: Agent<T, S>,
        after_revocations: Vec<Rc<Signed<Revocation<T, S>>>>,
        after_content: BTreeMap<DocumentId, (Rc<RefCell<Document<T, S>>>, Vec<T>)>,
    ) -> Result<Signed<Delegation<T, S>>, ActiveDelegationError> {
        let proof = self
            .get_capability(subject, attenuate)
            .ok_or(ActiveDelegationError::CannotFindProof)?;

        if attenuate > proof.payload().can {
            return Err(ActiveDelegationError::DelegationError(
                DelegationError::Escalation,
            ));
        }

        let delegation = self
            .try_sign(Delegation {
                delegate: delegate.dupe(),
                can: attenuate,
                proof: Some(proof.dupe()),
                after_revocations,
                after_content,
            })
            .map_err(DelegationError::SigningError)?;

        // FIXME IVM

        Ok(delegation)
    }
}

impl<S: EdSigner> std::fmt::Display for Active<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.id(), f)
    }
}

impl<S: EdSigner> Debug for Active<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let keypairs_hidden_secret_keys: Vec<(&ShareKey, &str)> = self
            .prekey_pairs
            .keys()
            .map(|pk| (pk, "<SecretKey>"))
            .collect();

        f.debug_struct("Active")
            .field("id", &self.id())
            .field("signer", &"<Signer>")
            .field("share_key_pairs", &keypairs_hidden_secret_keys)
            .finish()
    }
}

impl<S: EdSigner> std::hash::Hash for Active<S> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.id().hash(state);
        self.signer.verifying_key().to_bytes().hash(state);
        for pk in self.prekey_pairs.keys() {
            pk.hash(state);
        }
    }
}

impl<S: EdSigner> Verifiable for Active<S> {
    fn verifying_key(&self) -> VerifyingKey {
        self.signer.verifying_key()
    }
}

impl<S: EdSigner> Signer<Signature> for Active<S> {
    fn try_sign(&self, message: &[u8]) -> Result<Signature, signature::Error> {
        self.signer.try_sign(message)
    }
}

#[derive(Debug, Error)]
pub enum ShareError {
    #[error("The active agent cannot find a public ShareKey for themselves")]
    MissingYourSharePublicKey,

    #[error("The active agent cannot find a secret ShareKey for themselves")]
    MissingYourShareSecretKey,

    #[error("The active agent does not know the ShareKey for the recipient: {0}")]
    MissingRecipientShareKey(Identifier),

    #[error("Encryption failed: {0}")]
    EncryptionFailed(chacha20poly1305::Error),

    #[error("Siv error: {0}")]
    SivError(std::io::Error),
}

#[derive(Debug, Error)]
pub enum ActiveDelegationError {
    #[error("Cannot find proof at the requested access level")]
    CannotFindProof,

    #[error(transparent)]
    DelegationError(#[from] DelegationError),
}

#[cfg(test)]
mod tests {
    use crate::crypto::signer::memory::MemorySigner;

    use super::*;

    #[test]
    fn test_sign() {
        let mut csprng = rand::thread_rng();
        let signer = MemorySigner::generate(&mut csprng);
        let active = Active::generate(signer, &mut csprng).unwrap();
        let message = "hello world".as_bytes();
        let signed = active.try_sign(message).unwrap();

        assert!(signed.try_verify().is_ok());
    }
}
