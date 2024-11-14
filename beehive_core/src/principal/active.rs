//! The current user agent (which can sign and encrypt).

use super::{
    document::{id::DocumentId, Document},
    identifier::Identifier,
    individual::{id::IndividualId, Individual},
    verifiable::Verifiable,
};
use crate::{
    access::Access,
    content::reference::ContentRef,
    crypto::{
        encrypted::Encrypted,
        share_key::ShareKey,
        signed::{Signed, SigningError},
        siv::Siv,
        symmetric_key::SymmetricKey,
    },
    principal::{
        agent::{Agent, AgentId},
        group::operation::{
            delegation::{Delegation, DelegationError},
            revocation::Revocation,
        },
        membered::Membered,
    },
};
use dupe::Dupe;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::Serialize;
use std::{cell::RefCell, collections::BTreeMap, fmt::Debug, rc::Rc};
use thiserror::Error;

/// The current user agent (which can sign and encrypt).
#[derive(Clone, Serialize)]
pub struct Active {
    /// The signing key of the active agent.
    pub signer: SigningKey,

    // FIXME generalize to use e.g. KMS
    // FIXME include timestamp for next PCS update
    /// The encryption "sharing" key pairs that the active agent has.
    /// This includes the secret keys for ECDH.
    pub share_key_pairs: BTreeMap<ShareKey, x25519_dalek::StaticSecret>,

    /// The [`Individual`] static identifier.
    pub individual: Individual,
}

impl Active {
    pub fn generate(signer: SigningKey) -> Result<Self, SigningError> {
        Ok(Self {
            individual: Individual::generate(&signer)?,
            share_key_pairs: BTreeMap::new(),
            signer,
        })
    }

    pub fn id(&self) -> IndividualId {
        self.individual.id()
    }

    pub fn agent_id(&self) -> AgentId {
        AgentId::IndividualId(self.id())
    }

    pub fn rotate_prekey(&mut self, prekey: ShareKey) -> Result<ShareKey, SigningError> {
        self.individual.rotate_prekey(prekey, &self.signer)
    }

    pub fn expand_prekeys(&mut self) -> Result<ShareKey, SigningError> {
        self.individual.expand_prekeys(&self.signer)
    }

    /// Sign a payload.
    pub fn try_sign<U: Serialize>(&self, payload: U) -> Result<Signed<U>, SigningError> {
        Signed::<U>::try_sign(payload, &self.signer)
    }

    pub fn get_capability<T: ContentRef>(
        &self,
        subject: Membered<T>,
        min: Access,
    ) -> Option<Rc<Signed<Delegation<T>>>> {
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
        subject: Membered<T>,
        attenuate: Access,
        delegate: Agent<T>,
        after_revocations: Vec<Rc<Signed<Revocation<T>>>>,
        after_content: BTreeMap<DocumentId, (Rc<RefCell<Document<T>>>, Vec<T>)>,
    ) -> Result<Signed<Delegation<T>>, ActiveDelegationError> {
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

    pub fn encrypt_to<T: ContentRef>(
        &self,
        doc: &Document<T>,
        to: &Individual,
        message: Vec<u8>,
    ) -> Result<Encrypted<&[u8]>, ShareError> {
        let recipient_share_pk = doc
            .reader_keys
            .get(&to.id())
            .ok_or_else(|| ShareError::MissingRecipientShareKey(to.id().into()))?;

        let our_pk = doc
            .reader_keys
            .get(&self.id())
            .ok_or(ShareError::MissingYourSharePublicKey)?;

        let our_sk = self
            .share_key_pairs
            .get(&our_pk.1)
            .ok_or(ShareError::MissingYourShareSecretKey)?;

        let key: SymmetricKey = our_sk.diffie_hellman(&recipient_share_pk.1.into()).into();

        let nonce = Siv::new(&key, &message, doc.doc_id()).map_err(ShareError::SivError)?;
        let mut bytes = message.clone();
        key.try_encrypt(nonce, &mut bytes)
            .map_err(ShareError::EncryptionFailed)?;

        Ok(Encrypted::new(nonce.into(), message))
    }
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
    use super::*;

    #[test]
    fn test_sign() {
        let signer = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
        let active = Active::generate(signer).unwrap();
        let message = "hello world".as_bytes();
        let signed = active.try_sign(message).unwrap();

        assert!(signed.try_verify().is_ok());
    }
}
