//! The current user agent (which can sign and encrypt).

use super::{
    document::id::DocumentId,
    identifier::Identifier,
    individual::{id::IndividualId, op::KeyOp, Individual},
    verifiable::Verifiable,
};
use crate::{
    access::Access,
    content::reference::ContentRef,
    crypto::{
        share_key::{ShareKey, ShareSecretKey},
        signed::{Signed, SigningError},
    },
    principal::{
        agent::{id::AgentId, Agent},
        group::operation::{
            delegation::{Delegation, DelegationError},
            revocation::Revocation,
        },
        membered::Membered,
    },
};
use derivative::Derivative;
use dupe::Dupe;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::Serialize;
use std::{collections::BTreeMap, fmt::Debug, rc::Rc};
use thiserror::Error;

/// The current user agent (which can sign and encrypt).
#[derive(Clone, Derivative, Serialize)]
#[derivative(Hash, PartialEq)]
pub struct Active {
    /// The signing key of the active agent.
    #[derivative(
        Hash(hash_with = "crate::util::hasher::signing_key"),
        PartialEq(compare_with = "key_partial_eq")
    )]
    pub(crate) signing_key: ed25519_dalek::SigningKey,

    // FIXME generalize to use e.g. KMS
    #[derivative(
        Hash(hash_with = "crate::util::hasher::keys"),
        PartialEq(compare_with = "prekey_partial_eq")
    )]
    pub(crate) prekey_pairs: BTreeMap<ShareKey, ShareSecretKey>,

    /// The [`Individual`] representation (how others see this agent).
    pub(crate) individual: Individual,
}

impl Active {
    pub fn generate<R: rand::CryptoRng + rand::RngCore>(
        signing_key: SigningKey,
        csprng: &mut R,
    ) -> Result<Self, SigningError> {
        let mut individual = Individual::new(signing_key.verifying_key().into());

        let mut prekey_pairs = BTreeMap::new();

        (0..7).try_for_each(|_| {
            let sk = ShareSecretKey::generate(csprng);
            let pk = sk.share_key();
            let op = Signed::try_sign(KeyOp::add(pk), &signing_key)?;

            prekey_pairs.insert(pk, sk);
            individual
                .receive_prekey_op(op)
                .expect("insertion of fresh prekey by the correct signer should work");

            Ok::<(), SigningError>(())
        })?;

        Ok(Self {
            individual,
            prekey_pairs,
            signing_key,
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
        self.individual
            .rotate_prekey(prekey, &self.signing_key, csprng)
    }

    pub fn expand_prekeys<R: rand::CryptoRng + rand::RngCore>(
        &mut self,
        csprng: &mut R,
    ) -> Result<ShareKey, SigningError> {
        self.individual.expand_prekeys(&self.signing_key, csprng)
    }

    /// Sign a payload.
    pub fn try_sign<U: Serialize>(&self, payload: U) -> Result<Signed<U>, SigningError> {
        Signed::<U>::try_sign(payload, &self.signing_key)
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
        after_content: BTreeMap<DocumentId, Vec<T>>,
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
}

impl std::fmt::Display for Active {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.id(), f)
    }
}

impl Debug for Active {
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

impl Verifiable for Active {
    fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }
}

impl Signer<Signature> for Active {
    fn try_sign(&self, message: &[u8]) -> Result<Signature, signature::Error> {
        self.signing_key.try_sign(message)
    }
}

fn prekey_partial_eq(
    xs: &BTreeMap<ShareKey, ShareSecretKey>,
    ys: &BTreeMap<ShareKey, ShareSecretKey>,
) -> bool {
    xs.len() == ys.len()
        && xs
            .iter()
            .zip(ys.iter())
            .all(|((xk, xv), (yk, yv))| xk == yk && xv.to_bytes() == yv.to_bytes())
}

fn key_partial_eq(a: &ed25519_dalek::SigningKey, b: &ed25519_dalek::SigningKey) -> bool {
    a.to_bytes() == b.to_bytes()
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
        let csprng = &mut rand::thread_rng();
        let signer = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
        let active = Active::generate(signer, csprng).unwrap();
        let message = "hello world".as_bytes();
        let signed = active.try_sign(message).unwrap();

        assert!(signed.try_verify().is_ok());
    }
}
