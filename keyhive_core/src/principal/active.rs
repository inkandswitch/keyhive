//! The current user agent (which can sign and encrypt).

use super::{
    document::id::DocumentId,
    identifier::Identifier,
    individual::{
        id::IndividualId,
        op::{add_key::AddKeyOp, rotate_key::RotateKeyOp},
        state::PrekeyState,
        Individual,
    },
};
use crate::{
    access::Access,
    content::reference::ContentRef,
    crypto::{
        share_key::{ShareKey, ShareSecretKey},
        signed::{Signed, SigningError},
        verifiable::Verifiable,
    },
    listener::{no_listener::NoListener, prekey::PrekeyListener},
    principal::{
        agent::id::AgentId,
        group::delegation::{Delegation, DelegationError},
        membered::Membered,
    },
};
use derivative::Derivative;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, fmt::Debug, rc::Rc};
use thiserror::Error;

/// The current user agent (which can sign and encrypt).
#[derive(Clone, Derivative, Serialize, Deserialize)]
#[derivative(Hash, PartialEq)]
pub struct Active<L: PrekeyListener = NoListener> {
    /// The signing key of the active agent.
    #[derivative(
        Hash(hash_with = "crate::util::hasher::signing_key"),
        PartialEq(compare_with = "key_partial_eq")
    )]
    pub(crate) signing_key: ed25519_dalek::SigningKey,

    // TODO generalize to use e.g. KMS
    #[derivative(
        Hash(hash_with = "crate::util::hasher::keys"),
        PartialEq(compare_with = "prekey_partial_eq")
    )]
    pub(crate) prekey_pairs: BTreeMap<ShareKey, ShareSecretKey>,

    /// The [`Individual`] representation (how others see this agent).
    pub(crate) individual: Individual,

    ///The listener for prekey events.
    #[serde(skip)]
    #[derivative(PartialEq = "ignore")]
    pub(crate) listener: L,
}

impl<L: PrekeyListener> Active<L> {
    pub(crate) fn generate<R: rand::CryptoRng + rand::RngCore>(
        signing_key: SigningKey,
        listener: L,
        csprng: &mut R,
    ) -> Result<Self, SigningError> {
        let init_sk = ShareSecretKey::generate(csprng);
        let init_pk = init_sk.share_key();
        let init_op = Rc::new(Signed::try_sign(
            AddKeyOp { share_key: init_pk },
            &signing_key,
        )?)
        .into();

        let mut prekey_pairs = BTreeMap::from_iter([(init_pk, init_sk)]);
        let mut prekey_state = PrekeyState::new(init_op);

        (0..6).try_for_each(|_| {
            let sk = ShareSecretKey::generate(csprng);
            let pk = sk.share_key();
            let op = Rc::new(Signed::try_sign(AddKeyOp { share_key: pk }, &signing_key)?).into();

            prekey_pairs.insert(pk, sk);
            prekey_state
                .insert_op(op)
                .expect("new prekey from generation should always work");

            Ok::<(), SigningError>(())
        })?;

        Ok(Self {
            individual: Individual {
                id: signing_key.verifying_key().into(),
                prekeys: prekey_state.build(),
                prekey_state,
            },
            prekey_pairs,
            listener,
            signing_key,
        })
    }

    pub fn id(&self) -> IndividualId {
        self.individual.id()
    }

    pub fn agent_id(&self) -> AgentId {
        AgentId::IndividualId(self.id())
    }

    pub fn individual(&self) -> &Individual {
        &self.individual
    }

    pub fn pick_prekey(&self, doc_id: DocumentId) -> Option<ShareKey> {
        self.individual.pick_prekey(doc_id)
    }

    pub fn rotate_prekey<R: rand::CryptoRng + rand::RngCore>(
        &mut self,
        old_prekey: ShareKey,
        csprng: &mut R,
    ) -> Result<Rc<Signed<RotateKeyOp>>, SigningError> {
        let op = self
            .individual
            .rotate_prekey(old_prekey, &self.signing_key, csprng)?;
        self.listener.on_prekey_rotated(&op);
        Ok(op)
    }

    pub fn expand_prekeys<R: rand::CryptoRng + rand::RngCore>(
        &mut self,
        csprng: &mut R,
    ) -> Result<Rc<Signed<AddKeyOp>>, SigningError> {
        let op = self.individual.expand_prekeys(&self.signing_key, csprng)?;
        self.listener.on_prekeys_expanded(&op);
        Ok(op)
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
        subject.get_capability(&self.id().into()).and_then(|cap| {
            if cap.payload().can >= min {
                Some(cap)
            } else {
                None
            }
        })
    }
}

impl<L: PrekeyListener> std::fmt::Display for Active<L> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.id(), f)
    }
}

impl<L: PrekeyListener> Debug for Active<L> {
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

impl<L: PrekeyListener> Verifiable for Active<L> {
    fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }
}

impl<L: PrekeyListener> Signer<Signature> for Active<L> {
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

impl<L: PrekeyListener> Eq for Active<L> {}

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
        let active = Active::generate(signer, NoListener, csprng).unwrap();
        let message = "hello world".as_bytes();
        let signed = active.try_sign(message).unwrap();

        assert!(signed.try_verify().is_ok());
    }
}
