//! The current user agent (which can sign and encrypt).

pub mod archive;

use self::archive::ActiveArchive;
use super::{
    document::id::DocumentId,
    identifier::Identifier,
    individual::{
        id::IndividualId,
        new_share_key::NewShareKey,
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
        signer::async_signer::AsyncSigner,
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
use futures::prelude::*;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, fmt::Debug, rc::Rc};
use thiserror::Error;

/// The current user agent (which can sign and encrypt).
#[derive(Clone, Derivative, Serialize, Deserialize)]
#[derivative(Debug, Hash, PartialEq)]
pub struct Active<S: AsyncSigner, L: PrekeyListener = NoListener> {
    /// The signing key of the active agent.
    #[derivative(Debug = "ignore")]
    pub(crate) signer: S,

    // TODO generalize to use e.g. KMS for X25519 secret keys
    #[derivative(
        Debug(format_with = "crate::util::debug::prekey_fmt"),
        Hash(hash_with = "crate::util::hasher::keys"),
        PartialEq(compare_with = "crate::util::partial_eq::prekey_partial_eq")
    )]
    pub(crate) prekey_pairs: BTreeMap<ShareKey, ShareSecretKey>,

    /// The [`Individual`] representation (how others see this agent).
    pub(crate) individual: Individual,

    ///The listener for prekey events.
    #[serde(skip)]
    #[derivative(Debug = "ignore", PartialEq = "ignore")]
    pub(crate) listener: L,
}

impl<S: AsyncSigner, L: PrekeyListener> Active<S, L> {
    /// Generate a new active agent.
    ///
    /// # Arguments
    ///
    /// * `signer` - The signing key of the active agent.
    /// * `listener` - The listener for changes to this agent's prekeys.
    /// * `csprng` - The cryptographically secure random number generator.
    pub async fn generate<R: rand::CryptoRng + rand::RngCore>(
        signer: S,
        listener: L,
        csprng: &mut R,
    ) -> Result<Self, SigningError> {
        let init_sk = ShareSecretKey::generate(csprng);
        let init_pk = init_sk.share_key();
        let init_op = Rc::new(
            signer
                .try_sign_async(AddKeyOp { share_key: init_pk })
                .await?,
        )
        .into();

        let mut prekey_state = PrekeyState::new(init_op);
        let prekey_pairs =
            (0..6).try_fold(BTreeMap::from_iter([(init_pk, init_sk)]), |mut acc, _| {
                let sk = ShareSecretKey::generate(csprng);
                let pk = sk.share_key();
                acc.insert(pk, sk);
                Ok::<_, SigningError>(acc)
            })?;

        let borrowed_signer = &signer;
        let ops = stream::iter(prekey_pairs.keys().map(|x| Ok::<_, SigningError>(x)))
            .try_fold(vec![], |mut acc, pk| async move {
                acc.push(
                    Rc::new(
                        borrowed_signer
                            .try_sign_async(AddKeyOp { share_key: *pk })
                            .await?,
                    )
                    .into(),
                );
                Ok(acc)
            })
            .await?;

        prekey_state
            .extend(ops)
            .expect("newly generated local op should be valid");

        Ok(Self {
            individual: Individual {
                id: signer.verifying_key().into(),
                prekeys: prekey_state.build(),
                prekey_state,
            },
            prekey_pairs,
            listener,
            signer,
        })
    }

    /// Getter for the agent's [`IndividualId`].
    pub fn id(&self) -> IndividualId {
        self.individual.id()
    }

    /// Getter for the agent's [`AgentId`].
    pub fn agent_id(&self) -> AgentId {
        AgentId::IndividualId(self.id())
    }

    /// The agent's underlying [`Individual`].
    pub fn individual(&self) -> &Individual {
        &self.individual
    }

    /// Create a [`ShareKey`] that is not broadcast via the prekey state.
    pub async fn generate_private_prekey<R: rand::CryptoRng + rand::RngCore>(
        &mut self,
        csprng: &mut R,
    ) -> Result<Rc<Signed<RotateKeyOp>>, SigningError> {
        let share_key = self.individual.pick_prekey(DocumentId(self.id().into())); // Hack
        let contact_key = self.rotate_prekey(*share_key, csprng).await?;
        self.rotate_prekey(contact_key.payload.new.clone(), csprng)
            .await?;

        Ok(contact_key)
    }

    /// Pseudorandomly select a prekey out of the current prekeys.
    pub fn pick_prekey(&self, doc_id: DocumentId) -> &ShareKey {
        self.individual.pick_prekey(doc_id)
    }

    /// Replace a particular prekey with a new one.
    pub async fn rotate_prekey<R: rand::CryptoRng + rand::RngCore>(
        &mut self,
        old_prekey: ShareKey,
        csprng: &mut R,
    ) -> Result<Rc<Signed<RotateKeyOp>>, SigningError> {
        let NewShareKey { new_secret, op } = self
            .individual
            .rotate_prekey(old_prekey, &self.signer, csprng)
            .await?;
        self.prekey_pairs.insert(op.payload.new, new_secret);
        self.listener.on_prekey_rotated(&op).await;
        Ok(op)
    }

    /// Add a new prekey, expanding the number of currently available prekeys.
    pub async fn expand_prekeys<R: rand::CryptoRng + rand::RngCore>(
        &mut self,
        csprng: &mut R,
    ) -> Result<Rc<Signed<AddKeyOp>>, SigningError> {
        let NewShareKey { new_secret, op } =
            self.individual.expand_prekeys(&self.signer, csprng).await?;
        self.prekey_pairs.insert(op.payload.share_key, new_secret);
        self.listener.on_prekeys_expanded(&op).await;
        Ok(op)
    }

    /// Asyncronously sign a payload.
    pub async fn try_sign_async<U: Serialize>(
        &self,
        payload: U,
    ) -> Result<Signed<U>, SigningError> {
        self.signer.try_sign_async(payload).await
    }

    /// Encrypt a payload for a member of some [`Group`] or [`Document`].
    pub fn get_capability<T: ContentRef>(
        &self,
        subject: Membered<S, T>,
        min: Access,
    ) -> Option<Rc<Signed<Delegation<S, T>>>> {
        subject.get_capability(&self.id().into()).and_then(|cap| {
            if cap.payload().can >= min {
                Some(cap)
            } else {
                None
            }
        })
    }

    /// Serialize for storage.
    pub fn into_archive(&self) -> ActiveArchive {
        ActiveArchive {
            prekey_pairs: self.prekey_pairs.clone(),
            individual: self.individual.clone(),
        }
    }

    /// Deserialize from storage.
    pub fn from_archive(archive: &ActiveArchive, signer: S, listener: L) -> Self {
        Self {
            prekey_pairs: archive.prekey_pairs.clone(),
            individual: archive.individual.clone(),
            signer,
            listener,
        }
    }
}

impl<S: AsyncSigner, L: PrekeyListener> std::fmt::Display for Active<S, L> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.id(), f)
    }
}

impl<S: AsyncSigner, L: PrekeyListener> Verifiable for Active<S, L> {
    fn verifying_key(&self) -> ed25519_dalek::VerifyingKey {
        self.signer.verifying_key()
    }
}

/// Errors when sharing encrypted content.
#[derive(Debug, Error)]
pub enum ShareError {
    /// The active agent cannot find a public [`ShareKey`] for themselves.
    #[error("The active agent cannot find a public ShareKey for themselves")]
    MissingYourSharePublicKey,

    /// The active agent cannot find a [`ShareSecretKey`] for themselves.
    #[error("The active agent cannot find a secret ShareKey for themselves")]
    MissingYourShareSecretKey,

    /// The active agent does not know the [`ShareKey`] for the recipient.
    #[error("The active agent does not know the ShareKey for the recipient: {0}")]
    MissingRecipientShareKey(Identifier),

    /// Encryption failed.
    #[error("Encryption failed: {0}")]
    EncryptionFailed(chacha20poly1305::Error),

    /// [`Siv`][crate::crypto::siv::Siv] construction failed with an IO error.
    #[error("Siv error: {0}")]
    SivError(std::io::Error),
}

/// Errors when looking up a delegation for the [`Active`] agent.
#[derive(Debug, Error)]
pub enum ActiveDelegationError {
    /// Cannot find proof at the requested access level.
    #[error("Cannot find proof at the requested access level")]
    CannotFindProof,

    /// Invalid delegation.
    #[error(transparent)]
    DelegationError(#[from] DelegationError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::signer::memory::MemorySigner;

    #[tokio::test]
    async fn test_seal() {
        let csprng = &mut rand::thread_rng();
        let signer = MemorySigner::generate(&mut rand::thread_rng());
        let active = Active::generate(signer, NoListener, csprng).await.unwrap();
        let message = "hello world".as_bytes();
        let signed = active.try_sign_async(message).await.unwrap();

        assert!(signed.try_verify().is_ok());
    }
}
