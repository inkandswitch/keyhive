//! The current user agent (which can sign and encrypt).

use super::{
    document::id::DocumentId,
    identifier::Identifier,
    individual::{
        id::IndividualId,
        op::{add_key::AddKeyOp, rotate_key::RotateKeyOp, KeyOp},
        state::PrekeyState,
        Individual,
    },
};
use crate::{
    access::Access,
    content::reference::ContentRef,
    crypto::{
        share_key::{AsyncSecretKey, ShareKey, ShareSecretKey, ShareSecretStore},
        signed::{Signed, SigningError},
        signer::async_signer::AsyncSigner,
        verifiable::Verifiable,
    },
    listener::{
        log::Log, membership::MembershipListener, no_listener::NoListener, prekey::PrekeyListener,
    },
    principal::{
        agent::id::AgentId,
        group::delegation::{Delegation, DelegationError},
        membered::Membered,
    },
    transact::{fork::Fork, merge::Merge},
};
use derivative::Derivative;
use dupe::Dupe;
use futures::prelude::*;
use serde::{Deserialize, Serialize};
use std::{fmt::Debug, marker::PhantomData, rc::Rc};
use thiserror::Error;

/// The current user agent (which can sign and encrypt).
#[derive(Clone, Derivative, Serialize, Deserialize)]
#[derivative(Debug, Hash, PartialEq)]
pub struct Active<
    S: AsyncSigner,
    K: ShareSecretStore,
    T: ContentRef = [u8; 32],
    L: PrekeyListener = NoListener,
> {
    /// The signing key of the active agent.
    #[derivative(Debug = "ignore")]
    pub(crate) signer: S,

    // TODO generalize to use e.g. KMS for X25519 secret keys
    #[derivative(Debug = "ignore", Hash = "ignore", PartialEq = "ignore")]
    pub(crate) secret_store: K,

    /// The [`Individual`] representation (how others see this agent).
    pub(crate) individual: Individual,

    ///The listener for prekey events.
    #[serde(skip)]
    #[derivative(Debug = "ignore", PartialEq = "ignore")]
    pub(crate) listener: L,

    pub(crate) _phantom: PhantomData<T>,
}

impl<S: AsyncSigner, K: ShareSecretStore, T: ContentRef, L: PrekeyListener> Active<S, K, T, L> {
    /// Generate a new active agent.
    ///
    /// # Arguments
    ///
    /// * `signer` - The signing key of the active agent.
    /// * `listener` - The listener for changes to this agent's prekeys.
    /// * `csprng` - The cryptographically secure random number generator.
    pub async fn generate<R: rand::CryptoRng + rand::RngCore>(
        signer: S,
        secret_store: K,
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
        let mut local_store = vec![];
        for _ in 0..6 {
            let sk = secret_store.generate_share_secret_key(csprng).await?;
            local_store.push(sk);
        }

        let borrowed_signer = &signer;
        let ops = stream::iter(local_store.map(|x| Ok::<_, SigningError>(x)))
            .try_fold(vec![], |mut acc, sk| async move {
                acc.push(
                    Rc::new(
                        borrowed_signer
                            .try_sign_async(AddKeyOp {
                                share_key: sk.to_share_key(),
                            })
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
            secret_store,
            listener,
            signer,
            _phantom: PhantomData,
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
        self.rotate_prekey(contact_key.payload.new, csprng).await?;

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
        let new_secret = ShareSecretKey::generate(csprng);
        let new_public = new_secret.share_key();

        let rot_op = Rc::new(
            self.try_sign_async(RotateKeyOp {
                old: old_prekey,
                new: new_public,
            })
            .await?,
        );

        self.secret_store.import_secret_key(new_secret).await?;

        self.individual
            .prekey_state
            .insert_op(KeyOp::Rotate(rot_op.dupe()))
            .expect("the op we just signed to be valid");

        self.individual.prekeys.remove(&old_prekey);
        self.individual.prekeys.insert(new_public);

        self.listener.on_prekey_rotated(&rot_op).await;
        Ok(rot_op)
    }

    /// Add a new prekey, expanding the number of currently available prekeys.
    pub async fn expand_prekeys<R: rand::CryptoRng + rand::RngCore>(
        &mut self,
        csprng: &mut R,
    ) -> Result<Rc<Signed<AddKeyOp>>, SigningError> {
        let new_secret = self
            .secret_store
            .generate_share_secret_key()
            .await
            .expect("FIXME");
        let new_public = new_secret.to_share_key();

        let op = Rc::new(
            self.signer
                .try_sign_async(AddKeyOp {
                    share_key: new_public,
                })
                .await?,
        );

        self.individual
            .prekey_state
            .insert_op(KeyOp::Add(op.dupe()))
            .expect("the op we just signed to be valid");
        self.individual.prekeys.insert(new_public);

        self.listener.on_prekeys_expanded(&op).await;
        Ok(op)
    }

    /// Asyncronously sign a payload.
    pub async fn try_sign_async<U: Serialize + std::fmt::Debug>(
        &self,
        payload: U,
    ) -> Result<Signed<U>, SigningError> {
        self.signer.try_sign_async(payload).await
    }

    /// Encrypt a payload for a member of some [`Group`] or [`Document`].
    pub fn get_capability(
        &self,
        subject: Membered<S, K, T, L>,
        min: Access,
    ) -> Option<Rc<Signed<Delegation<S, K, T, L>>>>
    where
        L: MembershipListener<S, K, T>,
    {
        subject.get_capability(&self.id().into()).and_then(|cap| {
            if cap.payload().can >= min {
                Some(cap)
            } else {
                None
            }
        })
    }

    /// Serialize for storage.
    pub fn into_archive(&self) -> Individual {
        self.individual.clone()
    }

    /// Deserialize from storage.
    pub fn from_archive(archive: &Individual, secret_store: K, signer: S, listener: L) -> Self {
        tracing::trace!("loaded from archive");
        Self {
            individual: archive.clone(),
            secret_store,
            signer,
            listener,
            _phantom: PhantomData,
        }
    }
}

impl<S: AsyncSigner, K: ShareSecretStore, T: ContentRef, L: PrekeyListener> std::fmt::Display
    for Active<S, K, T, L>
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.id(), f)
    }
}

impl<S: AsyncSigner, K: ShareSecretStore, T: ContentRef, L: PrekeyListener> Verifiable
    for Active<S, K, T, L>
{
    fn verifying_key(&self) -> ed25519_dalek::VerifyingKey {
        self.signer.verifying_key()
    }
}

impl<S: AsyncSigner + Clone, K: ShareSecretStore, T: ContentRef, L: PrekeyListener> Fork
    for Active<S, K, T, L>
{
    type Forked = Active<S, K, T, Log<S, K, T>>;

    fn fork(&self) -> Self::Forked {
        Active {
            signer: self.signer.clone(),
            secret_store: self.secret_store.clone(),
            individual: self.individual.clone(),
            listener: Log::new(),
            _phantom: PhantomData,
        }
    }
}

impl<S: AsyncSigner + Clone, K: ShareSecretStore, T: ContentRef, L: PrekeyListener> Merge
    for Active<S, K, T, L>
{
    fn merge(&mut self, fork: Self::Forked) {
        self.individual.merge(fork.individual);
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
        test_utils::init_logging();

        let csprng = &mut rand::thread_rng();
        let signer = MemorySigner::generate(&mut rand::thread_rng());
        let active: Active<_, [u8; 32], _> =
            Active::generate(signer, NoListener, csprng).await.unwrap();
        let message = "hello world".as_bytes();
        let signed = active.try_sign_async(message).await.unwrap();

        assert!(signed.try_verify().is_ok());
    }
}
