//! The current user agent (which can sign and encrypt).

pub mod archive;

use self::archive::ActiveArchive;
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
        share_key::{ShareKey, ShareSecretKey},
        signed::{Signed, SigningError},
        signer::async_signer::AsyncSigner,
        verifiable::Verifiable,
    },
    listener::{log::Log, no_listener::NoListener, prekey::PrekeyListener},
    principal::{agent::id::AgentId, group::delegation::Delegation, membered::Membered},
    transact::{
        fork::Fork,
        merge::{Merge, MergeAsync},
    },
};
use derivative::Derivative;
use dupe::Dupe;
use future_form::{future_form, FutureForm, Local, Sendable};
use futures::lock::Mutex;
use std::{collections::BTreeMap, fmt::Debug, marker::PhantomData, sync::Arc};
use thiserror::Error;

use super::group::delegation::DelegationError;

/// The current user agent (which can sign and encrypt).
///
/// The struct is parameterized by:
/// - `S`: The signer type (must implement [`Verifiable`], and [`AsyncSigner<K>`] for async operations)
/// - `T`: The content reference type
/// - `L`: The prekey listener type
#[derive(Clone, Derivative)]
#[derivative(Debug)]
pub struct Active<S: Verifiable, T: ContentRef = [u8; 32], L = NoListener> {
    /// The signing key of the active agent.
    #[derivative(Debug = "ignore")]
    pub(crate) signer: S,

    // TODO generalize to use e.g. KMS for X25519 secret keys
    pub(crate) prekey_pairs: Arc<Mutex<BTreeMap<ShareKey, ShareSecretKey>>>,

    pub(crate) id: IndividualId,

    /// The [`Individual`] representation (how others see this agent).
    pub(crate) individual: Arc<Mutex<Individual>>,

    /// The listener for prekey events.
    #[derivative(Debug = "ignore", PartialEq = "ignore")]
    pub(crate) listener: L,

    pub(crate) _phantom: PhantomData<T>,
}

// Non-async methods stay as inherent impls
impl<S: Verifiable, T: ContentRef, L> Active<S, T, L> {
    /// Getter for the agent's [`IndividualId`].
    pub fn id(&self) -> IndividualId {
        self.id
    }

    /// Getter for the agent's [`AgentId`].
    pub fn agent_id(&self) -> AgentId {
        AgentId::IndividualId(self.id())
    }

    /// The agent's underlying [`Individual`].
    pub fn individual(&self) -> Arc<Mutex<Individual>> {
        self.individual.dupe()
    }

    /// Deserialize from storage.
    pub fn from_archive(archive: &ActiveArchive, signer: S, listener: L) -> Self {
        tracing::trace!(
            num_prekey_pairs = archive.prekey_pairs.len(),
            "loaded from archive"
        );
        Self {
            id: signer.verifying_key().into(),
            prekey_pairs: Arc::new(Mutex::new(archive.prekey_pairs.clone())),
            individual: Arc::new(Mutex::new(archive.individual.clone())),
            signer,
            listener,
            _phantom: PhantomData,
        }
    }
}

impl<S: Verifiable, T: ContentRef, L> std::fmt::Display for Active<S, T, L> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.id(), f)
    }
}

impl<S: Verifiable, T: ContentRef, L> Verifiable for Active<S, T, L> {
    fn verifying_key(&self) -> ed25519_dalek::VerifyingKey {
        self.signer.verifying_key()
    }
}

/// Async operations for [`Active`] agents.
///
/// This trait is parameterized by `K: FutureForm` to support both
/// multi-threaded ([`Sendable`]) and single-threaded ([`Local`]) async runtimes.
///
/// [`Sendable`]: future_form::Sendable
/// [`Local`]: future_form::Local
pub trait ActiveOps<K: FutureForm>: Verifiable {
    /// The signer type.
    type Signer: AsyncSigner<K, AddKeyOp> + AsyncSigner<K, RotateKeyOp>;
    /// The content reference type.
    type ContentRef: ContentRef;
    /// The prekey listener type.
    type Listener: PrekeyListener<K>;

    /// Generate a new active agent.
    fn generate<R: rand::CryptoRng + rand::RngCore>(
        signer: Self::Signer,
        listener: Self::Listener,
        csprng: &mut R,
    ) -> K::Future<'static, Result<Self, SigningError>>
    where
        Self: Sized,
        Self::Signer: 'static,
        Self::Listener: 'static;

    /// Create a [`ShareKey`] that is not broadcast via the prekey state.
    fn generate_private_prekey<'a, R: rand::CryptoRng + rand::RngCore + Send + 'static>(
        &'a mut self,
        csprng: Arc<Mutex<R>>,
    ) -> K::Future<'a, Result<Arc<Signed<RotateKeyOp>>, SigningError>>;

    /// Pseudorandomly select a prekey out of the current prekeys.
    fn pick_prekey<'a>(&'a self, doc_id: DocumentId) -> K::Future<'a, ShareKey>;

    /// Replace a particular prekey with a new one.
    fn rotate_prekey<'a, R: rand::CryptoRng + rand::RngCore + Send + 'static>(
        &'a mut self,
        old_prekey: ShareKey,
        csprng: Arc<Mutex<R>>,
    ) -> K::Future<'a, Result<Arc<Signed<RotateKeyOp>>, SigningError>>;

    /// Add a new prekey, expanding the number of currently available prekeys.
    fn expand_prekeys<'a, R: rand::CryptoRng + rand::RngCore + Send + 'static>(
        &'a mut self,
        csprng: Arc<Mutex<R>>,
    ) -> K::Future<'a, Result<Arc<Signed<AddKeyOp>>, SigningError>>;

    /// Get capability for the active agent on a membered entity.
    fn get_capability<'a>(
        &'a self,
        subject: Membered<Self::Signer, Self::ContentRef>,
        min: Access,
    ) -> K::Future<'a, Option<Arc<Signed<Delegation<Self::Signer, Self::ContentRef>>>>>;

    /// Serialize for storage.
    fn into_archive<'a>(&'a self) -> K::Future<'a, ActiveArchive>;
}

#[future_form(Sendable where S: Send + Sync + 'static, T: Send + Sync + 'static, L: Send + Sync + 'static, Local)]
impl<
        K: FutureForm,
        S: AsyncSigner<K, AddKeyOp> + AsyncSigner<K, RotateKeyOp> + Clone + 'static,
        T: ContentRef + 'static,
        L: PrekeyListener<K> + 'static,
    > ActiveOps<K> for Active<S, T, L>
{
    type Signer = S;
    type ContentRef = T;
    type Listener = L;

    fn generate<R: rand::CryptoRng + rand::RngCore>(
        signer: S,
        listener: L,
        csprng: &mut R,
    ) -> K::Future<'static, Result<Self, SigningError>>
    where
        S: 'static,
        L: 'static,
    {
        // Pre-generate all the keys synchronously since csprng isn't Send
        let init_sk = ShareSecretKey::generate(csprng);
        let init_pk = init_sk.share_key();

        let mut prekey_pairs = BTreeMap::from_iter([(init_pk, init_sk)]);
        let additional_keys: Vec<_> = (0..6)
            .map(|_| {
                let sk = ShareSecretKey::generate(csprng);
                let pk = sk.share_key();
                prekey_pairs.insert(pk, sk);
                pk
            })
            .collect();

        K::from_future(async move {
            let init_op = Arc::new(
                AsyncSigner::<K, _>::try_sign_async(&signer, AddKeyOp { share_key: init_pk })
                    .await?,
            )
            .into();

            let mut prekey_state = PrekeyState::new(init_op);

            // Sign all the additional keys
            for pk in additional_keys {
                let op = Arc::new(
                    AsyncSigner::<K, _>::try_sign_async(&signer, AddKeyOp { share_key: pk })
                        .await?,
                )
                .into();
                prekey_state
                    .extend(vec![op])
                    .expect("newly generated local op should be valid");
            }

            let id = signer.verifying_key().into();

            Ok(Self {
                id,
                individual: Arc::new(Mutex::new(Individual {
                    id,
                    prekeys: prekey_state.build(),
                    prekey_state,
                })),
                prekey_pairs: Arc::new(Mutex::new(prekey_pairs)),
                listener,
                signer,
                _phantom: PhantomData,
            })
        })
    }

    fn generate_private_prekey<'a, R: rand::CryptoRng + rand::RngCore + Send + 'static>(
        &'a mut self,
        csprng: Arc<Mutex<R>>,
    ) -> K::Future<'a, Result<Arc<Signed<RotateKeyOp>>, SigningError>> {
        K::from_future(async move {
            let share_key = {
                // TODO total hack
                let locked = self.individual.lock().await;
                locked.pick_prekey(DocumentId(self.id().into())).dupe()
            };
            let contact_key = ActiveOps::<K>::rotate_prekey(self, share_key, csprng.dupe()).await?;
            ActiveOps::<K>::rotate_prekey(self, contact_key.payload.new, csprng).await?;
            Ok(contact_key)
        })
    }

    fn pick_prekey<'a>(&'a self, doc_id: DocumentId) -> K::Future<'a, ShareKey> {
        K::from_future(async move {
            tracing::trace!("picking prekey for document {doc_id}");
            self.individual.lock().await.pick_prekey(doc_id).dupe()
        })
    }

    fn rotate_prekey<'a, R: rand::CryptoRng + rand::RngCore + Send + 'static>(
        &'a mut self,
        old_prekey: ShareKey,
        csprng: Arc<Mutex<R>>,
    ) -> K::Future<'a, Result<Arc<Signed<RotateKeyOp>>, SigningError>> {
        K::from_future(async move {
            let new_secret = {
                let mut locked_csprng = csprng.lock().await;
                ShareSecretKey::generate(&mut *locked_csprng)
            };
            let new_public = new_secret.share_key();

            let rot_op = Arc::new(
                AsyncSigner::<K, _>::try_sign_async(
                    &self.signer,
                    RotateKeyOp {
                        old: old_prekey,
                        new: new_public,
                    },
                )
                .await?,
            );

            {
                self.prekey_pairs
                    .lock()
                    .await
                    .insert(new_public, new_secret);
            }

            {
                let mut locked_individual = self.individual.lock().await;
                locked_individual
                    .prekey_state
                    .insert_op(KeyOp::Rotate(rot_op.dupe()))
                    .expect("the op we just signed to be valid");

                locked_individual.prekeys.remove(&old_prekey);
                locked_individual.prekeys.insert(new_public);
            }

            PrekeyListener::<K>::on_prekey_rotated(&self.listener, &rot_op).await;
            Ok(rot_op)
        })
    }

    fn expand_prekeys<'a, R: rand::CryptoRng + rand::RngCore + Send + 'static>(
        &'a mut self,
        csprng: Arc<Mutex<R>>,
    ) -> K::Future<'a, Result<Arc<Signed<AddKeyOp>>, SigningError>> {
        K::from_future(async move {
            let new_secret = {
                let mut locked_csprng = csprng.lock().await;
                ShareSecretKey::generate(&mut *locked_csprng)
            };
            let new_public = new_secret.share_key();

            let op = Arc::new(
                AsyncSigner::<K, _>::try_sign_async(
                    &self.signer,
                    AddKeyOp {
                        share_key: new_public,
                    },
                )
                .await?,
            );

            {
                let mut locked_individual = self.individual.lock().await;

                locked_individual
                    .prekey_state
                    .insert_op(KeyOp::Add(op.dupe()))
                    .expect("the op we just signed to be valid");

                locked_individual.prekeys.insert(new_public);
            }

            {
                self.prekey_pairs
                    .lock()
                    .await
                    .insert(new_public, new_secret);
            }

            PrekeyListener::<K>::on_prekeys_expanded(&self.listener, &op).await;
            Ok(op)
        })
    }

    fn get_capability<'a>(
        &'a self,
        subject: Membered<S, T>,
        min: Access,
    ) -> K::Future<'a, Option<Arc<Signed<Delegation<S, T>>>>> {
        K::from_future(async move {
            subject
                .get_capability(&self.id().into())
                .await
                .and_then(|cap| {
                    if cap.payload().can >= min {
                        Some(cap)
                    } else {
                        None
                    }
                })
        })
    }

    fn into_archive<'a>(&'a self) -> K::Future<'a, ActiveArchive> {
        K::from_future(async move {
            ActiveArchive {
                prekey_pairs: self.prekey_pairs.lock().await.clone(),
                individual: self.individual.lock().await.clone(),
            }
        })
    }
}

impl<S: Verifiable + Clone, T: ContentRef, L> Fork for Active<S, T, L> {
    type Forked = Active<S, T, Log<S, T>>;

    fn fork(&self) -> Self::Forked {
        Active {
            id: self.id,
            signer: self.signer.clone(),
            prekey_pairs: self.prekey_pairs.clone(),
            individual: self.individual.clone(),
            listener: Log::new(),
            _phantom: PhantomData,
        }
    }
}

impl<S: Verifiable + Clone, T: ContentRef, L> MergeAsync for Active<S, T, L> {
    async fn merge_async(&self, fork: Self::AsyncForked) {
        let forked_individual = { fork.individual.lock().await.clone() };
        let forked_prekey_pairs = { fork.prekey_pairs.lock().await.clone() };
        {
            self.prekey_pairs.lock().await.extend(forked_prekey_pairs);
        }

        self.individual.lock().await.merge(forked_individual);
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
    use crate::crypto::signer::{memory::MemorySigner, sync_signer::SyncSigner};
    use future_form::Sendable;

    #[tokio::test]
    async fn test_seal() {
        test_utils::init_logging();

        let csprng = &mut rand::thread_rng();
        let signer = MemorySigner::generate(&mut rand::thread_rng());
        let _active: Active<_, [u8; 32], _> =
            ActiveOps::<Sendable>::generate(signer.clone(), NoListener, csprng)
                .await
                .unwrap();
        let message = "hello world".as_bytes();
        let signed = signer.try_sign_sync(message).unwrap();

        assert!(signed.try_verify().is_ok());
    }
}
