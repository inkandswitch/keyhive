//! This replica's own individual, which can sign and encrypt.

pub mod archive;

use self::archive::ActiveArchive;
use super::{
    document::id::DocumentId,
    individual::{
        id::IndividualId,
        op::{add_key::AddKeyOp, rotate_key::RotateKeyOp, KeyOp},
        state::PrekeyState,
        IndividualState,
    },
};
use crate::{
    listener::{log::Log, membership::MembershipListener, prekey::PrekeyListener},
    transact::{
        fork::Fork,
        merge::{Merge, MergeAsync},
    },
};
use derivative::Derivative;
use dupe::Dupe;
use ed25519_dalek::VerifyingKey;
use future_form::FutureForm;
use futures::{lock::Mutex, prelude::*};
use keyhive_codec::{
    error::DecodeError,
    traits::{Decode, Encode},
};
use keyhive_crypto::{
    content::reference::ContentRef,
    identifier::InvalidIdentifier,
    share_key::{ShareKey, ShareSecretKey},
    signer::async_signer::AsyncSigner,
    verifiable::Verifiable,
    verified::{SignError, Verified},
};
use rand::{CryptoRng, RngCore};
use std::{collections::BTreeMap, fmt, marker::PhantomData, sync::Arc};
use thiserror::Error;

/// This replica's own individual, which can sign and encrypt.
#[derive(Derivative)]
#[derivative(Debug)]
pub struct Active<F: FutureForm, S: AsyncSigner<F>, T: ContentRef, L: PrekeyListener<F>> {
    /// The signing key of the active individual.
    #[derivative(Debug = "ignore")]
    pub(crate) signer: S,

    // TODO generalize to use e.g. KMS for X25519 secret keys
    /// Secret keys for this identity's prekeys and for the keys it has sampled
    /// for PCS key rotations.
    pub(crate) key_pairs: Arc<Mutex<BTreeMap<ShareKey, ShareSecretKey>>>,

    pub(crate) id: IndividualId,

    /// The [`IndividualState`] representation (how others see it).
    pub(crate) individual: Arc<Mutex<IndividualState>>,

    ///The listener for prekey events.
    #[derivative(Debug = "ignore", PartialEq = "ignore")]
    pub(crate) listener: L,

    pub(crate) _phantom: PhantomData<(F, T)>,
}

impl<F: FutureForm, S: AsyncSigner<F>, T: ContentRef, L: PrekeyListener<F>> Active<F, S, T, L> {
    /// Generate a new active individual.
    ///
    /// # Arguments
    ///
    /// * `signer` - The signing key of the active individual.
    /// * `listener` - The listener for changes to its prekeys.
    /// * `csprng` - The cryptographically secure random number generator.
    pub async fn generate<R: CryptoRng + RngCore>(
        signer: S,
        listener: L,
        csprng: &mut R,
    ) -> Result<Self, SignError> {
        let init_sk = ShareSecretKey::generate(csprng);
        let init_pk = init_sk.share_key();
        let init_op =
            KeyOp::Add(Verified::sign::<F, S>(&AddKeyOp { share_key: init_pk }, &signer).await?);

        // Signing checked that the signer's key is a valid id.
        let id = IndividualId::from(init_op.issuer());
        let mut prekey_state = PrekeyState::new(init_op);
        let mut prekey_pairs = BTreeMap::from_iter([(init_pk, init_sk)]);
        for _ in 0..6 {
            let sk = ShareSecretKey::generate(csprng);
            prekey_pairs.insert(sk.share_key(), sk);
        }

        let borrowed_signer = &signer;
        let ops = stream::iter(prekey_pairs.keys().map(Ok::<_, SignError>))
            .try_fold(vec![], |mut acc, pk| async move {
                acc.push(KeyOp::Add(
                    Verified::sign::<F, S>(&AddKeyOp { share_key: *pk }, borrowed_signer).await?,
                ));
                Ok(acc)
            })
            .await?;

        prekey_state.extend(ops);

        Ok(Self {
            id,
            individual: Arc::new(Mutex::new(IndividualState {
                id,
                prekeys: prekey_state.build(),
                prekey_state,
            })),
            key_pairs: Arc::new(Mutex::new(prekey_pairs)),
            listener,
            signer,
            _phantom: PhantomData,
        })
    }

    /// This individual's [`IndividualId`].
    pub fn id(&self) -> IndividualId {
        self.id
    }

    /// The underlying [`IndividualState`].
    pub(crate) fn individual(&self) -> Arc<Mutex<IndividualState>> {
        self.individual.dupe()
    }

    /// Create a [`ShareKey`] that is not broadcast via the prekey state.
    pub async fn generate_private_prekey<R: CryptoRng + RngCore>(
        &self,
        csprng: Arc<Mutex<R>>,
    ) -> Result<Verified<RotateKeyOp>, SignError> {
        let picked = {
            // TODO total hack
            let locked = self.individual.lock().await;
            locked.pick_prekey(DocumentId(self.id().into())).copied()
        };
        // With no live prekey (rotations can retire every one), publish one
        // to rotate.
        let share_key = match picked {
            Some(share_key) => share_key,
            None => {
                self.expand_prekeys(csprng.dupe())
                    .await?
                    .payload()
                    .share_key
            }
        };
        let contact_key = self.rotate_prekey(share_key, csprng.dupe()).await?;
        self.rotate_prekey(contact_key.payload().new, csprng)
            .await?;
        Ok(contact_key)
    }

    /// Select a prekey out of the current prekeys, as
    /// [`IndividualState::pick_prekey`] does, preferring one whose secret this
    /// instance holds. `None` if there are no live prekeys.
    pub async fn pick_prekey(&self, doc_id: DocumentId) -> Option<ShareKey> {
        tracing::trace!("picking prekey for document {doc_id}",);
        let (picked, published) = {
            let locked = self.individual.lock().await;
            (
                locked.pick_prekey(doc_id).copied()?,
                locked.prekeys().clone(),
            )
        };
        // It's possible a sibling instance for our keyhive identity has not yet
        // shared the secret for `picked`. If we don't have it, we pick a prekey
        // we do have the secret for.
        let local_pairs = self.key_pairs.lock().await;
        if local_pairs.contains_key(&picked) {
            return Some(picked);
        }
        Some(
            published
                .iter()
                .filter(|pk| local_pairs.contains_key(pk))
                .min()
                .copied()
                .unwrap_or(picked),
        )
    }

    /// Replace a particular prekey with a new one.
    pub async fn rotate_prekey<R: CryptoRng + RngCore>(
        &self,
        old_prekey: ShareKey,
        csprng: Arc<Mutex<R>>,
    ) -> Result<Verified<RotateKeyOp>, SignError> {
        let new_secret = {
            let mut locked_csprng = csprng.lock().await;
            ShareSecretKey::generate(&mut *locked_csprng)
        };
        let new_public = new_secret.share_key();

        let rot_op = Verified::sign::<F, S>(
            &RotateKeyOp {
                old: old_prekey,
                new: new_public,
            },
            &self.signer,
        )
        .await?;

        {
            self.key_pairs.lock().await.insert(new_public, new_secret);
        }

        {
            let mut locked_individual = self.individual.lock().await;
            locked_individual
                .prekey_state
                .insert_op(KeyOp::Rotate(rot_op.clone()));

            locked_individual.prekeys.remove(&old_prekey);
            locked_individual.prekeys.insert(new_public);
        }

        self.listener.on_prekey_rotated(rot_op.signed()).await;
        Ok(rot_op)
    }

    /// Add a new prekey, expanding the number of currently available prekeys.
    pub async fn expand_prekeys<R: CryptoRng + RngCore>(
        &self,
        csprng: Arc<Mutex<R>>,
    ) -> Result<Verified<AddKeyOp>, SignError> {
        let new_secret = {
            let mut locked_csprng = csprng.lock().await;
            ShareSecretKey::generate(&mut *locked_csprng)
        };
        let new_public = new_secret.share_key();

        let op = Verified::sign::<F, S>(
            &AddKeyOp {
                share_key: new_public,
            },
            &self.signer,
        )
        .await?;

        {
            let mut locked_individual = self.individual.lock().await;

            locked_individual
                .prekey_state
                .insert_op(KeyOp::Add(op.clone()));

            locked_individual.prekeys.insert(new_public);
        }

        {
            self.key_pairs.lock().await.insert(new_public, new_secret);
        }

        self.listener.on_prekeys_expanded(op.signed()).await;
        Ok(op)
    }

    /// Export prekey secrets, for backup or for another instance of this
    /// identity: `count ‖ ( share_key ‖ secret )*`, sorted by share key.
    ///
    /// # Security
    ///
    /// The returned bytes contain unencrypted secret key material.
    /// Callers are responsible for protecting this data at rest and in transit.
    pub async fn export_prekey_secrets(&self) -> Vec<u8> {
        self.key_pairs.lock().await.encode().into_bytes()
    }

    /// Insert a secret generated by a key rotation.
    pub async fn insert_rotated_secret(&self, pk: ShareKey, sk: ShareSecretKey) {
        self.key_pairs.lock().await.insert(pk, sk);
    }

    /// Import prekey secrets from [`Active::export_prekey_secrets`], extending
    /// the existing set. Refuses the whole import if any secret does not
    /// produce the key it is paired with.
    pub async fn import_prekey_secrets(
        &self,
        bytes: &[u8],
    ) -> Result<(), ImportPrekeySecretsError> {
        let imported = BTreeMap::<ShareKey, ShareSecretKey>::decode(bytes)?;
        if let Some((pk, _)) = imported.iter().find(|(pk, sk)| sk.share_key() != **pk) {
            return Err(ImportPrekeySecretsError::NotItsSecret(*pk));
        }
        self.key_pairs.lock().await.extend(imported);
        Ok(())
    }

    /// Serialize for storage.
    pub async fn into_archive(&self) -> ActiveArchive {
        ActiveArchive {
            key_pairs: self.key_pairs.lock().await.clone(),
            individual: self.individual.lock().await.clone(),
        }
    }

    /// Deserialize from storage. Fails if the signer's key is not a valid id.
    pub fn from_archive(
        archive: &ActiveArchive,
        signer: S,
        listener: L,
    ) -> Result<Self, InvalidIdentifier> {
        tracing::trace!(
            num_key_pairs = archive.key_pairs.len(),
            "loaded from archive"
        );
        Ok(Self {
            id: IndividualId::try_from(signer.verifying_key())?,
            key_pairs: Arc::new(Mutex::new(archive.key_pairs.clone())),
            individual: Arc::new(Mutex::new(archive.individual.clone())),
            signer,
            listener,
            _phantom: PhantomData,
        })
    }
}

impl<F: FutureForm, S: AsyncSigner<F> + Clone, T: ContentRef, L: PrekeyListener<F> + Clone> Clone
    for Active<F, S, T, L>
{
    fn clone(&self) -> Self {
        Self {
            signer: self.signer.clone(),
            key_pairs: self.key_pairs.clone(),
            id: self.id,
            individual: self.individual.clone(),
            listener: self.listener.clone(),
            _phantom: PhantomData,
        }
    }
}

impl<F: FutureForm, S: AsyncSigner<F>, T: ContentRef, L: PrekeyListener<F>> fmt::Display
    for Active<F, S, T, L>
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.id(), f)
    }
}

impl<F: FutureForm, S: AsyncSigner<F>, T: ContentRef, L: PrekeyListener<F>> Verifiable
    for Active<F, S, T, L>
{
    fn verifying_key(&self) -> VerifyingKey {
        self.signer.verifying_key()
    }
}

impl<F: FutureForm, S: AsyncSigner<F> + Clone, T: ContentRef, L: PrekeyListener<F>> Fork
    for Active<F, S, T, L>
where
    Log<T>: MembershipListener<F, T>,
{
    type Forked = Active<F, S, T, Log<T>>;

    fn fork(&self) -> Self::Forked {
        Active {
            id: self.id,
            signer: self.signer.clone(),
            key_pairs: self.key_pairs.clone(),
            individual: self.individual.clone(),
            listener: Log::new(),
            _phantom: PhantomData,
        }
    }
}

impl<F: FutureForm, S: AsyncSigner<F> + Clone, T: ContentRef, L: PrekeyListener<F>> MergeAsync
    for Active<F, S, T, L>
where
    Log<T>: MembershipListener<F, T>,
{
    async fn merge_async(&self, fork: Self::AsyncForked) {
        let forked_individual = { fork.individual.lock().await.clone() };
        let forked_key_pairs = { fork.key_pairs.lock().await.clone() };
        {
            self.key_pairs.lock().await.extend(forked_key_pairs);
        }

        self.individual.lock().await.merge(forked_individual);
    }
}

/// Why [`Active::import_prekey_secrets`] refused its input.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ImportPrekeySecretsError {
    /// The bytes are not an export.
    #[error(transparent)]
    Decode(#[from] DecodeError),

    /// The secret paired with this key does not produce it.
    #[error("the secret paired with share key {0} does not produce it")]
    NotItsSecret(ShareKey),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::listener::no_listener::NoListener;
    use future_form::Sendable;
    use keyhive_crypto::signer::memory::MemorySigner;

    #[tokio::test]
    async fn test_export_import_prekey_secrets() {
        test_utils::init_logging();

        let csprng = &mut rand::thread_rng();
        let signer1 = MemorySigner::generate(csprng);
        let active1: Active<Sendable, _, [u8; 32], _> =
            Active::<Sendable, _, _, _>::generate(signer1, NoListener, csprng)
                .await
                .unwrap();

        let exported = active1.export_prekey_secrets().await;

        let signer2 = MemorySigner::generate(csprng);
        let active2: Active<Sendable, _, [u8; 32], _> =
            Active::<Sendable, _, _, _>::generate(signer2, NoListener, csprng)
                .await
                .unwrap();

        let original_pairs: BTreeMap<ShareKey, ShareSecretKey> =
            active2.key_pairs.lock().await.clone();

        active2.import_prekey_secrets(&exported).await.unwrap();

        let merged_pairs = active2.key_pairs.lock().await;
        let exported_pairs: BTreeMap<ShareKey, ShareSecretKey> =
            active1.key_pairs.lock().await.clone();

        // All original pairs should still be present
        for (k, v) in &original_pairs {
            assert_eq!(merged_pairs.get(k), Some(v));
        }

        // All imported pairs should be present
        for (k, v) in &exported_pairs {
            assert_eq!(merged_pairs.get(k), Some(v));
        }

        // Total count should be the union
        assert_eq!(
            merged_pairs.len(),
            original_pairs.len() + exported_pairs.len()
        );
    }

    #[tokio::test]
    async fn test_import_invalid_bytes() {
        test_utils::init_logging();

        let csprng = &mut rand::thread_rng();
        let signer = MemorySigner::generate(csprng);
        let active: Active<Sendable, _, [u8; 32], _> =
            Active::<Sendable, _, _, _>::generate(signer, NoListener, csprng)
                .await
                .unwrap();

        let result = active.import_prekey_secrets(b"not an export").await;
        assert!(matches!(result, Err(ImportPrekeySecretsError::Decode(_))));
    }

    /// A key paired with a secret that does not produce it is refused, and
    /// nothing from that import is kept.
    #[tokio::test]
    async fn an_import_pairing_a_key_with_another_secret_is_refused() {
        let csprng = &mut rand::thread_rng();
        let active: Active<Sendable, _, [u8; 32], _> = Active::<Sendable, _, _, _>::generate(
            MemorySigner::generate(csprng),
            NoListener,
            csprng,
        )
        .await
        .expect("generates");
        let before = active.key_pairs.lock().await.clone();

        let real = ShareSecretKey::generate(csprng);
        let other = ShareSecretKey::generate(csprng);
        let pairs = BTreeMap::from([(real.share_key(), real), (other.share_key(), real)]);
        let result = active
            .import_prekey_secrets(pairs.encode().as_bytes())
            .await;

        assert_eq!(
            result,
            Err(ImportPrekeySecretsError::NotItsSecret(other.share_key()))
        );
        assert_eq!(*active.key_pairs.lock().await, before);
    }
}
