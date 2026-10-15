use super::{
    active::Active,
    identifier::Identifier,
    individual::{op::add_key::AddKeyOp, state::PrekeyState, IndividualState},
};
use crate::listener::prekey::PrekeyListener;
use dupe::Dupe;
use ed25519_dalek::{SigningKey, VerifyingKey};
use future_form::FutureForm;
use futures::lock::Mutex;
use keyhive_crypto::{
    content::reference::ContentRef,
    share_key::{ShareKey, ShareSecretKey},
    signer::{async_signer::AsyncSigner, memory::MemorySigner},
    verifiable::Verifiable,
};
use std::{
    collections::BTreeMap,
    marker::PhantomData,
    sync::{Arc, LazyLock},
};

/// The `Public` identifier, derived once from the well-known signing key.
static PUBLIC_ID: LazyLock<Identifier> = LazyLock::new(|| Public.verifying_key().into());

/// The `Public` share key, derived once from the well-known secret.
static PUBLIC_SHARE_KEY: LazyLock<ShareKey> =
    LazyLock::new(|| Public.share_secret_key().share_key());

/// A well-known individual that can be used by anyone. ⚠ USE WITH CAUTION ⚠
///
/// This is a constant key that is publicly-known.
/// Sharing to this key is equivalent to setting a document to "public" by using a
/// pre-leaked key. We use this so that the visibility of a document can be made
/// temporarily public and later revoked.
#[derive(Debug, Clone, Dupe, Copy)]
pub struct Public;

impl Public {
    pub fn id(&self) -> Identifier {
        *PUBLIC_ID
    }

    pub fn signing_key(&self) -> SigningKey {
        SigningKey::from([0; 32])
    }

    pub fn signer(&self) -> MemorySigner {
        MemorySigner::from(self.signing_key())
    }

    pub fn share_secret_key(&self) -> ShareSecretKey {
        x25519_dalek::StaticSecret::from([0; 32]).into()
    }

    pub fn share_key(&self) -> ShareKey {
        *PUBLIC_SHARE_KEY
    }

    pub fn individual(&self) -> IndividualState {
        let op = Arc::new(
            self.signer()
                .try_sign_sync(AddKeyOp {
                    share_key: self.share_key(),
                })
                .expect("signature with well-known key should work"),
        )
        .into();

        let prekey_state = PrekeyState::new(op);

        IndividualState {
            id: self.verifying_key().into(),
            prekeys: prekey_state.build(),
            prekey_state,
        }
    }

    pub fn active<F: FutureForm, T: ContentRef, L: PrekeyListener<F>>(
        &self,
        listener: L,
    ) -> Active<F, MemorySigner, T, L>
    where
        MemorySigner: AsyncSigner<F>,
    {
        Active {
            id: self.signer().verifying_key().into(),
            signer: self.signer(),
            key_pairs: Arc::new(Mutex::new(BTreeMap::from_iter([(
                self.share_key(),
                self.share_secret_key(),
            )]))),
            individual: Arc::new(Mutex::new(self.individual())),
            listener,
            _phantom: PhantomData,
        }
    }
}

impl Verifiable for Public {
    fn verifying_key(&self) -> VerifyingKey {
        VerifyingKey::from(&self.signing_key())
    }
}
