//! In-memory secret key store.
//!
//! Stores keys in a `BTreeMap<ShareKey, ShareSecretKey>`. All
//! operations are infallible.

use super::SecretKeyStore;
use future_form::{future_form, FutureForm, Local, Sendable};
use futures::lock::Mutex;
use keyhive_crypto::share_key::{ShareKey, ShareSecretKey};
use std::{collections::BTreeMap, convert::Infallible, sync::Arc};

/// In-memory secret key store backed by a `BTreeMap` with interior
/// mutability via [`futures::lock::Mutex`].
///
/// Cloning produces a handle to the same shared key set.
///
/// This is the default store for development and testing.
/// For production use with durable keys, implement
/// [`SecretKeyStore`] for your storage backend.
#[derive(Debug, Clone, Default)]
pub struct MemorySecretKeyStore {
    keys: Arc<Mutex<BTreeMap<ShareKey, ShareSecretKey>>>,
}

impl MemorySecretKeyStore {
    pub fn new() -> Self {
        Self {
            keys: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }

    /// Number of keys in the store.
    pub async fn len(&self) -> usize {
        self.keys.lock().await.len()
    }

    /// Whether the store is empty.
    pub async fn is_empty(&self) -> bool {
        self.keys.lock().await.is_empty()
    }
}

#[future_form(Sendable, Local)]
impl<F: FutureForm> SecretKeyStore<F> for MemorySecretKeyStore {
    type SecretKey = ShareSecretKey;
    type GetError = Infallible;
    type ImportError = Infallible;
    type GenerateError = Infallible;

    fn get_secret_key<'a>(
        &'a self,
        public_key: &'a ShareKey,
    ) -> F::Future<'a, Result<Option<ShareSecretKey>, Infallible>> {
        F::from_future(async move { Ok(self.keys.lock().await.get(public_key).copied()) })
    }

    fn import_secret_key<'a>(
        &'a self,
        secret_key: ShareSecretKey,
    ) -> F::Future<'a, Result<ShareKey, Infallible>> {
        F::from_future(async move {
            let pk = secret_key.share_key();
            self.keys.lock().await.insert(pk, secret_key);
            Ok(pk)
        })
    }

    fn import_raw_secret_key<'a>(
        &'a self,
        raw: ShareSecretKey,
    ) -> F::Future<'a, Result<ShareSecretKey, Infallible>> {
        F::from_future(async move {
            let pk = raw.share_key();
            self.keys.lock().await.insert(pk, raw);
            Ok(raw)
        })
    }

    fn generate_secret_key<'a>(&'a self) -> F::Future<'a, Result<ShareSecretKey, Infallible>> {
        F::from_future(async move {
            let sk = ShareSecretKey::generate(&mut rand::thread_rng());
            let pk = sk.share_key();
            self.keys.lock().await.insert(pk, sk);
            Ok(sk)
        })
    }

    fn contains_secret_key<'a>(
        &'a self,
        public_key: &'a ShareKey,
    ) -> F::Future<'a, Result<bool, Infallible>> {
        F::from_future(async move { Ok(self.keys.lock().await.contains_key(public_key)) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use future_form::Sendable;

    #[tokio::test]
    async fn test_generate_and_retrieve() {
        let store = MemorySecretKeyStore::new();
        assert!(store.is_empty().await);

        let sk = SecretKeyStore::<Sendable>::generate_secret_key(&store)
            .await
            .unwrap();
        assert_eq!(store.len().await, 1);

        let pk = sk.share_key();
        let retrieved = SecretKeyStore::<Sendable>::get_secret_key(&store, &pk)
            .await
            .unwrap();
        assert_eq!(retrieved, Some(sk));
    }

    #[tokio::test]
    async fn test_import_raw() {
        let store = MemorySecretKeyStore::new();
        let sk = ShareSecretKey::generate(&mut rand::thread_rng());
        let pk = sk.share_key();

        let imported = SecretKeyStore::<Sendable>::import_raw_secret_key(&store, sk)
            .await
            .unwrap();
        assert_eq!(imported, sk);

        let exists = SecretKeyStore::<Sendable>::contains_secret_key(&store, &pk)
            .await
            .unwrap();
        assert!(exists);
    }

    #[tokio::test]
    async fn test_missing_key_returns_none() {
        let store = MemorySecretKeyStore::new();
        let random_pk = ShareSecretKey::generate(&mut rand::thread_rng()).share_key();

        let result = SecretKeyStore::<Sendable>::get_secret_key(&store, &random_pk)
            .await
            .unwrap();
        assert_eq!(result, None);
    }

    /// Verify that keys generated during `Active::generate` are
    /// stored in the `SecretKeyStore`.
    #[tokio::test]
    async fn test_active_generate_stores_keys() {
        use crate::{listener::no_listener::NoListener, principal::active::Active};
        use keyhive_crypto::signer::memory::MemorySigner;

        let store = MemorySecretKeyStore::new();
        let signer = MemorySigner::generate(&mut rand::thread_rng());
        let _active =
            Active::<Sendable, MemorySigner, MemorySecretKeyStore, [u8; 32], NoListener>::generate(
                signer,
                &store,
                NoListener,
                &mut rand::thread_rng(),
            )
            .await
            .unwrap();

        // Active::generate creates 7 prekeys (1 initial + 6 additional)
        assert_eq!(store.len().await, 7, "all 7 prekeys should be in the store");
    }

    /// Verify that keys generated during `Active::expand_prekeys`
    /// are stored in the `SecretKeyStore`.
    #[tokio::test]
    async fn test_expand_prekeys_stores_key() {
        use crate::{listener::no_listener::NoListener, principal::active::Active};
        use keyhive_crypto::signer::memory::MemorySigner;

        let store = MemorySecretKeyStore::new();
        let signer = MemorySigner::generate(&mut rand::thread_rng());
        let mut active =
            Active::<Sendable, MemorySigner, MemorySecretKeyStore, [u8; 32], NoListener>::generate(
                signer,
                &store,
                NoListener,
                &mut rand::thread_rng(),
            )
            .await
            .unwrap();

        let before = store.len().await;
        let _op = active
            .expand_prekeys(&store, futures::lock::Mutex::new(rand::thread_rng()).into())
            .await
            .unwrap();

        assert_eq!(
            store.len().await,
            before + 1,
            "expand_prekeys should add one key to the store"
        );
    }

    /// Verify that keys generated during `Active::rotate_prekey`
    /// are stored in the `SecretKeyStore`.
    #[tokio::test]
    async fn test_rotate_prekey_stores_key() {
        use crate::{listener::no_listener::NoListener, principal::active::Active};
        use keyhive_crypto::signer::memory::MemorySigner;

        let store = MemorySecretKeyStore::new();
        let signer = MemorySigner::generate(&mut rand::thread_rng());
        let mut active =
            Active::<Sendable, MemorySigner, MemorySecretKeyStore, [u8; 32], NoListener>::generate(
                signer,
                &store,
                NoListener,
                &mut rand::thread_rng(),
            )
            .await
            .unwrap();

        let before = store.len().await;
        let old_pk = *active.prekey_pairs.lock().await.keys().next().unwrap();
        let _op = active
            .rotate_prekey(
                old_pk,
                &store,
                futures::lock::Mutex::new(rand::thread_rng()).into(),
            )
            .await
            .unwrap();

        assert_eq!(
            store.len().await,
            before + 1,
            "rotate_prekey should add the new key to the store"
        );
    }

    /// Verify that `Keyhive::generate` populates the secret store.
    #[tokio::test]
    async fn test_keyhive_generate_populates_store() {
        use crate::{
            keyhive::Keyhive, listener::no_listener::NoListener,
            store::ciphertext::memory::MemoryCiphertextStore,
        };
        use keyhive_crypto::signer::memory::MemorySigner;

        let signer = MemorySigner::generate(&mut rand::thread_rng());
        let store = MemorySecretKeyStore::new();
        let ciphertext_store: MemoryCiphertextStore<[u8; 32], Vec<u8>> =
            MemoryCiphertextStore::new();
        let keyhive = Keyhive::<Sendable, _, _, _, _, _, _, _>::generate(
            signer,
            store,
            ciphertext_store,
            NoListener,
            rand::rngs::OsRng,
        )
        .await
        .unwrap();

        assert_eq!(
            keyhive.secret_store().len().await,
            7,
            "keyhive should have 7 prekeys in the store"
        );
    }

    /// Verify that `import_prekey_secrets` stores keys in the store.
    #[tokio::test]
    async fn test_import_prekey_secrets_stores_in_store() {
        use crate::{listener::no_listener::NoListener, principal::active::Active};
        use keyhive_crypto::signer::memory::MemorySigner;

        let store1 = MemorySecretKeyStore::new();
        let signer1 = MemorySigner::generate(&mut rand::thread_rng());
        let active1 =
            Active::<Sendable, MemorySigner, MemorySecretKeyStore, [u8; 32], NoListener>::generate(
                signer1,
                &store1,
                NoListener,
                &mut rand::thread_rng(),
            )
            .await
            .unwrap();

        let exported = active1.export_prekey_secrets().await.unwrap();

        let store2 = MemorySecretKeyStore::new();
        let signer2 = MemorySigner::generate(&mut rand::thread_rng());
        let active2 =
            Active::<Sendable, MemorySigner, MemorySecretKeyStore, [u8; 32], NoListener>::generate(
                signer2,
                &store2,
                NoListener,
                &mut rand::thread_rng(),
            )
            .await
            .unwrap();

        let before = store2.len().await;
        active2
            .import_prekey_secrets(&exported, &store2)
            .await
            .unwrap();

        assert!(
            store2.len().await > before,
            "imported keys should be added to the store"
        );
    }

    /// Verify that CGKA tree-ratcheted keys from `pcs_update` are
    /// synced to the durable store.
    #[tokio::test]
    async fn test_pcs_update_syncs_cgka_keys_to_store() {
        use crate::{
            keyhive::Keyhive, listener::no_listener::NoListener,
            store::ciphertext::memory::MemoryCiphertextStore,
        };
        use keyhive_crypto::signer::memory::MemorySigner;
        use nonempty::nonempty;

        let signer = MemorySigner::generate(&mut rand::thread_rng());
        let store = MemorySecretKeyStore::new();
        let ciphertext_store: MemoryCiphertextStore<[u8; 32], Vec<u8>> =
            MemoryCiphertextStore::new();
        let keyhive = Keyhive::<Sendable, _, _, _, _, _, _, _>::generate(
            signer,
            store,
            ciphertext_store,
            NoListener,
            rand::rngs::OsRng,
        )
        .await
        .unwrap();

        // Create a document
        let doc = keyhive
            .generate_doc(vec![], nonempty![[0u8; 32]])
            .await
            .unwrap();

        let keys_after_doc = keyhive.secret_store().len().await;

        // Perform a PCS update — this generates new tree keys
        keyhive.force_pcs_update(doc.clone()).await.unwrap();

        let keys_after_pcs = keyhive.secret_store().len().await;
        assert!(
            keys_after_pcs > keys_after_doc,
            "pcs_update should add tree-ratcheted keys to the store (before={keys_after_doc}, after={keys_after_pcs})"
        );
    }
}
