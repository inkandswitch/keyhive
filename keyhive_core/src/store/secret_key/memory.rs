//! In-memory secret key store.
//!
//! Stores keys in a `BTreeMap<ShareKey, ShareSecretKey>`. All
//! operations are infallible.

use super::SecretKeyStore;
use future_form::{future_form, FutureForm, Local, Sendable};
use keyhive_crypto::share_key::{ShareKey, ShareSecretKey};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, convert::Infallible};

/// In-memory secret key store backed by a `BTreeMap`.
///
/// This is the default store for development and testing.
/// For production use with durable keys, implement
/// [`SecretKeyStore`] for your storage backend.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MemorySecretKeyStore {
    keys: BTreeMap<ShareKey, ShareSecretKey>,
}

impl MemorySecretKeyStore {
    pub fn new() -> Self {
        Self {
            keys: BTreeMap::new(),
        }
    }

    /// Number of keys in the store.
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Whether the store is empty.
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// Iterate over all (public, secret) key pairs.
    pub fn iter(&self) -> impl Iterator<Item = (&ShareKey, &ShareSecretKey)> {
        self.keys.iter()
    }

    /// Extend the store with key pairs from another source.
    pub fn extend(&mut self, other: impl IntoIterator<Item = (ShareKey, ShareSecretKey)>) {
        self.keys.extend(other);
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
        F::ready(Ok(self.keys.get(public_key).copied()))
    }

    fn import_secret_key<'a>(
        &'a mut self,
        secret_key: ShareSecretKey,
    ) -> F::Future<'a, Result<ShareKey, Infallible>> {
        let pk = secret_key.share_key();
        self.keys.insert(pk, secret_key);
        F::ready(Ok(pk))
    }

    fn import_raw_secret_key<'a>(
        &'a mut self,
        raw: ShareSecretKey,
    ) -> F::Future<'a, Result<ShareSecretKey, Infallible>> {
        let pk = raw.share_key();
        self.keys.insert(pk, raw);
        F::ready(Ok(raw))
    }

    fn generate_secret_key<'a>(&'a mut self) -> F::Future<'a, Result<ShareSecretKey, Infallible>> {
        let sk = ShareSecretKey::generate(&mut rand::thread_rng());
        let pk = sk.share_key();
        self.keys.insert(pk, sk);
        F::ready(Ok(sk))
    }

    fn contains_secret_key<'a>(
        &'a self,
        public_key: &'a ShareKey,
    ) -> F::Future<'a, Result<bool, Infallible>> {
        F::ready(Ok(self.keys.contains_key(public_key)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use future_form::Sendable;

    #[tokio::test]
    async fn test_generate_and_retrieve() {
        let mut store = MemorySecretKeyStore::new();
        assert!(store.is_empty());

        let sk = SecretKeyStore::<Sendable>::generate_secret_key(&mut store)
            .await
            .unwrap();
        assert_eq!(store.len(), 1);

        let pk = sk.share_key();
        let retrieved = SecretKeyStore::<Sendable>::get_secret_key(&store, &pk)
            .await
            .unwrap();
        assert_eq!(retrieved, Some(sk));
    }

    #[tokio::test]
    async fn test_import_raw() {
        let mut store = MemorySecretKeyStore::new();
        let sk = ShareSecretKey::generate(&mut rand::thread_rng());
        let pk = sk.share_key();

        let imported = SecretKeyStore::<Sendable>::import_raw_secret_key(&mut store, sk)
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
}
