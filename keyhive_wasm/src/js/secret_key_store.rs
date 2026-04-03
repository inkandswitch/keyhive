//! Pluggable secret key store for Wasm.
//!
//! Provides two backends:
//! - [`JsSecretKeyStore::memory()`] — in-memory only (for Node.js tests)
//! - [`JsSecretKeyStore::load_from_indexed_db()`] — IndexedDB-backed with
//!   in-memory cache (for browsers)

use future_form::{FutureForm, Local};
use futures::lock::Mutex;
use keyhive_core::store::secret_key::SecretKeyStore;
use keyhive_crypto::share_key::{ShareKey, ShareSecretKey};
use std::{collections::BTreeMap, sync::Arc};
use thiserror::Error;
use wasm_bindgen::prelude::*;

// JS interop for IndexedDB persistence
#[wasm_bindgen(module = "/src/js/secret_key_store_idb.js")]
extern "C" {
    #[wasm_bindgen(catch)]
    async fn idb_load_all_keys() -> Result<JsValue, JsValue>;

    #[wasm_bindgen(catch)]
    async fn idb_store_key(public_key_hex: &str, secret_key_bytes: &[u8]) -> Result<(), JsValue>;
}

/// Secret key store for Wasm.
///
/// Two backends are available:
/// - [`memory()`](JsSecretKeyStore::memory) — in-memory only, no persistence.
///   Use for Node.js tests or environments without IndexedDB.
/// - [`load_from_indexed_db()`](JsSecretKeyStore::load_from_indexed_db) —
///   IndexedDB-backed with in-memory cache. Keys persist across page reloads.
///
/// # Security
///
/// The IndexedDB backend stores raw secret key bytes in cleartext.
/// Any same-origin JavaScript can read them. For stronger protection,
/// a future implementation should use WebCrypto `SubtleCrypto`
/// with non-extractable X25519 `CryptoKey` handles — the
/// [`AsyncSecretKey`](keyhive_crypto::share_key::AsyncSecretKey)
/// trait's return types are designed to support this.
#[wasm_bindgen(js_name = SecretKeyStore)]
#[derive(Debug, Clone)]
pub struct JsSecretKeyStore {
    cache: Arc<Mutex<BTreeMap<ShareKey, ShareSecretKey>>>,
    /// Whether to persist mutations to IndexedDB.
    persistent: bool,
}

#[wasm_bindgen(js_class = SecretKeyStore)]
impl JsSecretKeyStore {
    /// Create an in-memory-only store (no IndexedDB persistence).
    ///
    /// Use for Node.js tests or environments without IndexedDB.
    #[wasm_bindgen]
    pub fn memory() -> Self {
        Self {
            cache: Arc::new(Mutex::new(BTreeMap::new())),
            persistent: false,
        }
    }

    /// Load keys from IndexedDB and create a persistent store.
    ///
    /// Keys are cached in memory for fast lookups and written
    /// back to IndexedDB on every mutation.
    #[wasm_bindgen(js_name = loadFromIndexedDB)]
    pub async fn load_from_indexed_db() -> Result<JsSecretKeyStore, JsError> {
        let js_entries = idb_load_all_keys()
            .await
            .map_err(|e| JsError::new(&format!("IndexedDB load failed: {e:?}")))?;

        let mut cache = BTreeMap::new();

        let entries = js_sys::Array::from(&js_entries);
        for i in 0..entries.length() {
            let pair = js_sys::Array::from(&entries.get(i));
            let sk_array = js_sys::Uint8Array::new(&pair.get(1));
            let sk_bytes: Vec<u8> = sk_array.to_vec();

            if sk_bytes.len() != 32 {
                continue; // skip malformed entries
            }

            let mut arr = [0u8; 32];
            arr.copy_from_slice(&sk_bytes);
            let sk = ShareSecretKey::from_bytes(arr);
            let pk = sk.share_key();
            cache.insert(pk, sk);
        }

        Ok(Self {
            cache: Arc::new(Mutex::new(cache)),
            persistent: true,
        })
    }
}

impl JsSecretKeyStore {
    /// Persist a key to IndexedDB (no-op if not persistent).
    async fn maybe_persist(
        &self,
        pk: &ShareKey,
        sk: &ShareSecretKey,
    ) -> Result<(), JsSecretKeyStoreError> {
        if self.persistent {
            let pk_hex = to_hex(pk.as_bytes());
            idb_store_key(&pk_hex, &sk.to_bytes())
                .await
                .map_err(JsSecretKeyStoreError::IdbError)?;
        }
        Ok(())
    }
}

impl Default for JsSecretKeyStore {
    fn default() -> Self {
        Self::memory()
    }
}

impl SecretKeyStore<Local> for JsSecretKeyStore {
    type SecretKey = ShareSecretKey;
    type GetError = JsSecretKeyStoreError;
    type ImportError = JsSecretKeyStoreError;
    type GenerateError = JsSecretKeyStoreError;

    fn get_secret_key<'a>(
        &'a self,
        public_key: &'a ShareKey,
    ) -> <Local as FutureForm>::Future<'a, Result<Option<ShareSecretKey>, Self::GetError>> {
        Local::from_future(async move { Ok(self.cache.lock().await.get(public_key).copied()) })
    }

    fn import_secret_key<'a>(
        &'a self,
        secret_key: ShareSecretKey,
    ) -> <Local as FutureForm>::Future<'a, Result<ShareKey, Self::ImportError>> {
        Local::from_future(async move {
            let pk = secret_key.share_key();
            self.cache.lock().await.insert(pk, secret_key);
            self.maybe_persist(&pk, &secret_key).await?;
            Ok(pk)
        })
    }

    fn import_raw_secret_key<'a>(
        &'a self,
        raw: ShareSecretKey,
    ) -> <Local as FutureForm>::Future<'a, Result<ShareSecretKey, Self::ImportError>> {
        Local::from_future(async move {
            let pk = raw.share_key();
            self.cache.lock().await.insert(pk, raw);
            self.maybe_persist(&pk, &raw).await?;
            Ok(raw)
        })
    }

    fn generate_secret_key<'a>(
        &'a self,
    ) -> <Local as FutureForm>::Future<'a, Result<ShareSecretKey, Self::GenerateError>> {
        Local::from_future(async move {
            let sk = ShareSecretKey::generate(&mut rand::thread_rng());
            let pk = sk.share_key();
            self.cache.lock().await.insert(pk, sk);
            self.maybe_persist(&pk, &sk).await?;
            Ok(sk)
        })
    }

    fn contains_secret_key<'a>(
        &'a self,
        public_key: &'a ShareKey,
    ) -> <Local as FutureForm>::Future<'a, Result<bool, Self::GetError>> {
        Local::from_future(async move { Ok(self.cache.lock().await.contains_key(public_key)) })
    }
}

#[derive(Debug, Clone, Error)]
pub enum JsSecretKeyStoreError {
    #[error("IndexedDB error: {0:?}")]
    IdbError(JsValue),

    #[error("Parse error: {0}")]
    ParseError(String),
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
