//! IndexedDB-backed secret key store for Wasm.
//!
//! Stores X25519 secret key bytes in IndexedDB for durability across
//! page reloads, with an in-memory `BTreeMap` cache for fast lookups.
//! Keys are loaded from IndexedDB on construction and written back
//! on every mutation.

use future_form::{FutureForm, Local};
use keyhive_core::store::secret_key::SecretKeyStore;
use keyhive_crypto::share_key::{ShareKey, ShareSecretKey};
use std::collections::BTreeMap;
use thiserror::Error;
use wasm_bindgen::prelude::*;

// JS interop for IndexedDB persistence
#[wasm_bindgen(module = "/src/js/secret_key_store_idb.js")]
extern "C" {
    #[wasm_bindgen(catch)]
    async fn idb_load_all_keys() -> Result<JsValue, JsValue>;

    #[wasm_bindgen(catch)]
    async fn idb_store_key(public_key_hex: &str, secret_key_bytes: &[u8]) -> Result<(), JsValue>;

    #[wasm_bindgen(catch)]
    async fn idb_has_key(public_key_hex: &str) -> Result<JsValue, JsValue>;
}

/// IndexedDB-backed secret key store.
///
/// Maintains an in-memory cache (`BTreeMap`) synchronized with
/// IndexedDB for persistence across page reloads. All ECDH
/// operations happen in-process using `x25519_dalek` (compiled
/// to Wasm).
#[derive(Debug, Clone)]
pub struct JsSecretKeyStore {
    cache: BTreeMap<ShareKey, ShareSecretKey>,
}

impl JsSecretKeyStore {
    /// Create a new empty store (call [`load`] to hydrate from IndexedDB).
    pub fn new() -> Self {
        Self {
            cache: BTreeMap::new(),
        }
    }

    /// Load all keys from IndexedDB into the in-memory cache.
    ///
    /// Call this once on startup before using the store.
    pub async fn load() -> Result<Self, JsSecretKeyStoreError> {
        let js_entries = idb_load_all_keys()
            .await
            .map_err(JsSecretKeyStoreError::IdbError)?;

        let mut cache = BTreeMap::new();

        // js_entries is an array of [hex_public_key, Uint8Array_secret_key]
        let entries = js_sys::Array::from(&js_entries);
        for i in 0..entries.length() {
            let pair = js_sys::Array::from(&entries.get(i));
            let _pk_hex = pair.get(0).as_string().ok_or_else(|| {
                JsSecretKeyStoreError::ParseError("public key not a string".into())
            })?;
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

        Ok(Self { cache })
    }

    /// Persist a key to IndexedDB.
    async fn persist(
        &self,
        pk: &ShareKey,
        sk: &ShareSecretKey,
    ) -> Result<(), JsSecretKeyStoreError> {
        let pk_hex = to_hex(pk.as_bytes());
        idb_store_key(&pk_hex, &sk.to_bytes())
            .await
            .map_err(JsSecretKeyStoreError::IdbError)
    }
}

impl Default for JsSecretKeyStore {
    fn default() -> Self {
        Self::new()
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
        // Fast path: check in-memory cache (no IDB round-trip)
        Local::ready(Ok(self.cache.get(public_key).copied()))
    }

    fn import_secret_key<'a>(
        &'a mut self,
        secret_key: ShareSecretKey,
    ) -> <Local as FutureForm>::Future<'a, Result<ShareKey, Self::ImportError>> {
        let pk = secret_key.share_key();
        self.cache.insert(pk, secret_key);
        Local::from_future(async move {
            self.persist(&pk, &secret_key).await?;
            Ok(pk)
        })
    }

    fn import_raw_secret_key<'a>(
        &'a mut self,
        raw: ShareSecretKey,
    ) -> <Local as FutureForm>::Future<'a, Result<ShareSecretKey, Self::ImportError>> {
        let pk = raw.share_key();
        self.cache.insert(pk, raw);
        Local::from_future(async move {
            self.persist(&pk, &raw).await?;
            Ok(raw)
        })
    }

    fn generate_secret_key<'a>(
        &'a mut self,
    ) -> <Local as FutureForm>::Future<'a, Result<ShareSecretKey, Self::GenerateError>> {
        let sk = ShareSecretKey::generate(&mut rand::thread_rng());
        let pk = sk.share_key();
        self.cache.insert(pk, sk);
        Local::from_future(async move {
            self.persist(&pk, &sk).await?;
            Ok(sk)
        })
    }

    fn contains_secret_key<'a>(
        &'a self,
        public_key: &'a ShareKey,
    ) -> <Local as FutureForm>::Future<'a, Result<bool, Self::GetError>> {
        Local::ready(Ok(self.cache.contains_key(public_key)))
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
