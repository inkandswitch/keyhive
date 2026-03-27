//! Pluggable secret key storage.
//!
//! The [`SecretKeyStore`] trait abstracts over secret key storage,
//! enabling keys to live in durable backends (IndexedDB, SQLite,
//! KMS, hardware enclaves) rather than only in process memory.
//!
//! The default implementation ([`MemorySecretKeyStore`]) stores
//! keys in an in-memory `BTreeMap` and is infallible.

pub mod memory;

use future_form::FutureForm;
use keyhive_crypto::share_key::{AsyncSecretKey, ShareKey, ShareSecretKey};
use std::fmt::{Debug, Display};

/// Async trait for storing and retrieving ECDH secret keys.
///
/// The `F: FutureForm` parameter determines whether returned
/// futures are `Send` or `!Send`.
///
/// The `SecretKey` associated type is the handle to a stored key.
/// For in-memory stores this is [`ShareSecretKey`] directly. For
/// external stores (KMS, WebCrypto) it may be an opaque handle
/// that implements [`AsyncSecretKey`] for ECDH operations.
pub trait SecretKeyStore<F: FutureForm>: Sized {
    /// The secret key handle type.
    type SecretKey: AsyncSecretKey<F>;

    /// Error returned when looking up a key fails.
    type GetError: Debug + Display;

    /// Error returned when storing/importing a key fails.
    type ImportError: Debug + Display;

    /// Error returned when generating a new key fails.
    type GenerateError: Debug + Display;

    /// Look up a secret key by its public key.
    ///
    /// Returns `Ok(None)` if the key is not in the store.
    fn get_secret_key<'a>(
        &'a self,
        public_key: &'a ShareKey,
    ) -> F::Future<'a, Result<Option<Self::SecretKey>, Self::GetError>>;

    /// Store a secret key, indexed by its public key.
    ///
    /// If a key with the same public key already exists, it is
    /// overwritten.
    fn import_secret_key<'a>(
        &'a mut self,
        secret_key: Self::SecretKey,
    ) -> F::Future<'a, Result<ShareKey, Self::ImportError>>;

    /// Import a raw [`ShareSecretKey`] (e.g., from deserialization).
    ///
    /// This is separate from [`import_secret_key`] because external
    /// stores may need to convert raw bytes into an opaque handle.
    fn import_raw_secret_key<'a>(
        &'a mut self,
        raw: ShareSecretKey,
    ) -> F::Future<'a, Result<Self::SecretKey, Self::ImportError>>;

    /// Generate a new keypair and store it.
    ///
    /// Returns the secret key handle. The corresponding public key
    /// can be obtained via [`AsyncSecretKey::to_share_key`].
    fn generate_secret_key<'a>(
        &'a mut self,
    ) -> F::Future<'a, Result<Self::SecretKey, Self::GenerateError>>;

    /// Check if a secret key for the given public key exists.
    fn contains_secret_key<'a>(
        &'a self,
        public_key: &'a ShareKey,
    ) -> F::Future<'a, Result<bool, Self::GetError>>;
}
