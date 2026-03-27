//! In-memory signer.

use super::sync_signer::SyncSignerBasic;
use crate::{signed::SigningError, signer::async_signer::AsyncSigner, verifiable::Verifiable};
use core::hash::Hash;
use ed25519_dalek::Signer;
use future_form::{future_form, FutureForm, Local, Sendable};
use tracing::instrument;
#[cfg(feature = "std")]
use {crate::signed::Signed, alloc::vec::Vec, dupe::Dupe, serde::Serialize};

/// An in-memory signer.
///
/// This signer is backed by an in-memory Ed25519 signing key.
///
/// <div class="warning">
///
/// While very convenient, an in-memory signing key can be leaked.
/// It is recommended to use a non-extractable key (and thus [`AsyncSigner`])
/// instead.
///
/// </div>
///
/// [`AsyncSigner`]: crate::signer::async_signer::AsyncSigner
#[derive(Debug, Clone)]
pub struct MemorySigner(
    /// Raw underlying Ed25519 signing key.
    pub ed25519_dalek::SigningKey,
);

impl MemorySigner {
    /// Randomly generates a new in-memory signer.
    ///
    /// # Arguments
    ///
    /// * `csprng` - A cryptographically secure random number generator.
    ///
    /// # Examples
    ///
    /// ```
    /// # use keyhive_crypto::{
    /// #    signer::memory::MemorySigner,
    /// #    verifiable::Verifiable
    /// # };
    /// let signer = MemorySigner::generate(&mut rand::rngs::OsRng);
    /// assert_eq!(signer.0.to_bytes().len(), 32);
    /// assert_eq!(signer.verifying_key().to_bytes().len(), 32);
    /// ```
    pub fn generate<R: rand::CryptoRng + rand::RngCore>(csprng: &mut R) -> Self {
        Self(ed25519_dalek::SigningKey::generate(csprng))
    }

    /// Sign a byte slice synchronously.
    ///
    /// Convenience method for tests and contexts where async is
    /// unnecessary. The same operation is available via
    /// [`AsyncSigner::try_sign_bytes_async`] (which wraps this with
    /// [`FutureForm::ready`]).
    pub fn try_sign_bytes_sync(
        &self,
        payload_bytes: &[u8],
    ) -> Result<ed25519_dalek::Signature, SigningError> {
        self.0
            .try_sign(payload_bytes)
            .map_err(SigningError::SigningFailed)
    }

    /// Sign a serializable payload synchronously.
    ///
    /// Convenience method for tests. Serializes with [`bincode`],
    /// signs the bytes, and wraps in [`Signed`].
    #[cfg(feature = "std")]
    pub fn try_sign_sync<T: Serialize + core::fmt::Debug>(
        &self,
        payload: T,
    ) -> Result<Signed<T>, SigningError> {
        let payload_bytes: Vec<u8> = bincode::serialize(&payload)?;
        let signature = self.try_sign_bytes_sync(payload_bytes.as_slice())?;
        let signed = Signed::new(payload, self.verifying_key(), signature);
        Ok(signed)
    }
}

#[future_form(Sendable, Local)]
impl<F: FutureForm> AsyncSigner<F> for MemorySigner {
    fn try_sign_bytes_async<'a>(
        &'a self,
        payload_bytes: &'a [u8],
    ) -> F::Future<'a, Result<ed25519_dalek::Signature, SigningError>> {
        F::ready(self.try_sign_bytes_sync(payload_bytes))
    }
}

impl SyncSignerBasic for MemorySigner {
    #[instrument(skip(self))]
    fn try_sign_bytes_sync_basic(
        &self,
        payload_bytes: &[u8],
    ) -> Result<ed25519_dalek::Signature, SigningError> {
        self.try_sign_bytes_sync(payload_bytes)
    }
}

impl Hash for MemorySigner {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.verifying_key().hash(state);
    }
}

#[cfg(feature = "std")]
impl Dupe for MemorySigner {
    fn dupe(&self) -> Self {
        Self(self.0.clone())
    }
}

impl PartialEq for MemorySigner {
    fn eq(&self, other: &Self) -> bool {
        self.verifying_key() == other.verifying_key()
    }
}

impl Eq for MemorySigner {}

impl From<ed25519_dalek::SigningKey> for MemorySigner {
    fn from(key: ed25519_dalek::SigningKey) -> Self {
        Self(key)
    }
}

impl ed25519_dalek::Signer<ed25519_dalek::Signature> for MemorySigner {
    #[instrument(skip(self))]
    fn try_sign(
        &self,
        msg: &[u8],
    ) -> Result<ed25519_dalek::Signature, ed25519_dalek::SignatureError> {
        self.0.try_sign(msg)
    }
}

impl Verifiable for MemorySigner {
    fn verifying_key(&self) -> ed25519_dalek::VerifyingKey {
        self.0.verifying_key()
    }
}
