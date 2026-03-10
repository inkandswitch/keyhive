//! Synchronous signer trait.

use super::async_signer::AsyncSigner;
use crate::{
    crypto::{
        signed::{Signed, SigningError},
        verifiable::Verifiable,
    },
    util::hex::ToHexString,
};
use ed25519_dalek::Signer;
use serde::Serialize;
use tracing::{info, instrument};

/// Synchronous signer trait. This is the primary sync signer API.
///
/// This trait is primarily used for the [`MemorySigner`],
/// but any synchronous signer can implement this trait.
///
/// [`MemorySigner`]: crate::crypto::signer::memory::MemorySigner
pub trait SyncSigner: Verifiable {
    /// Sign a byte slice synchronously.
    ///
    /// # Arguments
    ///
    /// * `payload_bytes` - The raw payload bytes to sign.
    ///
    /// # Examples
    ///
    /// ```
    /// use keyhive_core::crypto::{
    ///     signed::Signed,
    ///     signer::{
    ///         memory::MemorySigner,
    ///         sync_signer::SyncSigner
    ///     }
    /// };
    ///
    /// let signer = MemorySigner::generate(&mut rand::rngs::OsRng);
    /// let sig = signer.try_sign_bytes_sync(b"hello world");
    /// assert!(sig.is_ok());
    /// ```
    fn try_sign_bytes_sync(
        &self,
        payload_bytes: &[u8],
    ) -> Result<ed25519_dalek::Signature, SigningError>;

    /// Sign a serializable payload synchronously.
    ///
    /// This helper automatically serializes using [`bincode`], signs the resulting bytes,
    /// and wraps the result in [`Signed`].
    ///
    /// # Arguments
    ///
    /// * `payload` - The payload to serialize and sign.
    ///
    /// # Examples
    ///
    /// ```
    ///  use keyhive_core::crypto::{
    ///      signed::Signed,
    ///      signer::{
    ///          memory::MemorySigner,
    ///          sync_signer::SyncSigner
    ///      }
    ///  };
    ///
    /// let signer = MemorySigner::generate(&mut rand::rngs::OsRng);
    ///
    /// let payload: Vec<u8> = vec![0, 1, 2];
    /// let sig = signer.try_sign_sync(payload.clone());
    ///
    /// assert!(sig.is_ok());
    /// assert_eq!(*sig.unwrap().payload(), payload);
    /// ```
    fn try_sign_sync<T: Serialize + std::fmt::Debug>(
        &self,
        payload: T,
    ) -> Result<Signed<T>, SigningError> {
        let payload_bytes: Vec<u8> = bincode::serialize(&payload)?;

        Ok(Signed {
            payload,
            issuer: self.verifying_key(),
            signature: self.try_sign_bytes_sync(payload_bytes.as_slice())?,
        })
    }
}

impl SyncSigner for ed25519_dalek::SigningKey {
    #[instrument(skip(self))]
    fn try_sign_bytes_sync(
        &self,
        payload_bytes: &[u8],
    ) -> Result<ed25519_dalek::Signature, SigningError> {
        self.try_sign(payload_bytes)
            .map_err(SigningError::SigningFailed)
    }
}

impl<T: SyncSigner> AsyncSigner for T {
    #[instrument(skip_all)]
    async fn try_sign_bytes_async(
        &self,
        payload_bytes: &[u8],
    ) -> Result<ed25519_dalek::Signature, SigningError> {
        self.try_sign_bytes_sync(payload_bytes)
    }
}

/// Low-level variant of [`SyncSigner`].
///
/// This is less constrained, and lower-level, than [`SyncSigner`].
///
/// If you aren't passing something to [`EphemeralSigner`],
/// you more likely want [`SyncSigner`].
pub trait SyncSignerBasic {
    /// Sign a byte slice synchronously.
    ///
    /// # Examples
    ///
    /// ```
    /// # use keyhive_core::crypto::{
    /// #   signed::Signed,
    /// #   signer::{
    /// #     memory::MemorySigner,
    /// #     sync_signer::SyncSignerBasic
    /// #   }
    /// # };
    /// #
    /// let signer = MemorySigner::generate(&mut rand::rngs::OsRng);
    /// let sig = signer.try_sign_bytes_sync_basic(b"hello world");
    /// assert!(sig.is_ok());
    /// ```
    fn try_sign_bytes_sync_basic(
        &self,
        payload_bytes: &[u8],
    ) -> Result<ed25519_dalek::Signature, SigningError>;
}

impl<T: SyncSigner> SyncSignerBasic for T {
    #[instrument(skip(self))]
    fn try_sign_bytes_sync_basic(
        &self,
        payload_bytes: &[u8],
    ) -> Result<ed25519_dalek::Signature, SigningError> {
        T::try_sign_bytes_sync(self, payload_bytes)
    }
}

/// Wrapper to lift the result of a low-level [`SyncSignerBasic`] into [`Signed`].
#[instrument(skip_all, fields(issuer = issuer.to_hex_string()))]
pub fn try_sign_basic<S: SyncSignerBasic + ?Sized, T: Serialize + std::fmt::Debug>(
    signer: &S,
    issuer: ed25519_dalek::VerifyingKey,
    payload: T,
) -> Result<Signed<T>, SigningError> {
    let bytes = bincode::serialize(&payload)?;
    let signature = signer.try_sign_bytes_sync_basic(bytes.as_slice())?;
    info!("signature: {:0x?}", signature.to_bytes());
    Ok(Signed {
        signature,
        payload,
        issuer,
    })
}
