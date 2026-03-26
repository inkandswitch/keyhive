//! Low-level synchronous signer primitives.
//!
//! The [`SyncSigner`] trait has been removed. Synchronous signing
//! convenience methods are now concrete methods on
//! [`MemorySigner`](crate::signer::memory::MemorySigner). All
//! signers implement [`AsyncSigner<F>`](crate::signer::async_signer::AsyncSigner)
//! directly.
//!
//! This module retains [`SyncSignerBasic`] (used by
//! [`EphemeralSigner`](crate::signer::ephemeral::EphemeralSigner))
//! and the [`try_sign_basic`] helper.

use crate::{signed::SigningError, signer::async_signer::AsyncSigner};
use ed25519_dalek::Signer;
use future_form::{future_form, FutureForm, Local, Sendable};
use tracing::instrument;
#[cfg(feature = "std")]
use {
    crate::{hex::ToHexString, signed::Signed},
    serde::Serialize,
    tracing::info,
};

/// Implement [`AsyncSigner<F>`] for the raw `ed25519_dalek::SigningKey`.
///
/// Synchronous signing wrapped in [`F::ready`].
#[future_form(Sendable, Local)]
impl<F: FutureForm> AsyncSigner<F> for ed25519_dalek::SigningKey {
    fn try_sign_bytes_async<'a>(
        &'a self,
        payload_bytes: &'a [u8],
    ) -> F::Future<'a, Result<ed25519_dalek::Signature, SigningError>> {
        F::ready(
            self.try_sign(payload_bytes)
                .map_err(SigningError::SigningFailed),
        )
    }
}

/// Low-level variant of the (now-removed) `SyncSigner`.
///
/// This is less constrained and lower-level. It is used by
/// [`EphemeralSigner`](crate::signer::ephemeral::EphemeralSigner)
/// which takes a `Box<dyn SyncSignerBasic>`.
pub trait SyncSignerBasic {
    /// Sign a byte slice synchronously.
    ///
    /// # Examples
    ///
    /// ```
    /// # use keyhive_crypto::{
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

impl SyncSignerBasic for ed25519_dalek::SigningKey {
    #[instrument(skip(self))]
    fn try_sign_bytes_sync_basic(
        &self,
        payload_bytes: &[u8],
    ) -> Result<ed25519_dalek::Signature, SigningError> {
        self.try_sign(payload_bytes)
            .map_err(SigningError::SigningFailed)
    }
}

/// Wrapper to lift the result of a low-level [`SyncSignerBasic`] into [`Signed`].
///
/// Requires the `std` feature (uses [`bincode`] for serialization).
#[cfg(feature = "std")]
#[instrument(skip_all, fields(issuer = issuer.to_hex_string()))]
pub fn try_sign_basic<S: SyncSignerBasic + ?Sized, T: Serialize + core::fmt::Debug>(
    signer: &S,
    issuer: ed25519_dalek::VerifyingKey,
    payload: T,
) -> Result<Signed<T>, SigningError> {
    let bytes = bincode::serialize(&payload)?;
    let signature = signer.try_sign_bytes_sync_basic(bytes.as_slice())?;
    info!("signature: {:0x?}", signature.to_bytes());
    let signed = Signed::new(payload, issuer, signature);
    Ok(signed)
}
