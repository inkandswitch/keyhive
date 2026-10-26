//! Low-level synchronous signer primitives.
//!
//! [`SyncSignerBasic`] signs bytes synchronously, for a key held in memory
//! (such as [`EphemeralSigner`](crate::signer::ephemeral::EphemeralSigner)).
//! Every signer also implements
//! [`AsyncSigner<F>`](crate::signer::async_signer::AsyncSigner), and
//! [`MemorySigner`](crate::signer::memory::MemorySigner) has synchronous
//! convenience methods.

use crate::signer::{async_signer::AsyncSigner, SigningError};
use ed25519_dalek::Signer;
use future_form::{future_form, FutureForm, Local, Sendable};
use tracing::instrument;

/// Implement [`AsyncSigner<F>`] for the raw `ed25519_dalek::SigningKey`.
///
/// Synchronous signing wrapped in [`F::ready`](FutureForm::ready).
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
    /// # use keyhive_crypto::signer::{memory::MemorySigner, sync_signer::SyncSignerBasic};
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
