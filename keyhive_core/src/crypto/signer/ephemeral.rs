//! Ephemeral signers that are only valid for a short period of time.

use super::sync_signer::SyncSignerBasic;
use crate::crypto::verifiable::Verifiable;
use derive_more::{From, Into};
use std::future::Future;
use tracing::instrument;

/// An ephemeral signer that never exposes its signing key.
///
/// This is a very specialized signer that only lives for the lifetime inside
/// a specified closure. This is useful for initial setup and delegation of a
/// [`Group`] or [`Document`], where the signing key should then be forgotten.
///
/// [`Document`]: crate::principal::document::Document
/// [`Group`]: crate::principal::group::Group
#[derive(Debug, From, Into)]
pub struct EphemeralSigner(ed25519_dalek::SigningKey);

impl EphemeralSigner {
    /// Run a closure with a randomly generated ephemeral key.
    ///
    /// # Arguments
    ///
    /// * `csprng` - A cryptographically secure random number generator.
    /// * `f` - A closure that takes the ephemeral verifying key and a signer.
    ///
    /// # Examples
    ///
    /// ```
    /// use keyhive_core::crypto::{
    ///     signed::Signed,
    ///     signer::{
    ///         async_signer::AsyncSigner,
    ///         ephemeral::EphemeralSigner,
    ///     }
    /// };
    ///
    /// let ((signature, returned_payload), _vk) =
    ///     EphemeralSigner::with_signer(&mut rand::rngs::OsRng, |vk, sk| {
    ///         let payload = vec![1, 2, 3];
    ///         let sig = sk.try_sign_bytes_sync_basic(payload.as_slice());
    ///         (sig, payload)
    ///     });
    ///
    /// assert!(signature.is_ok());
    /// assert_eq!(returned_payload, vec![1, 2, 3]);
    /// ```
    pub fn with_signer<T, R: rand::CryptoRng + rand::RngCore>(
        csprng: &mut R,
        f: impl FnOnce(ed25519_dalek::VerifyingKey, Box<dyn SyncSignerBasic>) -> T,
    ) -> (T, ed25519_dalek::VerifyingKey) {
        let sk = ed25519_dalek::SigningKey::generate(csprng);
        let vk = sk.verifying_key();
        (f(vk, Box::new(sk)), vk)
    }

    /// Run an async closure with a randomly generated ephemeral key.
    ///
    /// ```
    /// use keyhive_core::crypto::{
    ///     signed::Signed,
    ///     signer::{
    ///         async_signer::AsyncSigner,
    ///         ephemeral::EphemeralSigner,
    ///     }
    /// };
    ///
    /// #[tokio::main(flavor = "current_thread")]
    /// async fn main() {
    ///     let mut csprng = rand::rngs::OsRng;
    ///     let (fut, _vk) = EphemeralSigner::with_signer_async(&mut csprng, |vk, sk| async move {
    ///         let payload = vec![1, 2, 3];
    ///         let sig = sk.try_sign(payload.as_slice());
    ///         (sig, payload)
    ///     }).await;
    ///
    ///     let (signature, returned_payload) = fut.await;
    ///
    ///     assert!(signature.is_ok());
    ///     assert_eq!(returned_payload, vec![1, 2, 3]);
    /// }
    /// ```
    pub async fn with_signer_async<
        T,
        R: rand::CryptoRng + rand::RngCore,
        Fut: Future<Output = T>,
    >(
        csprng: &mut R,
        f: impl FnOnce(
            ed25519_dalek::VerifyingKey,
            Box<dyn ed25519_dalek::Signer<ed25519_dalek::Signature>>,
        ) -> Fut,
    ) -> (Fut, ed25519_dalek::VerifyingKey) {
        let sk = ed25519_dalek::SigningKey::generate(csprng);
        let vk = sk.verifying_key();
        (f(vk, Box::new(sk)), vk)
    }
}

impl ed25519_dalek::Signer<ed25519_dalek::Signature> for EphemeralSigner {
    #[instrument(skip(self))]
    fn try_sign(
        &self,
        msg: &[u8],
    ) -> Result<ed25519_dalek::Signature, ed25519_dalek::SignatureError> {
        self.0.try_sign(msg)
    }
}

impl Verifiable for EphemeralSigner {
    fn verifying_key(&self) -> ed25519_dalek::VerifyingKey {
        self.0.verifying_key()
    }
}
