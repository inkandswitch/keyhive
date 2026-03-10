//! Async [Ed25519] signer trait.
//!
//! [Ed25519]: https://en.wikipedia.org/wiki/EdDSA#Ed25519

use crate::crypto::{
    signed::{Signed, SigningError},
    verifiable::Verifiable,
};
use serde::Serialize;
use tracing::instrument;

#[allow(async_fn_in_trait)]
/// Async [Ed25519] signer trait.
///
/// This is especially helpful for signing with keys that are externally managed,
/// such as via the WebCrypto API, a hardware wallet, or a remote signing service / KMS.
///
/// <div class="warning">
///
/// NOTE: we presently assume single-threaded async (esp targetting Wasm which is `!Send`).
/// If multithreaded async is desired, please let the authors know on the [GitHub Repo]
/// or in the [Automerge Discord].
///
/// </div>
///
/// [Ed25519]: https://en.wikipedia.org/wiki/EdDSA#Ed25519
/// [GitHub Repo]: https://github.com/inkandswitch/keyhive/issues
/// [Automerge Discord]: https://discord.com/channels/1200006940210757672/1200006941586509876
pub trait AsyncSigner: Verifiable {
    /// Sign a byte slice asynchronously.
    ///
    /// # Arguments
    ///
    /// * `payload_bytes` - The raw payload bytes to sign.
    ///
    /// # Examples
    ///
    /// ```
    /// use keyhive_core::crypto::{
    ///    signed::Signed,
    ///    signer::{
    ///        async_signer::AsyncSigner,
    ///        memory::MemorySigner
    ///    }
    /// };
    ///
    /// #[tokio::main(flavor = "current_thread")]
    /// async fn main() {
    ///     let signer = MemorySigner::generate(&mut rand::thread_rng());
    ///     let sig = signer.try_sign_bytes_async(b"hello world").await;
    ///     assert!(sig.is_ok());
    /// }
    /// ```
    async fn try_sign_bytes_async(
        &self,
        payload_bytes: &[u8],
    ) -> Result<ed25519_dalek::Signature, SigningError>;

    /// Sign a serializable payload asynchronously.
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
    /// use keyhive_core::crypto::{
    ///     signed::Signed,
    ///     signer::{
    ///         async_signer::AsyncSigner,
    ///         memory::MemorySigner
    ///     }
    /// };
    ///
    /// #[tokio::main(flavor = "current_thread")]
    /// async fn main() {
    ///     let signer = MemorySigner::generate(&mut rand::thread_rng());
    ///
    ///     let payload: Vec<u8> = vec![0, 1, 2];
    ///     let sig = signer.try_sign_async(payload.clone()).await;
    ///
    ///     assert!(sig.is_ok());
    ///     assert_eq!(*sig.unwrap().payload(), payload);
    /// }
    /// ```
    #[instrument(skip_all)]
    async fn try_sign_async<T: Serialize + std::fmt::Debug>(
        &self,
        payload: T,
    ) -> Result<Signed<T>, SigningError> {
        let payload_bytes: Vec<u8> = bincode::serialize(&payload)?;

        Ok(Signed {
            payload,
            issuer: self.verifying_key(),
            signature: self.try_sign_bytes_async(payload_bytes.as_slice()).await?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::signer::memory::MemorySigner;

    #[tokio::test]
    async fn test_round_trip() {
        test_utils::init_logging();
        let sk = MemorySigner::generate(&mut rand::thread_rng());
        let signed = sk.try_sign_async(vec![1, 2, 3]).await.unwrap();
        assert!(signed.try_verify().is_ok());
    }
}
