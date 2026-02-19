//! Async [Ed25519] signer trait.
//!
//! [Ed25519]: https://en.wikipedia.org/wiki/EdDSA#Ed25519

use crate::crypto::{
    signed::{Signed, SigningError},
    verifiable::Verifiable,
};
use future_form::FutureForm;
use serde::Serialize;

/// Async [Ed25519] signer trait.
///
/// This is especially helpful for signing with keys that are externally managed,
/// such as via the WebCrypto API, a hardware wallet, or a remote signing service / KMS.
///
/// The `K` type parameter controls whether futures are `Send` (`Sendable`) or not (`Local`).
/// Use `Sendable` for multi-threaded runtimes (e.g., Tokio) and `Local` for single-threaded
/// contexts (e.g., Wasm).
///
/// [Ed25519]: https://en.wikipedia.org/wiki/EdDSA#Ed25519
pub trait AsyncSigner<K: FutureForm + ?Sized>: Verifiable {
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
    /// use future_form::Local;
    ///
    /// #[tokio::main(flavor = "current_thread")]
    /// async fn main() {
    ///     let signer = MemorySigner::generate(&mut rand::thread_rng());
    ///     let sig = AsyncSigner::<Local>::try_sign_bytes_async(&signer, b"hello world").await;
    ///     assert!(sig.is_ok());
    /// }
    /// ```
    fn try_sign_bytes_async<'a>(
        &'a self,
        payload_bytes: &'a [u8],
    ) -> K::Future<'a, Result<ed25519_dalek::Signature, SigningError>>;

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
    /// use future_form::Local;
    ///
    /// #[tokio::main(flavor = "current_thread")]
    /// async fn main() {
    ///     let signer = MemorySigner::generate(&mut rand::thread_rng());
    ///
    ///     let payload: Vec<u8> = vec![0, 1, 2];
    ///     let sig = AsyncSigner::<Local>::try_sign_async(&signer, payload.clone()).await;
    ///
    ///     assert!(sig.is_ok());
    ///     assert_eq!(*sig.unwrap().payload(), payload);
    /// }
    /// ```
    fn try_sign_async<'a, T: Serialize + std::fmt::Debug + Send + 'a>(
        &'a self,
        payload: T,
    ) -> K::Future<'a, Result<Signed<T>, SigningError>>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::signer::memory::MemorySigner;
    use future_form::Local;

    #[tokio::test]
    async fn test_round_trip() {
        test_utils::init_logging();
        let sk = MemorySigner::generate(&mut rand::thread_rng());
        let signed = AsyncSigner::<Local>::try_sign_async(&sk, vec![1, 2, 3])
            .await
            .unwrap();
        assert!(signed.try_verify().is_ok());
    }
}
