//! Async [Ed25519] signer trait.
//!
//! [Ed25519]: https://en.wikipedia.org/wiki/EdDSA#Ed25519

use crate::crypto::{
    signed::{Signed, SigningError},
    verifiable::Verifiable,
};
use future_form::{FutureForm, Local, Sendable};
use serde::Serialize;

/// Async [Ed25519] signer trait (generic version, no `try_sign_async`).
///
/// For signing payloads, use [`AsyncSignerSend`] (multi-threaded) or 
/// [`AsyncSignerLocal`] (single-threaded).
///
/// [Ed25519]: https://en.wikipedia.org/wiki/EdDSA#Ed25519
pub trait AsyncSigner<K: FutureForm + ?Sized>: Verifiable {
    /// Sign a byte slice asynchronously.
    fn try_sign_bytes_async<'a>(
        &'a self,
        payload_bytes: &'a [u8],
    ) -> K::Future<'a, Result<ed25519_dalek::Signature, SigningError>>;
}

/// Async signer for `Sendable` (multi-threaded) contexts.
///
/// This requires `T: Send` on payloads for `try_sign_async`.
pub trait AsyncSignerSend: AsyncSigner<Sendable> {
    /// Sign a serializable payload asynchronously.
    fn try_sign_async<'a, T: Serialize + std::fmt::Debug + Send + 'a>(
        &'a self,
        payload: T,
    ) -> <Sendable as FutureForm>::Future<'a, Result<Signed<T>, SigningError>>;
}

/// Async signer for `Local` (single-threaded) contexts.
///
/// This does NOT require `T: Send` on payloads, making it suitable for Wasm.
pub trait AsyncSignerLocal: AsyncSigner<Local> {
    /// Sign a serializable payload asynchronously (no `Send` required).
    fn try_sign_async<'a, T: Serialize + std::fmt::Debug + 'a>(
        &'a self,
        payload: T,
    ) -> <Local as FutureForm>::Future<'a, Result<Signed<T>, SigningError>>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::signer::memory::MemorySigner;

    #[tokio::test]
    async fn test_round_trip() {
        test_utils::init_logging();
        let sk = MemorySigner::generate(&mut rand::thread_rng());
        let signed = AsyncSignerLocal::try_sign_async(&sk, vec![1, 2, 3])
            .await
            .unwrap();
        assert!(signed.try_verify().is_ok());
    }
}
