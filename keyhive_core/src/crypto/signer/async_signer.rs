//! Async [Ed25519] signer trait.
//!
//! [Ed25519]: https://en.wikipedia.org/wiki/EdDSA#Ed25519

use crate::crypto::{
    signed::{Signed, SigningError},
    verifiable::Verifiable,
};
use future_form::FutureForm;
use serde::Serialize;
use std::fmt::Debug;

/// Async [Ed25519] signer trait, parameterized by [`FutureForm`] and payload type.
///
/// This is especially helpful for signing with keys that are externally managed,
/// such as via the WebCrypto API, a hardware wallet, or a remote signing service / KMS.
///
/// The `K` parameter determines whether futures must be `Send` ([`Sendable`]) or not ([`Local`]).
/// The `T` parameter is the payload type - impls can add bounds (e.g., `Send` for [`Sendable`]).
///
/// [Ed25519]: https://en.wikipedia.org/wiki/EdDSA#Ed25519
/// [`Sendable`]: future_form::Sendable
/// [`Local`]: future_form::Local
pub trait AsyncSigner<K: FutureForm, T: Serialize + Debug>: Verifiable {
    /// Sign a byte slice asynchronously.
    fn try_sign_bytes_async<'a>(
        &'a self,
        payload_bytes: &'a [u8],
    ) -> K::Future<'a, Result<ed25519_dalek::Signature, SigningError>>;

    /// Sign a serializable payload asynchronously.
    ///
    /// This helper automatically serializes using [`bincode`], signs the resulting bytes,
    /// and wraps the result in [`Signed`].
    fn try_sign_async<'a>(&'a self, payload: T) -> K::Future<'a, Result<Signed<T>, SigningError>>
    where
        T: 'a;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::signer::memory::MemorySigner;
    use future_form::Sendable;

    #[tokio::test]
    async fn test_round_trip() {
        test_utils::init_logging();
        let sk = MemorySigner::generate(&mut rand::thread_rng());
        let signed = AsyncSigner::<Sendable, _>::try_sign_async(&sk, vec![1u8, 2, 3])
            .await
            .unwrap();
        assert!(signed.try_verify().is_ok());
    }
}
