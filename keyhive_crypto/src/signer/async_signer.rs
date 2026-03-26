//! Async [Ed25519] signer trait.
//!
//! [Ed25519]: https://en.wikipedia.org/wiki/EdDSA#Ed25519

use crate::{signed::SigningError, verifiable::Verifiable};
use future_form::FutureForm;
#[cfg(feature = "std")]
use {crate::signed::Signed, alloc::vec::Vec, serde::Serialize};

/// Async [Ed25519] signer trait.
///
/// This is the primary signer interface for keyhive. All signing
/// operations go through this trait, regardless of whether the
/// underlying implementation is synchronous (in-memory key) or
/// genuinely asynchronous (WebCrypto, KMS).
///
/// The `F: FutureForm` parameter determines whether the returned
/// futures are `Send` (for multi-threaded runtimes) or `!Send`
/// (for Wasm / single-threaded executors). Use
/// [`Sendable`](future_form::Sendable) for the former and
/// [`Local`](future_form::Local) for the latter.
///
/// Synchronous signers (like [`MemorySigner`]) implement this for
/// _both_ `Sendable` and `Local` using [`F::ready`], so they work
/// in any context.
///
/// [Ed25519]: https://en.wikipedia.org/wiki/EdDSA#Ed25519
/// [`MemorySigner`]: crate::signer::memory::MemorySigner
pub trait AsyncSigner<F: FutureForm>: Verifiable {
    /// Sign a byte slice asynchronously.
    fn try_sign_bytes_async<'a>(
        &'a self,
        payload_bytes: &'a [u8],
    ) -> F::Future<'a, Result<ed25519_dalek::Signature, SigningError>>;
}

/// Sign a serializable payload asynchronously.
///
/// Serializes with [`bincode`], signs the resulting bytes, and
/// wraps the result in [`Signed`]. This is a free function rather
/// than a trait method because the `Sendable` form requires
/// `T: Send` while the `Local` form does not — a constraint that
/// cannot be expressed on a single trait method signature.
#[cfg(feature = "std")]
pub async fn try_sign_async<F: FutureForm, S: AsyncSigner<F>, T: Serialize + core::fmt::Debug>(
    signer: &S,
    payload: T,
) -> Result<Signed<T>, SigningError> {
    let payload_bytes: Vec<u8> = bincode::serialize(&payload)?;
    let signature = signer
        .try_sign_bytes_async(payload_bytes.as_slice())
        .await?;
    let signed = Signed::new(payload, signer.verifying_key(), signature);
    Ok(signed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signer::memory::MemorySigner;
    use future_form::Local;

    #[tokio::test]
    async fn test_round_trip() {
        let sk = MemorySigner::generate(&mut rand::thread_rng());
        let signed = try_sign_async::<Local, _, _>(&sk, alloc::vec![1, 2, 3])
            .await
            .unwrap();
        assert!(signed.try_verify().is_ok());
    }
}
