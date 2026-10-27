//! Async [Ed25519] signer trait.
//!
//! [Ed25519]: https://en.wikipedia.org/wiki/EdDSA#Ed25519

use crate::{signer::SigningError, verifiable::Verifiable};
use future_form::FutureForm;

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
/// _both_ `Sendable` and `Local` using [`F::ready`](FutureForm::ready), so they work
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
