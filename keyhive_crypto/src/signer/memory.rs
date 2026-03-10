//! In-memory signer.

use super::sync_signer::SyncSigner;
use crate::crypto::{signed::SigningError, verifiable::Verifiable};
use dupe::Dupe;
use ed25519_dalek::Signer;
use std::hash::Hash;
use tracing::instrument;

/// An in-memory signer.
///
/// This signer is backed by an in-memory Ed25519 signing key.
///
/// <div class="warning">
///
/// While very convenient, an in-memory signing key can be leaked.
/// It is recommended to use a non-extractable key (and thus [`AsyncSigner`])
/// instead.
///
/// </div>
///
/// [`AsyncSigner`]: crate::crypto::signer::async_signer::AsyncSigner
#[derive(Debug, Clone)]
pub struct MemorySigner(
    /// Raw underlying Ed25519 signing key.
    pub ed25519_dalek::SigningKey,
);

impl MemorySigner {
    /// Randomly generates a new in-memory signer.
    ///
    /// # Arguments
    ///
    /// * `csprng` - A cryptographically secure random number generator.
    ///
    /// # Examples
    ///
    /// ```
    /// # use keyhive_core::crypto::{
    /// #    signer::memory::MemorySigner,
    /// #    verifiable::Verifiable
    /// # };
    /// let signer = MemorySigner::generate(&mut rand::rngs::OsRng);
    /// assert_eq!(signer.0.to_bytes().len(), 32);
    /// assert_eq!(signer.verifying_key().to_bytes().len(), 32);
    /// ```
    pub fn generate<R: rand::CryptoRng + rand::RngCore>(csprng: &mut R) -> Self {
        Self(ed25519_dalek::SigningKey::generate(csprng))
    }
}

impl SyncSigner for MemorySigner {
    fn try_sign_bytes_sync(
        &self,
        payload_bytes: &[u8],
    ) -> Result<ed25519_dalek::Signature, SigningError> {
        self.0
            .try_sign(payload_bytes)
            .map_err(SigningError::SigningFailed)
    }
}

impl Hash for MemorySigner {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.verifying_key().hash(state);
    }
}

impl Dupe for MemorySigner {
    fn dupe(&self) -> Self {
        Self(self.0.clone())
    }
}

impl PartialEq for MemorySigner {
    fn eq(&self, other: &Self) -> bool {
        self.verifying_key() == other.verifying_key()
    }
}

impl Eq for MemorySigner {}

impl From<ed25519_dalek::SigningKey> for MemorySigner {
    fn from(key: ed25519_dalek::SigningKey) -> Self {
        Self(key)
    }
}

impl ed25519_dalek::Signer<ed25519_dalek::Signature> for MemorySigner {
    #[instrument(skip(self))]
    fn try_sign(
        &self,
        msg: &[u8],
    ) -> Result<ed25519_dalek::Signature, ed25519_dalek::SignatureError> {
        self.0.try_sign(msg)
    }
}

impl Verifiable for MemorySigner {
    fn verifying_key(&self) -> ed25519_dalek::VerifyingKey {
        self.0.verifying_key()
    }
}
