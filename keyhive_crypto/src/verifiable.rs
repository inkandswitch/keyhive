//! Traits for types that have verifying keys.

/// Trait for types that have a verifying key.
///
/// This has multiple uses, including:
/// - Retrieving a verifying key from a [`ed25519_dalek::SigningKey`].
/// - Getting the verifying key for a principal.
/// - Extracting the issuer's key from a [`Verified`][crate::verified::Verified] statement.
pub trait Verifiable {
    /// Get the [`ed25519_dalek::VerifyingKey`] for [`Self`].
    ///
    /// # Examples
    ///
    /// ```
    /// use keyhive_crypto::{
    ///     signer::memory::MemorySigner,
    ///     verifiable::Verifiable
    /// };
    ///
    /// let mut csprng = rand::rngs::OsRng;
    ///
    /// // Ed25519 signing key
    /// let sk = ed25519_dalek::SigningKey::generate(&mut csprng);
    /// assert_eq!(sk.verifying_key().to_bytes().len(), 32);
    ///
    /// // MemorySigner
    /// let signer = MemorySigner::generate(&mut csprng);
    /// assert_eq!(signer.verifying_key().to_bytes().len(), 32);
    ///
    /// // A statement it signed
    /// let signed = keyhive_crypto::verified::Verified::sign_sync(
    ///     &keyhive_crypto::bytes::Bytes::from(vec![1u8, 2, 3]),
    ///     &signer,
    /// )
    /// .unwrap();
    /// assert_eq!(signed.verifying_key(), signer.verifying_key());
    /// ```
    fn verifying_key(&self) -> ed25519_dalek::VerifyingKey;
}

impl Verifiable for ed25519_dalek::SigningKey {
    fn verifying_key(&self) -> ed25519_dalek::VerifyingKey {
        self.into()
    }
}
