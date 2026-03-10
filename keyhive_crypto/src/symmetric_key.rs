//! Symmetric cipher newtype.

use super::{domain_separator::SEPARATOR, separable::Separable, siv::Siv};
use alloc::vec::Vec;
use chacha20poly1305::{AeadInPlace, KeyInit, XChaCha20Poly1305};
use serde::{Deserialize, Serialize};
use tracing::instrument;
use x25519_dalek::SharedSecret;

/// Newtype wrapper around ChaCha20 key that's serializable.
///
/// # Example
///
/// ```
/// # use keyhive_crypto::{siv::Siv, symmetric_key::SymmetricKey};
/// #
/// let plaintext = b"hello world";
/// let mut csprng = rand::rngs::OsRng;
/// let doc_id = b"some-document-id";
///
/// let key = SymmetricKey::generate(&mut csprng);
/// let nonce = Siv::new(&key, plaintext, doc_id);
///
/// let mut roundtrip_buf = plaintext.to_vec();
/// key.try_encrypt(nonce, &mut roundtrip_buf).unwrap();
/// key.try_decrypt(nonce, &mut roundtrip_buf).unwrap();
///
/// assert_eq!(roundtrip_buf.as_slice(), plaintext);
/// ```
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct SymmetricKey([u8; 32]);

impl SymmetricKey {
    /// Get the key as a byte slice.
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    /// Generate a new random symmetric key.
    pub fn generate<R: rand::CryptoRng + rand::RngCore>(csprng: &mut R) -> Self {
        let mut key = [0u8; 32];
        csprng.fill_bytes(&mut key);
        Self(key)
    }

    /// Convert into an [`XChaCha20Poly1305`] key.
    pub fn to_xchacha(&self) -> XChaCha20Poly1305 {
        XChaCha20Poly1305::new(&self.0.into())
    }

    /// Encrypt data with the [`SymmetricKey`].
    #[instrument(skip(self))]
    pub fn try_encrypt(
        &self,
        nonce: Siv,
        data: &mut Vec<u8>,
    ) -> Result<(), chacha20poly1305::Error> {
        self.to_xchacha()
            .encrypt_in_place(nonce.as_xnonce(), SEPARATOR, data)
    }

    /// Decrypt data with the [`SymmetricKey`].
    #[instrument(skip(self))]
    pub fn try_decrypt(
        &self,
        nonce: Siv,
        data: &mut Vec<u8>,
    ) -> Result<(), chacha20poly1305::Error> {
        self.to_xchacha()
            .decrypt_in_place(nonce.as_xnonce(), SEPARATOR, data)
    }
}

impl From<[u8; 32]> for SymmetricKey {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl From<SymmetricKey> for [u8; 32] {
    fn from(key: SymmetricKey) -> Self {
        key.0
    }
}

impl From<SymmetricKey> for XChaCha20Poly1305 {
    fn from(key: SymmetricKey) -> Self {
        key.to_xchacha()
    }
}

impl From<SharedSecret> for SymmetricKey {
    fn from(secret: SharedSecret) -> Self {
        (*secret.as_bytes()).into()
    }
}

impl core::fmt::Debug for SymmetricKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        "<SymmetricKey>".fmt(f)
    }
}

impl Separable for SymmetricKey {
    fn directly_from_32_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}
