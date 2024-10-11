//! Symmetric cipher newtype.

use super::siv::Siv;
use aead::Aead;
use chacha20poly1305::{KeyInit, XChaCha20Poly1305};
use serde::{Deserialize, Serialize};
use x25519_dalek::SharedSecret;

/// Newtype wrapper around ChaCha20 key that's serializable.
///
/// # Example
///
/// ```
/// # use beehive_core::crypto::{siv::Siv, symmetric_key::SymmetricKey};
/// # use beehive_core::principal::document::Document;
/// let plaintext = b"hello world";
/// let doc = Document::new(vec![]);
///
/// let key = SymmetricKey::generate();
/// let nonce = Siv::new(&key, plaintext, &doc);
///
/// let ciphertext = key.encrypt(nonce, plaintext).unwrap();
/// let decrypted = key.decrypt(nonce, &ciphertext).unwrap();
///
/// assert_eq!(decrypted, plaintext);
/// ```
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct SymmetricKey(pub [u8; 32]);

impl SymmetricKey {
    /// Get the key as a byte slice.
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    /// Generate a new random symmetric key.
    pub fn generate() -> Self {
        let key = rand::random();
        Self(key)
    }

    /// Convert into an [`XChaCha20Poly1305`] key.
    pub fn to_xchacha(&self) -> XChaCha20Poly1305 {
        XChaCha20Poly1305::new(&self.0.into())
    }

    /// Encrypt data with the [`SymmetricKey`].
    pub fn encrypt(&self, nonce: Siv, data: &[u8]) -> Result<Vec<u8>, chacha20poly1305::Error> {
        self.to_xchacha().encrypt(&nonce.as_xnonce(), data)
    }

    /// Decrypt data with the [`SymmetricKey`].
    pub fn decrypt(&self, nonce: Siv, data: &[u8]) -> Result<Vec<u8>, chacha20poly1305::Error> {
        self.to_xchacha().decrypt(&nonce.as_xnonce(), data)
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

impl std::fmt::Debug for SymmetricKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        "<SymmetricKey>".fmt(f)
    }
}
