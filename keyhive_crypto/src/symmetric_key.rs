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

    /// AEAD-seal `plaintext`, returning a self-contained `nonce(24) || ciphertext`.
    #[instrument(skip(self))]
    pub fn try_seal(
        &self,
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> Result<Vec<u8>, chacha20poly1305::Error> {
        let nonce = Siv::new(self, plaintext, associated_data);
        let mut buf = plaintext.to_vec();
        self.try_encrypt(nonce, &mut buf)?;
        let mut out = Vec::with_capacity(nonce.as_bytes().len() + buf.len());
        out.extend_from_slice(nonce.as_bytes());
        out.extend_from_slice(&buf);
        Ok(out)
    }

    /// Inverse of [`Self::try_seal`]. Reads a `nonce(24) || ciphertext` blob.
    #[instrument(skip(self))]
    pub fn try_open(&self, blob: &[u8]) -> Result<Vec<u8>, chacha20poly1305::Error> {
        let Some((nonce_bytes, ciphertext)) = blob.split_first_chunk::<24>() else {
            return Err(chacha20poly1305::Error);
        };
        let nonce = Siv::from(*nonce_bytes);
        let mut buf = ciphertext.to_vec();
        self.try_decrypt(nonce, &mut buf)?;
        Ok(buf)
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

#[cfg(test)]
mod tests {
    use super::SymmetricKey;
    use rand::rngs::OsRng;

    const NONCE_LEN: usize = 24;
    const TAG_LEN: usize = 16;

    #[test]
    fn try_seal_open_roundtrips() {
        let key = SymmetricKey::generate(&mut OsRng);
        let plaintext = b"hello world";
        let blob = key.try_seal(plaintext, b"doc-id").unwrap();
        assert_eq!(key.try_open(&blob).unwrap().as_slice(), plaintext);
    }

    #[test]
    fn try_seal_open_roundtrips_empty_plaintext() {
        let key = SymmetricKey::generate(&mut OsRng);
        let blob = key.try_seal(b"", b"doc-id").unwrap();
        // Nonce plus the Poly1305 tag, with no payload in between.
        assert_eq!(blob.len(), NONCE_LEN + TAG_LEN);
        assert!(key.try_open(&blob).unwrap().is_empty());
    }

    #[test]
    fn try_seal_output_is_nonce_plus_ciphertext_plus_tag() {
        let key = SymmetricKey::generate(&mut OsRng);
        let plaintext = b"some bytes to seal";
        let blob = key.try_seal(plaintext, b"doc-id").unwrap();
        assert_eq!(blob.len(), NONCE_LEN + plaintext.len() + TAG_LEN);
    }

    #[test]
    fn try_seal_is_deterministic_for_same_inputs() {
        // The SIV nonce is derived from key, plaintext, and associated data, so
        // identical inputs produce identical output.
        let key = SymmetricKey::generate(&mut OsRng);
        let a = key.try_seal(b"hello world", b"doc-id").unwrap();
        let b = key.try_seal(b"hello world", b"doc-id").unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn associated_data_changes_ciphertext_but_open_ignores_it() {
        // The same plaintext under different associated data yields distinct
        // ciphertext, yet `try_open` recovers it without knowing the data
        // because the nonce is carried in the blob.
        let key = SymmetricKey::generate(&mut OsRng);
        let plaintext = b"hello world";
        let blob_a = key.try_seal(plaintext, b"context-a").unwrap();
        let blob_b = key.try_seal(plaintext, b"context-b").unwrap();
        assert_ne!(blob_a, blob_b);
        assert_eq!(key.try_open(&blob_a).unwrap().as_slice(), plaintext);
        assert_eq!(key.try_open(&blob_b).unwrap().as_slice(), plaintext);
    }

    #[test]
    fn try_open_with_wrong_key_fails() {
        let key = SymmetricKey::generate(&mut OsRng);
        let other = SymmetricKey::generate(&mut OsRng);
        let blob = key.try_seal(b"hello world", b"doc-id").unwrap();
        assert!(other.try_open(&blob).is_err());
    }

    #[test]
    fn try_open_with_tampered_ciphertext_fails() {
        let key = SymmetricKey::generate(&mut OsRng);
        let mut blob = key.try_seal(b"hello world", b"doc-id").unwrap();
        // Flip a bit in the ciphertext (past the 24-byte nonce).
        let last = blob.len() - 1;
        blob[last] ^= 0x01;
        assert!(key.try_open(&blob).is_err());
    }

    #[test]
    fn try_open_with_tampered_nonce_fails() {
        let key = SymmetricKey::generate(&mut OsRng);
        let mut blob = key.try_seal(b"hello world", b"doc-id").unwrap();
        blob[0] ^= 0x01;
        assert!(key.try_open(&blob).is_err());
    }

    #[test]
    fn try_open_rejects_blob_shorter_than_nonce() {
        let key = SymmetricKey::generate(&mut OsRng);
        assert!(key.try_open(&[]).is_err());
        assert!(key.try_open(&[0u8; NONCE_LEN - 1]).is_err());
    }
}
