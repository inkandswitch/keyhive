//! Symmetric cipher newtype.

use super::{
    context::Context,
    secret::{boxed_from_slice, constant_time_eq},
    siv::{nonces_match, synthetic_nonce},
};
use alloc::{boxed::Box, vec::Vec};
use chacha20poly1305::{AeadInPlace, KeyInit, XChaCha20Poly1305, XNonce};
use tracing::instrument;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

const NONCE_LEN: usize = 24;

/// Newtype wrapper around ChaCha20 key that's serializable.
///
/// # Example
///
/// ```
/// # use keyhive_crypto::symmetric_key::SymmetricKey;
/// #
/// let key = SymmetricKey::generate(&mut rand::rngs::OsRng);
/// let sealed = key.try_seal(b"hello world", b"some-document-id").expect("seals");
///
/// let opened = key.try_open(&sealed, b"some-document-id").expect("opens");
/// assert_eq!(opened.as_slice(), b"hello world");
/// assert!(key.try_open(&sealed, b"another-document").is_err());
/// ```
///
/// Wiped when dropped. Not `Copy`: a copy needs an explicit `clone`, and a
/// clone is wiped too. The bytes are in their own allocation, so moving a
/// key, or a map of keys growing, does not copy them. Equality takes constant
/// time.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SymmetricKey(Box<[u8; 32]>);

impl SymmetricKey {
    /// The key's bytes, borrowed: a copy of them would not be wiped.
    pub fn as_slice(&self) -> &[u8] {
        self.0.as_slice()
    }

    /// Copy a key out of `bytes` with no copy on the way. Returns `None`
    /// unless `bytes` is 32 bytes long.
    pub fn try_from_slice(bytes: &[u8]) -> Option<Self> {
        boxed_from_slice(bytes).map(Self)
    }

    /// Generate a new random symmetric key.
    pub fn generate<R: rand::CryptoRng + rand::RngCore>(csprng: &mut R) -> Self {
        let mut key = Box::new([0; 32]);
        csprng.fill_bytes(key.as_mut_slice());
        Self(key)
    }

    /// AEAD-seal `plaintext`, returning a self-contained `nonce ‖ ciphertext ‖ tag`.
    ///
    /// `associated_data` is authenticated: it is the AEAD's associated data,
    /// and feeds the synthetic nonce. [`Self::try_open`] needs the same bytes.
    /// The cipher and the nonce each use their own subkey of this key:
    ///
    /// ```text
    /// enc_key   = derive_key(SEAL_ENCRYPTION_KEY, key)
    /// nonce_key = derive_key(SEAL_NONCE_KEY, key)
    /// nonce     = BLAKE3_keyed(nonce_key, aad_len:u64 ‖ aad ‖ plaintext)[0..24]
    /// ```
    #[instrument(skip_all)]
    pub fn try_seal(
        &self,
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> Result<Vec<u8>, chacha20poly1305::Error> {
        let keys = SealKeys::new(self);
        let nonce = keys.nonce(associated_data, plaintext);
        let mut buf = plaintext.to_vec();
        keys.cipher
            .encrypt_in_place(&XNonce::from(nonce), associated_data, &mut buf)?;
        let mut out = nonce.to_vec();
        out.extend_from_slice(&buf);
        Ok(out)
    }

    /// Inverse of [`Self::try_seal`]: reads a `nonce(24) || ciphertext` blob
    /// sealed with the same `associated_data`.
    ///
    /// Also refuses a blob whose nonce is not the synthetic nonce of what it
    /// decrypts to, which commits the blob to this key. The plaintext is wiped
    /// when dropped, as it is when the blob is refused.
    #[instrument(skip_all)]
    pub fn try_open(
        &self,
        blob: &[u8],
        associated_data: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, chacha20poly1305::Error> {
        let Some((nonce, ciphertext)) = blob.split_first_chunk::<NONCE_LEN>() else {
            return Err(chacha20poly1305::Error);
        };
        let keys = SealKeys::new(self);
        let mut buf = Zeroizing::new(ciphertext.to_vec());
        keys.cipher
            .decrypt_in_place(&XNonce::from(*nonce), associated_data, &mut *buf)?;
        if !nonces_match(&keys.nonce(associated_data, &buf), nonce) {
            return Err(chacha20poly1305::Error);
        }
        Ok(buf)
    }
}

/// The subkeys a seal is made with.
struct SealKeys {
    cipher: XChaCha20Poly1305,
    nonce_key: Zeroizing<[u8; 32]>,
}

impl SealKeys {
    fn new(key: &SymmetricKey) -> Self {
        // The cipher keeps, and wipes, its own copy of the key.
        let enc_key = Zeroizing::new(Context::SEAL_ENCRYPTION_KEY.derive_key(key.as_slice()));
        SealKeys {
            cipher: XChaCha20Poly1305::new(enc_key.as_ref().into()),
            nonce_key: Zeroizing::new(Context::SEAL_NONCE_KEY.derive_key(key.as_slice())),
        }
    }

    /// Over `aad_len:u64 ‖ aad ‖ plaintext`: the length prefix keeps where the
    /// associated data ends from moving into the plaintext.
    fn nonce(&self, aad: &[u8], plaintext: &[u8]) -> [u8; NONCE_LEN] {
        let aad_len = u64::try_from(aad.len()).expect("a slice's length fits in a u64");
        synthetic_nonce(&self.nonce_key, &[&aad_len.to_be_bytes(), aad, plaintext])
    }
}

impl From<[u8; 32]> for SymmetricKey {
    fn from(bytes: [u8; 32]) -> Self {
        Self(Box::new(bytes))
    }
}

/// Copies into a new allocation, so the copy is never on the stack.
impl Clone for SymmetricKey {
    fn clone(&self) -> Self {
        Self::try_from_slice(self.as_slice()).expect("a key is 32 bytes")
    }
}

impl PartialEq for SymmetricKey {
    fn eq(&self, other: &Self) -> bool {
        constant_time_eq(&self.0, &other.0)
    }
}

impl Eq for SymmetricKey {}

impl core::fmt::Debug for SymmetricKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        "<SymmetricKey>".fmt(f)
    }
}

// Fails to compile unless the key wipes itself when dropped and has a
// destructor, which a `Copy` type cannot have.
const _: () = assert!(core::mem::needs_drop::<SymmetricKey>());
const _: fn() = || {
    fn wiped_on_drop<T: ZeroizeOnDrop>() {}
    wiped_on_drop::<SymmetricKey>();
};

#[cfg(test)]
mod tests {
    use super::{SealKeys, SymmetricKey, NONCE_LEN};
    use rand::rngs::OsRng;

    const TAG_LEN: usize = 16;

    #[test]
    fn try_seal_open_roundtrips() {
        let key = SymmetricKey::generate(&mut OsRng);
        let plaintext = b"hello world";
        let blob = key.try_seal(plaintext, b"doc-id").unwrap();
        assert_eq!(
            key.try_open(&blob, b"doc-id").unwrap().as_slice(),
            plaintext
        );
    }

    #[test]
    fn try_seal_open_roundtrips_empty_plaintext() {
        let key = SymmetricKey::generate(&mut OsRng);
        let blob = key.try_seal(b"", b"doc-id").unwrap();
        // Nonce plus the Poly1305 tag, with no payload in between.
        assert_eq!(blob.len(), NONCE_LEN + TAG_LEN);
        assert!(key.try_open(&blob, b"doc-id").unwrap().is_empty());
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
    fn a_blob_opens_only_with_the_associated_data_it_was_sealed_with() {
        let key = SymmetricKey::generate(&mut OsRng);
        let plaintext = b"hello world";
        let blob_a = key.try_seal(plaintext, b"context-a").unwrap();
        let blob_b = key.try_seal(plaintext, b"context-b").unwrap();
        assert_ne!(blob_a, blob_b);
        assert_eq!(
            key.try_open(&blob_a, b"context-a").unwrap().as_slice(),
            plaintext
        );
        assert!(key.try_open(&blob_a, b"context-b").is_err());
        assert!(key.try_open(&blob_b, b"context-a").is_err());
    }

    /// A blob that authenticates but whose nonce is not its synthetic nonce
    /// is refused: the check is what commits a blob to one key.
    #[test]
    fn a_blob_whose_nonce_is_not_synthetic_is_refused() {
        use chacha20poly1305::AeadInPlace;

        let key = SymmetricKey::generate(&mut OsRng);
        let plaintext = b"hello world";
        let nonce = [7u8; NONCE_LEN];
        let mut buf = plaintext.to_vec();
        SealKeys::new(&key)
            .cipher
            .encrypt_in_place((&nonce).into(), b"doc-id", &mut buf)
            .unwrap();
        let blob = [&nonce[..], &buf].concat();
        assert!(key.try_open(&blob, b"doc-id").is_err());
    }

    /// Pins the seal. The nonce, its first 24 bytes, is checked with `b3sum`:
    /// the nonce key is `b3sum --derive-key` under `SEAL_NONCE_KEY` over the
    /// key `[1; 32]`, and the nonce `b3sum --keyed --length 24` under it over
    /// `3:u64 ‖ "aad" ‖ "keyhive"`.
    #[test]
    fn known_answer() {
        let blob = SymmetricKey::from([1; 32])
            .try_seal(b"keyhive", b"aad")
            .expect("seals");
        assert_eq!(
            crate::hex::bytes_to_hex_string(&blob[..NONCE_LEN]),
            "0x705d5af07b5d86eb860f8ed48f39ba6269e73eb598aa0972"
        );
        assert_eq!(crate::hex::bytes_to_hex_string(&blob), "0x705d5af07b5d86eb860f8ed48f39ba6269e73eb598aa0972891bd57da405d87af8b12ab1bfbc7d5fcff41f430ed387");
    }

    #[test]
    fn try_open_with_wrong_key_fails() {
        let key = SymmetricKey::generate(&mut OsRng);
        let other = SymmetricKey::generate(&mut OsRng);
        let blob = key.try_seal(b"hello world", b"doc-id").unwrap();
        assert!(other.try_open(&blob, b"doc-id").is_err());
    }

    #[test]
    fn try_open_with_tampered_ciphertext_fails() {
        let key = SymmetricKey::generate(&mut OsRng);
        let mut blob = key.try_seal(b"hello world", b"doc-id").unwrap();
        // Flip a bit in the ciphertext (past the 24-byte nonce).
        let last = blob.len() - 1;
        blob[last] ^= 0x01;
        assert!(key.try_open(&blob, b"doc-id").is_err());
    }

    #[test]
    fn try_open_with_tampered_nonce_fails() {
        let key = SymmetricKey::generate(&mut OsRng);
        let mut blob = key.try_seal(b"hello world", b"doc-id").unwrap();
        blob[0] ^= 0x01;
        assert!(key.try_open(&blob, b"doc-id").is_err());
    }

    #[test]
    fn try_open_rejects_blob_shorter_than_nonce() {
        let key = SymmetricKey::generate(&mut OsRng);
        assert!(key.try_open(&[], b"doc-id").is_err());
        assert!(key.try_open(&[0u8; NONCE_LEN - 1], b"doc-id").is_err());
    }
}
