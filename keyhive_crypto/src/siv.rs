//! Nonce-misuse resistant initialization vector.

use super::{domain_separator::SEPARATOR, symmetric_key::SymmetricKey};
use alloc::vec::Vec;
use keyhive_codec::{
    error::DecodeError,
    traits::{decode_exact, Decode, Encode, StreamDecode},
};
use serde::{Deserialize, Serialize};

/// Nonce-misuse resistant initialization vector.
///
/// Note that ChaCha having a very different foundation, this is not the well-known SIV mode from AES.
///
/// XChaCha uses a 24-byte nonce which is considered safe to use when
/// a nonce-collisions could result during random generation.
/// However, this doesn't commit the key, and is thus left open to [Invisible Salamanders]
/// and there are some cases where the key could be phished.
///
/// > Using random nonces runs the risk of repeating them unless the nonce size is particularly large (e.g. 192-bit extended nonces used by the XChaCha20Poly1305 and XSalsa20Poly1305 constructions.
/// >
/// > — [`chacha20poly1305 v0.10` Rust Crate docs][chacha20-docs]
///
/// The [`Siv`] here deterministically generates a nonce from the key, content, document ID, and library.
/// No novel cryptographic techniques are used; this is "merely" a way to ensure a unique key per ciphertext.
/// Malliciously constructing such a nonce would require prior knowledge of the key and content, at which point
/// an attacker doesn't need to forge a nonce. Additionally, the nonce can be reconstructed deterministically
/// to check the integrity of the plaintext and key.
///
/// [Invisible Salamanders]: https://eprint.iacr.org/2019/016.pdf
/// [chacha20-docs]: https://docs.rs/chacha20poly1305/0.10.1/chacha20poly1305/trait.AeadCore.html#method.generate_nonce
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[cfg_attr(any(test, feature = "arbitrary"), derive(arbitrary::Arbitrary))]
pub struct Siv([u8; 24]);

impl Siv {
    pub fn new(key: &SymmetricKey, plaintext: &[u8], doc_id: &[u8]) -> Siv {
        let mut hasher = blake3::Hasher::new();
        hasher.update(SEPARATOR);
        hasher.update(doc_id);
        hasher.update(key.as_slice());
        hasher.update(plaintext);

        let mut buf = [0; 24];
        hasher.finalize_xof().fill(&mut buf);

        Siv(buf)
    }

    /// Convert to a [`chacha20poly1305::XNonce`].
    pub fn as_xnonce(&self) -> &chacha20poly1305::XNonce {
        (&self.0).into()
    }

    pub fn as_bytes(&self) -> &[u8; 24] {
        &self.0
    }
}

impl From<Siv> for [u8; 24] {
    fn from(siv: Siv) -> Self {
        siv.0
    }
}

impl From<[u8; 24]> for Siv {
    fn from(arr: [u8; 24]) -> Self {
        Siv(arr)
    }
}

impl From<Siv> for chacha20poly1305::XNonce {
    fn from(siv: Siv) -> Self {
        Self::from(siv.0)
    }
}

impl From<chacha20poly1305::XNonce> for Siv {
    fn from(nonce: chacha20poly1305::XNonce) -> Self {
        Siv(nonce.into())
    }
}

/// Whether two nonces are equal, comparing every byte whatever the first
/// difference, so the time taken does not tell where they differ. For the
/// check after decryption that a nonce is the synthetic nonce of what it
/// decrypted to.
pub fn nonces_match(expected: &[u8; 24], received: &[u8; 24]) -> bool {
    expected
        .iter()
        .zip(received)
        .fold(0u8, |differ, (a, b)| differ | (a ^ b))
        == 0
}

/// A synthetic nonce encodes as its 24 bytes: canonical and prefix-free.
impl Encode for Siv {
    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.0);
    }
}

impl Decode for Siv {
    fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        decode_exact(bytes)
    }
}

impl StreamDecode for Siv {
    fn decode_next(bytes: &[u8]) -> Result<(Self, &[u8]), DecodeError> {
        let (raw, rest) = <[u8; 24]>::decode_next(bytes)?;
        Ok((Siv(raw), rest))
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;

    #[test]
    fn codec_laws() {
        keyhive_codec::laws::round_trip::<Siv>();
        keyhive_codec::laws::canonical_near::<Siv>();
        keyhive_codec::laws::stream::<Siv>();
    }

    #[test]
    fn nonces_match_only_when_every_byte_does() {
        let nonce = [7u8; 24];
        assert!(nonces_match(&nonce, &nonce));

        for at in [0, 11, 23] {
            let mut other = nonce;
            other[at] ^= 0x80;
            assert!(!nonces_match(&nonce, &other), "byte {at} differs");
        }

        // Two bytes that differ by the same bit: an XOR of the differences
        // would cancel, so every difference has to count.
        let mut twice = nonce;
        twice[3] ^= 1;
        twice[17] ^= 1;
        assert!(!nonces_match(&nonce, &twice));
    }
}
