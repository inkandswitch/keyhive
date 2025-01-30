//! Nonce-misuse resistant initialization vector.

use super::{domain_separator::SEPARATOR, symmetric_key::SymmetricKey};
use crate::principal::document::id::DocumentId;
use serde::{Deserialize, Serialize};
use std::io::Read;

/// Nonce-misuse resistant initialization vector.
///
/// Note that ChaCha having a very different foundation, this is not the well-known SIV mode from AES.
///
/// XChaCha uses a 24-byte nonce which is considered safe to use when
/// a nonce-collions could result during random generation.
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
    pub fn new(
        key: &SymmetricKey,
        plaintext: &[u8],
        doc_id: DocumentId,
    ) -> Result<Self, std::io::Error> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(SEPARATOR);
        hasher.update(doc_id.as_slice());
        hasher.update(key.as_slice());
        hasher.update(plaintext);

        let mut buf = [0; 24];
        hasher.finalize_xof().read_exact(&mut buf)?;

        Ok(Siv(buf))
    }

    /// Convert to a [`chacha20poly1305::XNonce`].
    pub fn as_xnonce(&self) -> &chacha20poly1305::XNonce {
        chacha20poly1305::XNonce::from_slice(&self.0)
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
        *Self::from_slice(&siv.0)
    }
}

impl From<chacha20poly1305::XNonce> for Siv {
    fn from(nonce: chacha20poly1305::XNonce) -> Self {
        Siv(nonce.into())
    }
}
