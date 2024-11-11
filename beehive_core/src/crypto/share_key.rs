//! Newtype around [ECDH] "sharing" public keys.
//!
//! [ECDH]: https://wikipedia.org/wiki/Elliptic-curve_Diffie%E2%80%93Hellman

use super::{domain_separator::SEPARATOR_STR, symmetric_key::SymmetricKey};
use serde::{Deserialize, Serialize};

/// Newtype around [x25519_dalek::PublicKey].
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ShareKey(pub x25519_dalek::PublicKey);

impl ShareKey {
    #[cfg(feature = "test_utils")]
    pub fn generate() -> Self {
        Self(x25519_dalek::PublicKey::from(
            &x25519_dalek::EphemeralSecret::random(),
        ))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }
}

impl PartialOrd for ShareKey {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ShareKey {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.as_bytes().cmp(other.0.as_bytes())
    }
}

impl From<ShareKey> for x25519_dalek::PublicKey {
    fn from(key: ShareKey) -> Self {
        key.0
    }
}

impl From<x25519_dalek::PublicKey> for ShareKey {
    fn from(key: x25519_dalek::PublicKey) -> Self {
        ShareKey(key)
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
// FIXME: Made pub to get tests passing. Need to revisit.
pub struct ShareSecretKey(pub [u8; 32]);

impl ShareSecretKey {
    pub fn generate() -> Self {
        x25519_dalek::StaticSecret::random().into()
    }

    pub fn derive_from_bytes(bytes: [u8; 32]) -> Self {
        Self(blake3::derive_key(SEPARATOR_STR, bytes.as_slice()))
    }

    pub fn share_key(&self) -> ShareKey {
        ShareKey(x25519_dalek::PublicKey::from(
            &x25519_dalek::StaticSecret::from(*self),
        ))
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    pub fn derive_shared_secret(&self, other: &ShareKey) -> x25519_dalek::SharedSecret {
        x25519_dalek::StaticSecret::from(*self).diffie_hellman(&other.0)
    }

    pub fn derive_new_secret_key(&self, other: &ShareKey) -> Self {
        let bytes: [u8; 32] = x25519_dalek::StaticSecret::from(*self)
            .diffie_hellman(&other.0)
            .to_bytes();

        Self::derive_from_bytes(bytes)
    }

    pub fn derive_symmetric_key(&self, other: &ShareKey) -> SymmetricKey {
        x25519_dalek::StaticSecret::from(*self)
            .diffie_hellman(&other.0)
            .into()
    }

    pub fn ratchet_forward(&self) -> Self {
        let bytes = self.to_bytes();
        Self::derive_from_bytes(bytes)
    }

    pub fn ratchet_n_forward(&self, n: usize) -> Self {
        (0..n).fold(*self, |acc, _| acc.ratchet_forward())
    }
}

impl From<ShareSecretKey> for x25519_dalek::StaticSecret {
    fn from(secret: ShareSecretKey) -> Self {
        x25519_dalek::StaticSecret::from(secret.0)
    }
}

impl From<x25519_dalek::StaticSecret> for ShareSecretKey {
    fn from(secret: x25519_dalek::StaticSecret) -> Self {
        Self(secret.to_bytes())
    }
}

impl From<&ShareSecretKey> for Vec<u8> {
    fn from(secret: &ShareSecretKey) -> Self {
        secret.0.to_vec()
    }
}
