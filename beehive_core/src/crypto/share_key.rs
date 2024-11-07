//! Newtype around [ECDH] "sharing" public keys.
//!
//! [ECDH]: https://wikipedia.org/wiki/Elliptic-curve_Diffie%E2%80%93Hellman

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

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ShareSecretKey([u8; 32]);

impl ShareSecretKey {
    pub fn generate() -> Self {
        x25519_dalek::StaticSecret::random().into()
    }

    pub fn share_key(&self) -> ShareKey {
        ShareKey(x25519_dalek::PublicKey::from(
            &x25519_dalek::StaticSecret::from(*self),
        ))
    }

    pub fn as_bytes(&self) -> [u8; 32] {
        self.0
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0
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
