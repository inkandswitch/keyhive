//! Newtype around [ECDH] "sharing" public keys.
//!
//! [ECDH]: https://wikipedia.org/wiki/Elliptic-curve_Diffie%E2%80%93Hellman

use super::{separable::Separable, symmetric_key::SymmetricKey};
use dupe::Dupe;
use serde::{Deserialize, Serialize};
use std::fmt;
use tracing::instrument;

/// Newtype around [x25519_dalek::PublicKey].
#[derive(Copy, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ShareKey(x25519_dalek::PublicKey);

#[cfg(any(test, feature = "arbitrary"))]
impl<'a> arbitrary::Arbitrary<'a> for ShareKey {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let bytes = u.bytes(32)?;
        let arr = <[u8; 32]>::try_from(bytes).unwrap();
        Ok(Self(x25519_dalek::PublicKey::from(arr)))
    }
}

impl ShareKey {
    #[instrument(skip_all)]
    pub fn generate<R: rand::CryptoRng + rand::RngCore>(csprng: &mut R) -> Self {
        Self(x25519_dalek::PublicKey::from(
            &x25519_dalek::EphemeralSecret::random_from_rng(csprng),
        ))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }
}

impl Dupe for ShareKey {
    fn dupe(&self) -> Self {
        Self(self.0)
    }
}

impl fmt::LowerHex for ShareKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        crate::util::hex::bytes_as_hex(self.0.as_bytes().iter(), f)
    }
}

impl fmt::Display for ShareKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#x}", self)
    }
}

impl fmt::Debug for ShareKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
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

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[cfg_attr(any(test, feature = "arbitrary"), derive(arbitrary::Arbitrary))]
pub struct ShareSecretKey([u8; 32]);

impl ShareSecretKey {
    #[instrument(skip_all)]
    pub fn generate<R: rand::CryptoRng + rand::RngCore>(csprng: &mut R) -> Self {
        x25519_dalek::StaticSecret::random_from_rng(csprng).into()
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

    #[instrument]
    pub fn derive_new_secret_key(&self, other: &ShareKey) -> Self {
        let bytes: [u8; 32] = x25519_dalek::StaticSecret::from(*self)
            .diffie_hellman(&other.0)
            .to_bytes();

        Self::derive_from_bytes(bytes.as_slice())
    }

    #[instrument]
    pub fn derive_symmetric_key(&self, other: &ShareKey) -> SymmetricKey {
        let secret = x25519_dalek::StaticSecret::from(*self)
            .diffie_hellman(&other.0)
            .to_bytes();

        Self::derive_from_bytes(secret.as_slice()).0.into()
    }

    #[instrument]
    pub fn ratchet_forward(&self) -> Self {
        let bytes = self.to_bytes();
        Self::derive_from_bytes(bytes.as_slice())
    }

    pub fn ratchet_n_forward(&self, n: usize) -> Self {
        (0..n).fold(*self, |acc, _| acc.ratchet_forward())
    }

    pub(crate) fn force_from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
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

impl Separable for ShareSecretKey {
    fn directly_from_32_bytes(bytes: [u8; 32]) -> Self {
        ShareSecretKey(bytes)
    }
}

impl fmt::LowerHex for ShareSecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        crate::util::hex::bytes_as_hex(self.0.iter(), f)
    }
}

impl fmt::Display for ShareSecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#x}", self)
    }
}

impl fmt::Debug for ShareSecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ShareSecretKey(SECRET)")
    }
}
