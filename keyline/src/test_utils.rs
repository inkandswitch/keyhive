//! Deterministic fixtures for tests. Not part of the public API.

use crate::id::Id;
use ed25519_dalek::{SigningKey, VerifyingKey};

/// A deterministic signing key derived from a small integer.
pub fn signing_key(n: u8) -> SigningKey {
    SigningKey::from([n; 32])
}

/// The [`Id`] of [`signing_key`]`(n)`.
pub fn id(n: u8) -> Id {
    Id::new(VerifyingKey::from(&signing_key(n)))
}
