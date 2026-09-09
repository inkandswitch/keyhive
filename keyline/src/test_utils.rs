//! Deterministic fixtures for tests. Not part of the public API.

use crate::{
    certificate::Certificate,
    id::Id,
    signed::{Signed, Verified},
};
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use keyhive_codec::traits::Encode;

/// A deterministic signing key derived from a small integer.
pub fn signing_key(n: u8) -> SigningKey {
    SigningKey::from([n; 32])
}

/// The [`Id`] of [`signing_key`]`(n)`.
pub fn id(n: u8) -> Id {
    Id::new(VerifyingKey::from(&signing_key(n)))
}

/// Wrap a certificate as [`Verified`] without signing it.
///
/// The signature is all zeros and is never checked: [`Verified::assume`] exists
/// so that graph tests do not pay for Ed25519. The issuer is taken from the
/// certificate, so the payload is self-consistent.
pub fn cert<C: Into<Certificate>>(cert: C) -> Verified<Certificate> {
    let cert = cert.into();
    Verified::assume(Signed::from_parts(
        cert.encode(),
        cert.issuer(),
        Signature::from_bytes(&[0u8; 64]),
    ))
}
