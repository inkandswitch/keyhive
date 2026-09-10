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
/// so that graph tests do not pay for Ed25519. Use [`signed`] where the
/// production path matters.
pub fn cert<C: Into<Certificate>>(cert: C) -> Verified<Certificate> {
    let cert = cert.into();
    Verified::assume(Signed::from_parts(
        cert.encode(),
        Signature::from_bytes(&[0u8; 64]),
    ))
}

/// Sign a certificate with the deterministic key of its issuer and verify it:
/// the production path, for the few tests that should exercise it.
///
/// The issuer must be one of the fixture identities (`id(n)`), so its signing
/// key is `signing_key(n)`.
pub fn signed<C: Into<Certificate>>(cert: C) -> Verified<Certificate> {
    let cert = cert.into();
    let key = (0..=u8::MAX)
        .map(signing_key)
        .find(|k| Id::new(k.verifying_key()) == cert.issuer())
        .expect("issuer is a fixture identity");
    Signed::try_sign(&cert, &key)
        .expect("key is the issuer")
        .verify()
        .expect("freshly signed certificate verifies")
}
