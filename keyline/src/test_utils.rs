//! Test support: deterministic fixtures, and the cross-backend conformance
//! suite in [`conformance`].
//!
//! Public so that other backends can run the conformance suite, and gated on
//! `cfg(test)` and the `conformance` feature (which `test_utils` implies). Not
//! covered by semver.
//!
//! > [!WARNING]
//! > [`assume_verified`] builds a [`VerifiedCertificate`] without checking any
//! > signature, so with either feature enabled the `Verified` witness proves
//! > nothing. Enable them only from dev-dependencies.

pub mod conformance;

use crate::{certificate::VerifiedCertificate, delegation::Delegation, revocation::Revocation};
use ed25519_dalek::{Signature, SigningKey};
use keyhive_codec::traits::{Decode, Encode};
use keyhive_crypto::{
    id::Id,
    signable::{message, Signable},
    verifiable::Verifiable,
    verified::{Signed, Verified},
};

/// An unsigned statement: what the generator, the oracles and the fixtures
/// work with before anything is signed.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Statement<W> {
    Delegation(Delegation),
    Revocation(Revocation<W>),
}

impl<W> Statement<W> {
    /// The signer either kind names.
    pub fn issuer(&self) -> Id {
        match self {
            Statement::Delegation(d) => d.issuer,
            Statement::Revocation(r) => r.issuer,
        }
    }

    /// The delegation, if this is one.
    pub fn as_delegation(&self) -> Option<&Delegation> {
        match self {
            Statement::Delegation(d) => Some(d),
            Statement::Revocation(_) => None,
        }
    }

    /// The revocation, if this is one.
    pub fn as_revocation(&self) -> Option<&Revocation<W>> {
        match self {
            Statement::Delegation(_) => None,
            Statement::Revocation(r) => Some(r),
        }
    }
}

impl<W> From<Delegation> for Statement<W> {
    fn from(d: Delegation) -> Self {
        Statement::Delegation(d)
    }
}

impl<W> From<Revocation<W>> for Statement<W> {
    fn from(r: Revocation<W>) -> Self {
        Statement::Revocation(r)
    }
}

/// A deterministic signing key derived from a small integer.
pub fn signing_key(n: u8) -> SigningKey {
    SigningKey::from([n; 32])
}

/// The [`Id`] of [`signing_key`]`(n)`.
pub fn id(n: u8) -> Id {
    Id::from(&signing_key(n))
}

/// Wrap a statement as a [`VerifiedCertificate`] without signing it.
///
/// The signature is all zeros and is never checked, so graph tests do not pay
/// for Ed25519. Use [`signed`] where the production path matters.
pub fn assume_verified<W: Encode + Decode, X: Into<Statement<W>>>(
    statement: X,
) -> VerifiedCertificate<W> {
    fn assume<T: Signable>(payload: &T) -> Verified<T> {
        Verified::assume(Signed::from_parts(
            payload.encode(),
            Signature::from_bytes(&[0u8; 64]),
        ))
    }
    match statement.into() {
        Statement::Delegation(d) => assume(&d).into(),
        Statement::Revocation(r) => assume(&r).into(),
    }
}

/// Sign a statement with the deterministic key of its issuer and verify it:
/// the production path, for the few tests that should exercise it.
///
/// The issuer must be one of the fixture identities (`id(n)`), so its signing
/// key is `signing_key(n)`.
///
/// # Panics
///
/// If the issuer is not a fixture identity, or if `W`'s `Encode`/`Decode` is
/// not canonical: the signed revocation then fails to verify.
pub fn signed<W: Encode + Decode, X: Into<Statement<W>>>(statement: X) -> VerifiedCertificate<W> {
    fn sign<T: Signable + Verifiable>(payload: &T, key: &SigningKey) -> Verified<T> {
        Verified::sign_sync(payload, key)
            .expect("signed by its issuer, so only a non-canonical `W` codec fails to verify")
    }
    let statement = statement.into();
    let key = issuer_key(statement.issuer());
    match statement {
        Statement::Delegation(d) => sign(&d, &key).into(),
        Statement::Revocation(r) => sign(&r, &key).into(),
    }
}

/// [`signed`], but with another valid signature over the same bytes.
///
/// The nonce is derived from `salt` instead of the RFC 8032 derivation, as a
/// hedged or randomized signer would choose it. The result has the same
/// identity as [`signed`]'s, and a different signature.
pub fn resigned<W: Encode + Decode, X: Into<Statement<W>>>(
    statement: X,
    salt: u8,
) -> VerifiedCertificate<W> {
    fn sign<T: Signable + Verifiable>(payload: &T, key: &SigningKey, salt: u8) -> Verified<T> {
        use ed25519_dalek::hazmat::{raw_sign, ExpandedSecretKey};

        let mut expanded = ExpandedSecretKey::from(key.as_bytes());
        expanded.hash_prefix = [salt; 32];
        let encoded = payload.encode();
        let message = message::<T>(encoded.as_bytes());
        let signature = raw_sign::<sha2::Sha512>(&expanded, &message, &key.verifying_key());
        Signed::from_parts(encoded, signature)
            .verify()
            .expect("a signature with any nonce verifies")
    }
    let statement = statement.into();
    let key = issuer_key(statement.issuer());
    match statement {
        Statement::Delegation(d) => sign(&d, &key, salt).into(),
        Statement::Revocation(r) => sign(&r, &key, salt).into(),
    }
}

/// The fixture signing key whose `Id` is `issuer`.
fn issuer_key(issuer: Id) -> SigningKey {
    (0..=u8::MAX)
        .map(signing_key)
        .find(|k| Id::from(k) == issuer)
        .expect("issuer is a fixture identity")
}
