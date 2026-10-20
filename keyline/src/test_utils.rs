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

use crate::{
    certificate::VerifiedCertificate,
    delegation::Delegation,
    power::Power,
    revocation::{Revocation, RevocationId},
};
use alloc::collections::BTreeMap;
use core::ops::Deref;
use ed25519_dalek::{Signature, SigningKey};
use keyhive_codec::traits::{Decode, Encode};
use keyhive_crypto::{
    digest::Digest,
    identifier::Identifier,
    signable::{message, Signable},
    verified::{Signed, Verified},
};

/// A payload and the key that will sign it: a certificate before it is
/// signed. Signing moves the issuer into the signed envelope.
///
/// Derefs to the payload, so fixtures and oracles read `d.audience` and
/// `d.issuer` alike.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Issued<T> {
    pub issuer: Identifier,
    pub payload: T,
}

impl<T> Deref for Issued<T> {
    type Target = T;

    fn deref(&self) -> &T {
        &self.payload
    }
}

impl Issued<Delegation> {
    /// The identity the delegation has once signed.
    pub fn digest(&self) -> Digest<Delegation> {
        Digest::of(&self.issuer, &self.payload.encode())
    }

    /// Re-issue past a revocation, as [`Delegation::reissue`].
    pub fn reissue(self, citation: Digest<RevocationId>) -> Self {
        Issued {
            issuer: self.issuer,
            payload: self.payload.reissue(citation),
        }
    }
}

impl<W: Encode> Issued<Revocation<W>> {
    /// The identity the revocation has once signed.
    pub fn digest(&self) -> Digest<RevocationId> {
        Digest::<Revocation<W>>::of(&self.issuer, &self.payload.encode()).coerce()
    }
}

impl<W> Issued<Revocation<W>> {
    /// The same revocation, carrying retention watermarks.
    pub fn retaining(self, retain: BTreeMap<Identifier, W>) -> Self {
        Issued {
            issuer: self.issuer,
            payload: self.payload.retaining(retain),
        }
    }
}

/// `issuer` delegates `power` over `subject` to `audience`.
pub fn delegation(
    issuer: Identifier,
    audience: Identifier,
    subject: Identifier,
    power: Power,
) -> Issued<Delegation> {
    Issued {
        issuer,
        payload: Delegation::new(audience, subject, power),
    }
}

/// `issuer` revokes the delegation with digest `revoke`.
pub fn revocation<W>(issuer: Identifier, revoke: Digest<Delegation>) -> Issued<Revocation<W>> {
    Issued {
        issuer,
        payload: Revocation::new(revoke),
    }
}

/// An unsigned statement: what the generator, the oracles and the fixtures
/// work with before anything is signed.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Statement<W> {
    Delegation(Issued<Delegation>),
    Revocation(Issued<Revocation<W>>),
}

impl<W> Statement<W> {
    /// Who will sign it.
    pub fn issuer(&self) -> Identifier {
        match self {
            Statement::Delegation(d) => d.issuer,
            Statement::Revocation(r) => r.issuer,
        }
    }

    /// The delegation, if this is one.
    pub fn as_delegation(&self) -> Option<&Issued<Delegation>> {
        match self {
            Statement::Delegation(d) => Some(d),
            Statement::Revocation(_) => None,
        }
    }

    /// The revocation, if this is one.
    pub fn as_revocation(&self) -> Option<&Issued<Revocation<W>>> {
        match self {
            Statement::Delegation(_) => None,
            Statement::Revocation(r) => Some(r),
        }
    }
}

impl<W> From<Issued<Delegation>> for Statement<W> {
    fn from(d: Issued<Delegation>) -> Self {
        Statement::Delegation(d)
    }
}

impl<W> From<Issued<Revocation<W>>> for Statement<W> {
    fn from(r: Issued<Revocation<W>>) -> Self {
        Statement::Revocation(r)
    }
}

/// A deterministic signing key derived from a small integer.
pub fn signing_key(n: u8) -> SigningKey {
    SigningKey::from([n; 32])
}

/// The [`Identifier`] of [`signing_key`]`(n)`.
pub fn id(n: u8) -> Identifier {
    Identifier::from(&signing_key(n))
}

/// Wrap a statement as a [`VerifiedCertificate`] without signing it.
///
/// The signature is all zeros and is never checked, so graph tests do not pay
/// for Ed25519. Use [`signed`] where the production path matters.
pub fn assume_verified<W: Encode + Decode, X: Into<Statement<W>>>(
    statement: X,
) -> VerifiedCertificate<W> {
    fn assume<T: Signable>(issued: &Issued<T>) -> Verified<T> {
        Verified::assume(Signed::new(
            issued.issuer,
            issued.payload.encode(),
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
    fn sign<T: Signable>(payload: &T, key: &SigningKey) -> Verified<T> {
        Verified::sign_sync(payload, key)
            .expect("signed by its issuer, so only a non-canonical `W` codec fails to verify")
    }
    let statement = statement.into();
    let key = issuer_key(statement.issuer());
    match statement {
        Statement::Delegation(d) => sign(&d.payload, &key).into(),
        Statement::Revocation(r) => sign(&r.payload, &key).into(),
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
    fn sign<T: Signable>(payload: &T, key: &SigningKey, salt: u8) -> Verified<T> {
        use ed25519_dalek::hazmat::{raw_sign, ExpandedSecretKey};

        let mut expanded = ExpandedSecretKey::from(key.as_bytes());
        expanded.hash_prefix = [salt; 32];
        let issuer = Identifier::from(key);
        let encoded = payload.encode();
        let message = message::<T>(&issuer, encoded.as_bytes());
        let signature = raw_sign::<sha2::Sha512>(&expanded, &message, &key.verifying_key());
        Signed::new(issuer, encoded, signature)
            .verify()
            .expect("a signature with any nonce verifies")
    }
    let statement = statement.into();
    let key = issuer_key(statement.issuer());
    match statement {
        Statement::Delegation(d) => sign(&d.payload, &key, salt).into(),
        Statement::Revocation(r) => sign(&r.payload, &key, salt).into(),
    }
}

/// The fixture signing key whose `Identifier` is `issuer`.
fn issuer_key(issuer: Identifier) -> SigningKey {
    (0..=u8::MAX)
        .map(signing_key)
        .find(|k| Identifier::from(k) == issuer)
        .expect("issuer is a fixture identity")
}
