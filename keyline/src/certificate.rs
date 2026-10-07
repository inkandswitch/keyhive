//! The unit of the set: a signed delegation or a signed revocation.
//!
//! What gets signed is the delegation or the revocation itself, each under its
//! own [`Domain`](keyhive_crypto::domain_separator::Domain) context. A
//! certificate is the sum of those two signed forms, not a signature over a
//! sum, so each statement has exactly one identity: the digest of its signed
//! payload. That is what the set is keyed by, and what `revoke` and `citation`
//! name.

use crate::{
    delegation::Delegation,
    id::Id,
    revocation::{Revocation, RevocationId},
    signed::{Signed, Verified, VerifyError},
};
use keyhive_codec::traits::{Decode, Encode};
use keyhive_crypto::digest::Digest;

/// A signed statement, as received: either kind of certificate.
///
/// Equality is [`Signed`]'s: payload bytes _and_ signature. Compare
/// [`Certificate::id`] for "same statement".
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(bound = ""))]
pub enum Certificate<W> {
    /// A signed delegation.
    Delegation(Signed<Delegation>),

    /// A signed revocation.
    Revocation(Signed<Revocation<W>>),
}

impl<W> Certificate<W> {
    /// The certificate's identity.
    pub fn id(&self) -> CertificateId {
        match self {
            Certificate::Delegation(d) => CertificateId::Delegation(d.digest()),
            Certificate::Revocation(r) => CertificateId::Revocation(r.digest().coerce()),
        }
    }
}

impl<W: Decode + Encode> Certificate<W> {
    /// Verify whichever kind this is; see [`Signed::verify`].
    pub fn verify(self) -> Result<VerifiedCertificate<W>, VerifyError> {
        Ok(match self {
            Certificate::Delegation(d) => VerifiedCertificate::Delegation(d.verify()?),
            Certificate::Revocation(r) => VerifiedCertificate::Revocation(r.verify()?),
        })
    }
}

/// A certificate whose bytes decoded canonically and whose signature checked
/// against the issuer it names: what [`crate::contract::Keyline::insert`]
/// takes. Equality is the [`Certificate`]'s it was verified from.
#[derive(Debug, Clone)]
pub enum VerifiedCertificate<W> {
    /// A verified delegation.
    Delegation(Verified<Delegation>),

    /// A verified revocation.
    Revocation(Verified<Revocation<W>>),
}

impl<W> VerifiedCertificate<W> {
    /// The certificate's identity.
    pub fn id(&self) -> CertificateId {
        match self {
            VerifiedCertificate::Delegation(d) => CertificateId::Delegation(d.digest()),
            VerifiedCertificate::Revocation(r) => CertificateId::Revocation(r.digest().coerce()),
        }
    }

    /// The key that signed it, as named by the payload.
    pub fn issuer(&self) -> Id {
        match self {
            VerifiedCertificate::Delegation(d) => d.payload().issuer,
            VerifiedCertificate::Revocation(r) => r.payload().issuer,
        }
    }

    /// The certificate as received, for forwarding without re-encoding.
    pub fn into_certificate(self) -> Certificate<W> {
        match self {
            VerifiedCertificate::Delegation(d) => Certificate::Delegation(d.into_parts().1),
            VerifiedCertificate::Revocation(r) => Certificate::Revocation(r.into_parts().1),
        }
    }
}

// Manual impls: derives would bound `W`, which `Signed` and `Verified` do not
// need for these.
impl<W> Clone for Certificate<W> {
    fn clone(&self) -> Self {
        match self {
            Certificate::Delegation(d) => Certificate::Delegation(d.clone()),
            Certificate::Revocation(r) => Certificate::Revocation(r.clone()),
        }
    }
}

impl<W> PartialEq for Certificate<W> {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Certificate::Delegation(a), Certificate::Delegation(b)) => a == b,
            (Certificate::Revocation(a), Certificate::Revocation(b)) => a == b,
            _ => false,
        }
    }
}

impl<W> Eq for Certificate<W> {}

impl<W> core::hash::Hash for Certificate<W> {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        core::mem::discriminant(self).hash(state);
        match self {
            Certificate::Delegation(d) => d.hash(state),
            Certificate::Revocation(r) => r.hash(state),
        }
    }
}

impl<W> core::fmt::Debug for Certificate<W> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Certificate::Delegation(d) => f.debug_tuple("Delegation").field(d).finish(),
            Certificate::Revocation(r) => f.debug_tuple("Revocation").field(r).finish(),
        }
    }
}

impl<W> PartialEq for VerifiedCertificate<W> {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (VerifiedCertificate::Delegation(a), VerifiedCertificate::Delegation(b)) => a == b,
            (VerifiedCertificate::Revocation(a), VerifiedCertificate::Revocation(b)) => a == b,
            _ => false,
        }
    }
}

impl<W> Eq for VerifiedCertificate<W> {}

impl<W> From<Verified<Delegation>> for VerifiedCertificate<W> {
    fn from(d: Verified<Delegation>) -> Self {
        VerifiedCertificate::Delegation(d)
    }
}

impl<W> From<Verified<Revocation<W>>> for VerifiedCertificate<W> {
    fn from(r: Verified<Revocation<W>>) -> Self {
        VerifiedCertificate::Revocation(r)
    }
}

/// A certificate's identity: the digest of its signed payload.
///
/// The two kinds are hashed under different domain contexts, so their digests
/// never collide and a set can hold both under one key type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CertificateId {
    /// A delegation's digest, as a revocation's `revoke` names it.
    Delegation(Digest<Delegation>),

    /// A revocation's digest, as a delegation's `citation` names it.
    Revocation(Digest<RevocationId>),
}

impl CertificateId {
    /// The digest bytes.
    pub fn as_slice(&self) -> &[u8] {
        match self {
            CertificateId::Delegation(d) => d.as_slice(),
            CertificateId::Revocation(r) => r.as_slice(),
        }
    }
}

impl From<Digest<Delegation>> for CertificateId {
    fn from(d: Digest<Delegation>) -> Self {
        CertificateId::Delegation(d)
    }
}

impl From<Digest<RevocationId>> for CertificateId {
    fn from(r: Digest<RevocationId>) -> Self {
        CertificateId::Revocation(r)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        power::Power,
        test_utils::{id, signing_key},
    };

    /// Variable-length, to exercise the `retain` codec.
    type Watermark = alloc::vec::Vec<u8>;

    /// The set key, the `revoke` pointer and the signed form's digest are one
    /// value.
    #[test]
    fn identity_is_the_payload_digest() {
        let d = Delegation::new(id(1), id(2), id(3), Power::Read);
        let signed = Signed::try_sign(&d, &signing_key(1)).expect("key is the issuer");
        let cert: Certificate<Watermark> = Certificate::Delegation(signed);
        assert_eq!(cert.id(), CertificateId::Delegation(d.digest()));

        let r: Revocation<Watermark> = Revocation::new(id(4), d.digest());
        let signed = Signed::try_sign(&r, &signing_key(4)).expect("key is the issuer");
        let cert = Certificate::Revocation(signed);
        assert_eq!(cert.id(), CertificateId::Revocation(r.digest()));

        let verified = cert.clone().verify().expect("verifies");
        assert_eq!(verified.id(), cert.id());
        assert_eq!(verified.issuer(), id(4));
        assert_eq!(verified.into_certificate(), cert);
    }
}
