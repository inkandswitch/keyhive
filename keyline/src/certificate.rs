//! The unit of the set: a signed delegation or a signed revocation.
//!
//! What gets signed is the delegation or the revocation itself, each under its
//! own [`Domain`](keyhive_crypto::domain_separator::Domain) context. A
//! certificate is the sum of those two signed forms, not a signature over a
//! sum, so each statement has exactly one identity: the digest of its signed
//! payload. That is what the set is keyed by, and what `revoke` and `citation`
//! name.
//!
//! On the wire a certificate is its kind, its signature, then its payload
//! ([`Encode`] and [`Decode`] below).

use crate::{
    delegation::Delegation,
    id::Id,
    revocation::{Revocation, RevocationId},
    signed::{Signed, Verified, VerifyError},
};
use alloc::vec::Vec;
use ed25519_dalek::Signature;
use keyhive_codec::{
    encoded::Encoded,
    error::DecodeError,
    traits::{Decode, Encode},
};
use keyhive_crypto::digest::Digest;

/// A signed statement, as received: either kind of certificate.
///
/// Equality is [`Signed`]'s: payload bytes _and_ signature. Compare
/// [`Certificate::id`] for "same statement".
///
/// The wire form is [`Encode`]/[`Decode`]. The `serde` feature also derives
/// `Serialize`/`Deserialize`, for a caller that wants a format of its own.
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

// Wire framing: kind ‖ signature ‖ payload. The payload is last and runs to
// the end of the input, so it needs no length; inside a larger message, frame
// the whole certificate. `decode` checks the framing only: the payload is
// kept as received, and `verify` decodes it, checks it is canonical, and
// checks the signature.
const TAG_DELEGATION: u8 = 0;
const TAG_REVOCATION: u8 = 1;
const SIGNATURE_LEN: usize = 64;

impl<W> Encode for Certificate<W> {
    fn encode_into(&self, out: &mut Vec<u8>) {
        let (tag, signature, payload) = match self {
            Certificate::Delegation(d) => (TAG_DELEGATION, d.signature(), d.encoded().as_bytes()),
            Certificate::Revocation(r) => (TAG_REVOCATION, r.signature(), r.encoded().as_bytes()),
        };
        out.push(tag);
        out.extend_from_slice(&signature.to_bytes());
        out.extend_from_slice(payload);
    }
}

impl<W> Decode for Certificate<W> {
    fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let (tag, rest) = bytes.split_first().ok_or(DecodeError::UnexpectedEnd)?;
        let (signature, payload) = rest
            .split_first_chunk::<SIGNATURE_LEN>()
            .ok_or(DecodeError::UnexpectedEnd)?;
        let signature = Signature::from_bytes(signature);
        match *tag {
            TAG_DELEGATION => Ok(Certificate::Delegation(Signed::from_parts(
                Encoded::from_bytes_unchecked(payload.to_vec()),
                signature,
            ))),
            TAG_REVOCATION => Ok(Certificate::Revocation(Signed::from_parts(
                Encoded::from_bytes_unchecked(payload.to_vec()),
                signature,
            ))),
            other => Err(DecodeError::InvalidTag(other)),
        }
    }
}

#[cfg(feature = "arbitrary")]
impl<'a, W: arbitrary::Arbitrary<'a> + Encode> arbitrary::Arbitrary<'a> for Certificate<W> {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let signature = Signature::from_bytes(&u.arbitrary()?);
        Ok(if u.arbitrary()? {
            let d: Delegation = u.arbitrary()?;
            Certificate::Delegation(Signed::from_parts(d.encode(), signature))
        } else {
            let r: Revocation<W> = u.arbitrary()?;
            Certificate::Revocation(Signed::from_parts(r.encode(), signature))
        })
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

    /// The wire form is kind, signature, payload; it decodes back to the same
    /// certificate, which still verifies.
    #[test]
    fn wire_form_round_trips_and_verifies() {
        let d = Delegation::new(id(1), id(2), id(3), Power::Read);
        let signed = Signed::try_sign(&d, &signing_key(1)).expect("key is the issuer");
        let cert: Certificate<Watermark> = Certificate::Delegation(signed.clone());
        let bytes = cert.encode().into_bytes();
        assert_eq!(bytes[0], TAG_DELEGATION);
        assert_eq!(&bytes[1..=SIGNATURE_LEN], &signed.signature().to_bytes());
        assert_eq!(&bytes[1 + SIGNATURE_LEN..], d.encode().as_bytes());

        let decoded = Certificate::<Watermark>::decode(&bytes).expect("decodes");
        assert_eq!(decoded, cert);
        assert!(decoded.verify().is_ok());
    }

    #[test]
    fn rejects_bad_framing() {
        assert_eq!(
            Certificate::<Watermark>::decode(&[]),
            Err(DecodeError::UnexpectedEnd)
        );
        assert_eq!(
            Certificate::<Watermark>::decode(&[TAG_DELEGATION; SIGNATURE_LEN]),
            Err(DecodeError::UnexpectedEnd),
            "shorter than a signature"
        );
        assert_eq!(
            Certificate::<Watermark>::decode(&[7; 1 + SIGNATURE_LEN]),
            Err(DecodeError::InvalidTag(7))
        );
    }

    #[test]
    #[cfg(feature = "arbitrary")]
    fn codec_laws() {
        bolero::check!()
            .with_arbitrary::<Certificate<Watermark>>()
            .for_each(|c| {
                let encoded = c.encode();
                assert_eq!(
                    &Certificate::decode(encoded.as_bytes()).expect("round trip"),
                    c
                );
            });
    }

    #[test]
    #[cfg(feature = "arbitrary")]
    fn decode_is_canonical() {
        crate::test_utils::decode_is_canonical_near::<Certificate<Watermark>>();
    }
}
