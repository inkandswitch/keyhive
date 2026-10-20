//! The unit of the set: a signed delegation or a signed revocation.
//!
//! What gets signed is the delegation or the revocation itself, each as its
//! own [`Kinded`](keyhive_crypto::signable::Kinded) kind. A
//! certificate is the sum of those two signed forms, not a signature over a
//! sum, so each statement has exactly one identity: the digest of what its
//! signature covers, its frame without the signature (issuer and payload).
//! That is what the set is keyed by, and what `revoke` and `citation` name.
//!
//! On the wire a certificate is its signed form's frame:
//! `"KH" ‖ kind ‖ version ‖ issuer ‖ payload_len ‖ payload ‖ signature`
//! ([`Encode`] and [`Decode`] below).

use crate::{
    delegation::Delegation,
    revocation::{Revocation, RevocationId},
};
use alloc::{sync::Arc, vec::Vec};
use core::{
    fmt,
    hash::{Hash, Hasher},
};
use keyhive_codec::{
    error::DecodeError,
    traits::{decode_exact, Decode, Encode, StreamDecode},
};
use keyhive_crypto::{
    digest::Digest,
    identifier::Identifier,
    signable::Kind,
    verified::{header, Signed, Verified, VerifyError},
};

/// A signed statement, as received: either kind of certificate.
///
/// Equality is [`Signed`]'s: payload bytes _and_ signature. Compare
/// [`Certificate::id`] for "same statement".
///
/// The wire form is [`Encode`]/[`Decode`]. The `serde` feature also derives
/// `Serialize`/`Deserialize`, for a caller that wants a format of its own.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(bound = ""))]
///
/// Each variant shares its [`Signed`] form, so a store hands out certificates
/// without copying their bytes.
pub enum Certificate<W> {
    /// A signed delegation.
    Delegation(Arc<Signed<Delegation>>),

    /// A signed revocation.
    Revocation(Arc<Signed<Revocation<W>>>),
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

// Wire framing: each signed form's own frame,
// `"KH" ‖ kind ‖ version ‖ issuer ‖ payload_len ‖ payload ‖ signature`; the
// kind says which. Frames are self-delimiting, so certificates can be read
// back to back. `decode` checks the framing only: the payload is kept as
// received, and `verify` decodes it, checks it is canonical, and checks the
// signature.
impl<W> Encode for Certificate<W> {
    fn encode_into(&self, out: &mut Vec<u8>) {
        match self {
            Certificate::Delegation(d) => d.encode_into(out),
            Certificate::Revocation(r) => r.encode_into(out),
        }
    }
}

impl<W> Decode for Certificate<W> {
    fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        decode_exact(bytes)
    }
}

impl<W> StreamDecode for Certificate<W> {
    fn decode_next(bytes: &[u8]) -> Result<(Self, &[u8]), DecodeError> {
        let (kind, _) = header(bytes)?;
        match Kind::from_u8(kind) {
            Some(Kind::DELEGATION) => {
                let (signed, rest) = Signed::decode_next(bytes)?;
                Ok((Certificate::Delegation(Arc::new(signed)), rest))
            }
            Some(Kind::REVOCATION) => {
                let (signed, rest) = Signed::decode_next(bytes)?;
                Ok((Certificate::Revocation(Arc::new(signed)), rest))
            }
            _ => Err(DecodeError::UnexpectedKind(kind)),
        }
    }
}

#[cfg(feature = "arbitrary")]
impl<'a, W: arbitrary::Arbitrary<'a> + Encode> arbitrary::Arbitrary<'a> for Certificate<W> {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let signature = ed25519_dalek::Signature::from_bytes(&u.arbitrary()?);
        Ok(if u.arbitrary()? {
            let d: Delegation = u.arbitrary()?;
            Certificate::Delegation(Arc::new(Signed::new(u.arbitrary()?, d.encode(), signature)))
        } else {
            let r: Revocation<W> = u.arbitrary()?;
            Certificate::Revocation(Arc::new(Signed::new(u.arbitrary()?, r.encode(), signature)))
        })
    }
}

impl<W: Decode + Encode> Certificate<W> {
    /// Verify whichever kind this is; see [`Signed::verify`].
    ///
    /// A freshly decoded certificate holds the only reference to its signed
    /// form, so nothing is copied.
    pub fn verify(self) -> Result<VerifiedCertificate<W>, VerifyError> {
        Ok(match self {
            Certificate::Delegation(d) => Arc::unwrap_or_clone(d).verify()?.into(),
            Certificate::Revocation(r) => Arc::unwrap_or_clone(r).verify()?.into(),
        })
    }
}

/// A certificate whose bytes decoded canonically and whose signature checked
/// against the issuer it names: what [`crate::contract::Keyline::insert`]
/// takes. Equality is the [`Certificate`]'s it was verified from.
///
/// Each variant shares its [`Verified`] value, so cloning is a reference
/// count, and a store keeps the value it is given.
#[derive(Debug)]
pub enum VerifiedCertificate<W> {
    /// A verified delegation.
    Delegation(Arc<Verified<Delegation>>),

    /// A verified revocation.
    Revocation(Arc<Verified<Revocation<W>>>),
}

impl<W> VerifiedCertificate<W> {
    /// The certificate's identity.
    pub fn id(&self) -> CertificateId {
        match self {
            VerifiedCertificate::Delegation(d) => CertificateId::Delegation(d.digest()),
            VerifiedCertificate::Revocation(r) => CertificateId::Revocation(r.digest().coerce()),
        }
    }

    /// The key that signed it.
    pub fn issuer(&self) -> Identifier {
        match self {
            VerifiedCertificate::Delegation(d) => d.issuer(),
            VerifiedCertificate::Revocation(r) => r.issuer(),
        }
    }

    /// The certificate as received, for forwarding without re-encoding.
    /// Shares the signed form.
    pub fn into_certificate(self) -> Certificate<W> {
        match self {
            VerifiedCertificate::Delegation(d) => Certificate::Delegation(Arc::clone(d.signed())),
            VerifiedCertificate::Revocation(r) => Certificate::Revocation(Arc::clone(r.signed())),
        }
    }
}

// Manual: the derive would bound `W: Clone`, which sharing does not need.
impl<W> Clone for VerifiedCertificate<W> {
    fn clone(&self) -> Self {
        match self {
            VerifiedCertificate::Delegation(d) => VerifiedCertificate::Delegation(Arc::clone(d)),
            VerifiedCertificate::Revocation(r) => VerifiedCertificate::Revocation(Arc::clone(r)),
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

impl<W> Hash for Certificate<W> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        core::mem::discriminant(self).hash(state);
        match self {
            Certificate::Delegation(d) => d.hash(state),
            Certificate::Revocation(r) => r.hash(state),
        }
    }
}

impl<W> fmt::Debug for Certificate<W> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
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

impl<W> Hash for VerifiedCertificate<W> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        core::mem::discriminant(self).hash(state);
        match self {
            VerifiedCertificate::Delegation(d) => d.hash(state),
            VerifiedCertificate::Revocation(r) => r.hash(state),
        }
    }
}

impl<W> From<Verified<Delegation>> for VerifiedCertificate<W> {
    fn from(d: Verified<Delegation>) -> Self {
        VerifiedCertificate::Delegation(Arc::new(d))
    }
}

impl<W> From<Verified<Revocation<W>>> for VerifiedCertificate<W> {
    fn from(r: Verified<Revocation<W>>) -> Self {
        VerifiedCertificate::Revocation(Arc::new(r))
    }
}

/// A certificate's identity: the digest of its frame without the signature
/// (issuer and payload).
///
/// The two kinds are hashed under different registry kinds, so their digests
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

    /// The digest bytes, by value.
    pub fn to_bytes(&self) -> [u8; Digest::<Delegation>::LEN] {
        match *self {
            CertificateId::Delegation(d) => d.into(),
            CertificateId::Revocation(r) => r.into(),
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
    use alloc::vec::Vec;

    /// Variable-length, to exercise the `retain` codec.
    type Watermark = Vec<u8>;

    /// The set key, the `revoke` pointer and the signed form's digest are one
    /// value, over the issuer and the payload.
    #[test]
    fn identity_is_the_digest_of_issuer_and_payload() {
        let d = Delegation::new(id(2), id(3), Power::Read);
        let signed = Verified::sign_sync(&d, &signing_key(1))
            .expect("key is the issuer")
            .into_parts()
            .1;
        let cert: Certificate<Watermark> = Certificate::Delegation(signed);
        let d_digest = Digest::of(&id(1), &d.encode());
        assert_eq!(cert.id(), CertificateId::Delegation(d_digest));

        let r: Revocation<Watermark> = Revocation::new(d_digest);
        let signed = Verified::sign_sync(&r, &signing_key(4))
            .expect("key is the issuer")
            .into_parts()
            .1;
        let cert = Certificate::Revocation(signed);
        assert_eq!(
            cert.id(),
            CertificateId::Revocation(Digest::of(&id(4), &r.encode()).coerce())
        );

        let verified = cert.clone().verify().expect("verifies");
        assert_eq!(verified.id(), cert.id());
        assert_eq!(verified.issuer(), id(4));
        assert_eq!(verified.into_certificate(), cert);
    }

    /// The wire form is the `KH` tag, kind, version, issuer, payload length,
    /// payload, signature; it decodes back to the same certificate, which still
    /// verifies.
    #[test]
    fn wire_form_round_trips_and_verifies() {
        let d = Delegation::new(id(2), id(3), Power::Read);
        let signed = Verified::sign_sync(&d, &signing_key(1))
            .expect("key is the issuer")
            .into_parts()
            .1;
        let cert: Certificate<Watermark> = Certificate::Delegation(signed.clone());
        let bytes = cert.encode().into_bytes();
        assert_eq!(bytes[..4], *b"KHD\x00");
        let payload = d.encode();
        assert_eq!(&bytes[4..36], id(1).as_bytes());
        assert_eq!(
            usize::from(bytes[36]),
            payload.len(),
            "a one-byte bijou64 length"
        );
        assert_eq!(&bytes[37..37 + payload.len()], payload.as_bytes());
        assert_eq!(&bytes[37 + payload.len()..], &signed.signature().to_bytes());

        let decoded = Certificate::<Watermark>::decode(&bytes).expect("decodes");
        assert_eq!(decoded, cert);
        assert!(decoded.verify().is_ok());
    }

    /// Frames are self-delimiting: two certificates written back to back
    /// read back one at a time.
    #[test]
    fn certificates_read_back_to_back() {
        let first =
            Verified::sign_sync(&Delegation::new(id(2), id(3), Power::Read), &signing_key(1))
                .expect("any key signs");
        let second: Verified<Revocation<Watermark>> =
            Verified::sign_sync(&Revocation::new(first.digest()), &signing_key(1))
                .expect("any key signs");
        let a: Certificate<Watermark> = Certificate::Delegation(first.signed().clone());
        let b = Certificate::Revocation(second.signed().clone());
        let mut bytes = a.encode().into_bytes();
        bytes.extend_from_slice(b.encode().as_bytes());

        let (read_a, rest) = Certificate::<Watermark>::decode_next(&bytes).expect("first");
        let (read_b, rest) = Certificate::<Watermark>::decode_next(rest).expect("second");
        assert_eq!((read_a, read_b, rest), (a, b, &[][..]));
    }

    #[test]
    fn rejects_bad_framing() {
        let frame = |kind: Kind, version: u8, rest: &[u8]| {
            let mut bytes = b"KH".to_vec();
            bytes.extend_from_slice(&[kind.to_u8(), version]);
            bytes.extend_from_slice(rest);
            bytes
        };
        assert_eq!(
            Certificate::<Watermark>::decode(&[]),
            Err(DecodeError::UnexpectedEnd)
        );
        assert_eq!(
            Certificate::<Watermark>::decode(&[0; 66]),
            Err(DecodeError::NotKeyhive),
            "no `KH` tag"
        );
        assert_eq!(
            Certificate::<Watermark>::decode(&frame(Kind::DELEGATION, 0, &[0])),
            Err(DecodeError::UnexpectedEnd),
            "shorter than an issuer"
        );
        assert_eq!(
            Certificate::<Watermark>::decode(&frame(Kind::CERTIFICATE_SET, 0, &[0])),
            Err(DecodeError::UnexpectedKind(Kind::CERTIFICATE_SET.to_u8())),
            "a registered kind that is not a certificate"
        );
        assert_eq!(
            Certificate::<Watermark>::decode(&frame(Kind::REVOCATION, 9, &[0])),
            Err(DecodeError::UnsupportedVersion {
                kind: Kind::REVOCATION.to_u8(),
                version: 9
            })
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
        keyhive_codec::laws::canonical_near::<Certificate<Watermark>>();
    }
}
