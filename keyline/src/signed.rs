//! `Signed<T>` over `Encoded<T>`, and the `Verified<T>` witness.
//!
//! A [`Signed<T>`] carries a value's canonical bytes and a signature over
//! those bytes, prefixed with `T`'s [`Domain`] context. The signer is not a
//! separate field: the payload names its own issuer, and [`Signed::verify`]
//! checks the signature against the key the payload names
//! ([`Verifiable::verifying_key`]). A certificate that claims one issuer and is
//! signed by another does not verify. The digest and the signature cover the
//! same prefixed bytes by construction.
//!
//! [`Verified<T>`] is a witness that a `Signed<T>` has had its bytes decoded
//! canonically and its signature checked against the decoded issuer. Outside
//! the `test_utils` feature its only public constructor is [`Signed::verify`],
//! so an unchecked certificate cannot reach [`crate::contract::Keyline::insert`].
//!
//! `keyhive_crypto` has a serde-based `Signed<T>` that `keyhive_core` uses; this
//! type is its `Encoded`-based counterpart.

// TODO(keyhive_types): lift `Signed` and `Verified` out of keyline once beekem migrates.

use core::fmt;
use ed25519_dalek::{Signature, Signer, SigningKey};
use keyhive_codec::{
    encoded::Encoded,
    error::DecodeError,
    traits::{Decode, Encode},
};
use keyhive_crypto::{
    digest::Digest,
    domain_separator::{message, Domain},
    verifiable::Verifiable,
};

/// A value's canonical bytes and a signature over those bytes.
///
/// Equality is by encoded bytes _and_ signature. Ed25519 signing as specified
/// in RFC 8032 is deterministic, so one key signing one payload twice yields
/// equal values. A signer that picks its nonce another way produces a
/// different signature that verifies just as well, and so a different
/// `Signed<T>` with the same [`Signed::digest`]. Compare digests or payloads
/// when "same statement" is what is meant. A
/// [`Keyline`](crate::contract::Keyline) set is keyed by digest, so it holds
/// such a pair as one certificate.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(bound = ""))]
pub struct Signed<T> {
    encoded: Encoded<T>,
    signature: Signature,
}

impl<T> Signed<T> {
    /// Assemble from parts received over a transport. Nothing is checked;
    /// call [`Signed::verify`] before trusting the payload.
    pub fn from_parts(encoded: Encoded<T>, signature: Signature) -> Self {
        Signed { encoded, signature }
    }

    /// The canonical bytes the signature covers.
    pub fn encoded(&self) -> &Encoded<T> {
        &self.encoded
    }

    /// The signature over [`Signed::encoded`], under `T`'s [`Domain`] context.
    pub fn signature(&self) -> &Signature {
        &self.signature
    }
}

impl<T: Domain> Signed<T> {
    /// Content address of the payload: BLAKE3 over the same bytes the signature covers.
    pub fn digest(&self) -> Digest<T> {
        Digest::of(&self.encoded)
    }
}

impl<T: Domain + Encode + Verifiable> Signed<T> {
    /// Encode and sign a value with the key it names as issuer.
    ///
    /// Fails if `key` is not the payload's issuer; `verify` would reject the
    /// result.
    pub fn try_sign(value: &T, key: &SigningKey) -> Result<Self, SignError> {
        if key.verifying_key() != value.verifying_key() {
            return Err(SignError::NotTheIssuer);
        }
        let encoded = value.encode();
        let signature = key.sign(&message::<T>(encoded.as_bytes()));
        Ok(Signed { encoded, signature })
    }
}

impl<T: Decode + Domain + Encode + Verifiable> Signed<T> {
    /// Decode the payload and check the signature against the issuer it names.
    ///
    /// The payload must decode and then re-encode to exactly the received
    /// bytes, so a `Verified<T>` is always canonical. The re-encode check
    /// covers what a decoder cannot vouch for itself, such as a consumer's
    /// [`RetentionWatermark`](crate::contract::Keyline::RetentionWatermark)
    /// codec. The signature is then checked with `verify_strict`, which
    /// rejects the malleable and small-order signatures that plain `verify`
    /// accepts, against `payload.verifying_key()`, never against a key the
    /// transport supplied.
    pub fn verify(self) -> Result<Verified<T>, VerifyError> {
        let payload = self
            .encoded
            .decode()
            .and_then(|p: T| {
                if p.encode().as_bytes() == self.encoded.as_bytes() {
                    Ok(p)
                } else {
                    Err(DecodeError::NonCanonical)
                }
            })
            .inspect_err(|&e| {
                tracing::debug!(digest = %self.digest(), error = %e, "certificate failed to decode");
            })?;
        payload
            .verifying_key()
            .verify_strict(&message::<T>(self.encoded.as_bytes()), &self.signature)
            .map_err(|_| {
                tracing::debug!(digest = %self.digest(), "certificate signature does not verify");
                VerifyError::BadSignature
            })?;
        Ok(Verified {
            payload,
            signed: self,
        })
    }
}

// Manual impls: derives would add `T: Clone` / `T: PartialEq` bounds that the
// phantom-typed `Encoded<T>` does not need.
impl<T> Clone for Signed<T> {
    fn clone(&self) -> Self {
        Signed {
            encoded: self.encoded.clone(),
            signature: self.signature,
        }
    }
}

impl<T> PartialEq for Signed<T> {
    fn eq(&self, other: &Self) -> bool {
        self.encoded == other.encoded && self.signature == other.signature
    }
}

impl<T> Eq for Signed<T> {}

impl<T> core::hash::Hash for Signed<T> {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.encoded.hash(state);
        self.signature.to_bytes().hash(state);
    }
}

impl<T: Domain> fmt::Debug for Signed<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Signed")
            .field("digest", &self.digest())
            .finish_non_exhaustive()
    }
}

/// A [`Signed<T>`] whose bytes decoded canonically and whose signature was
/// checked against the issuer the payload names. Constructed only by
/// [`Signed::verify`].
pub struct Verified<T> {
    payload: T,
    signed: Signed<T>,
}

impl<T> Verified<T> {
    /// The decoded payload.
    pub fn payload(&self) -> &T {
        &self.payload
    }

    /// The signed form as received, for forwarding without re-encoding.
    pub fn signed(&self) -> &Signed<T> {
        &self.signed
    }

    /// The payload and the signed form it came from.
    pub fn into_parts(self) -> (T, Signed<T>) {
        (self.payload, self.signed)
    }

    /// Construct without checking anything. Test fixtures only: lets the
    /// conformance suite build certificates without paying for signing.
    #[cfg(any(test, feature = "conformance"))]
    pub(crate) fn assume(signed: Signed<T>) -> Self
    where
        T: Decode,
    {
        let payload = signed
            .encoded
            .decode()
            .expect("test fixture must be canonically encoded");
        Verified { payload, signed }
    }
}

impl<T: Domain> Verified<T> {
    /// Content address of the payload.
    pub fn digest(&self) -> Digest<T> {
        self.signed.digest()
    }
}

impl<T: Verifiable> Verifiable for Verified<T> {
    fn verifying_key(&self) -> ed25519_dalek::VerifyingKey {
        self.payload.verifying_key()
    }
}

impl<T: Clone> Clone for Verified<T> {
    fn clone(&self) -> Self {
        Verified {
            payload: self.payload.clone(),
            signed: self.signed.clone(),
        }
    }
}

impl<T: Domain + fmt::Debug> fmt::Debug for Verified<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Verified")
            .field("payload", &self.payload)
            .field("digest", &self.digest())
            .finish()
    }
}

impl<T> PartialEq for Verified<T> {
    fn eq(&self, other: &Self) -> bool {
        self.signed == other.signed
    }
}

impl<T> Eq for Verified<T> {}

impl<T> core::hash::Hash for Verified<T> {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.signed.hash(state)
    }
}

/// Why [`Signed::try_sign`] refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SignError {
    /// The signing key is not the issuer the payload names.
    #[error("signing key is not the payload's issuer")]
    NotTheIssuer,
}

/// Why a [`Signed<T>`] did not verify.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum VerifyError {
    /// The signature does not match the issuer the payload names and the bytes.
    #[error("signature does not verify")]
    BadSignature,

    /// The bytes are not the canonical encoding of a `T`.
    #[error("payload does not decode: {0}")]
    Decode(#[from] DecodeError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        delegation::Delegation,
        id::Id,
        power::Power,
        revocation::Revocation,
        test_utils::{id, signing_key},
    };

    fn sample() -> Delegation {
        Delegation::new(id(1), id(2), id(3), Power::Edit)
    }

    #[test]
    fn sign_then_verify() {
        let signed = Signed::try_sign(&sample(), &signing_key(1)).expect("key is the issuer");
        let verified = signed.clone().verify().expect("verifies");
        assert_eq!(verified.payload(), &sample());
        assert_eq!(verified.payload().issuer, id(1));
        assert_eq!(verified.digest(), signed.digest());
        assert_eq!(verified.signed(), &signed);
    }

    #[test]
    fn signature_and_digest_cover_the_same_bytes() {
        let signed = Signed::try_sign(&sample(), &signing_key(1)).expect("key is the issuer");
        assert_eq!(signed.digest(), Digest::of(&sample().encode()));
        assert!(sample()
            .verifying_key()
            .verify_strict(
                &message::<Delegation>(signed.encoded().as_bytes()),
                signed.signature()
            )
            .is_ok());
    }

    /// A signature over the bare encoding, as another protocol sharing the
    /// key might produce, is not a signature over the certificate.
    #[test]
    fn signature_without_the_domain_context_fails() {
        let encoded = sample().encode();
        let bare = signing_key(1).sign(encoded.as_bytes());
        let signed = Signed::<Delegation>::from_parts(encoded, bare);
        assert_eq!(signed.verify().unwrap_err(), VerifyError::BadSignature);
    }

    /// A signature that plain `verify` accepts and `verify_strict` rejects.
    ///
    /// The issuer key is `[a]B + T` for a point `T` of order 8. It has mixed
    /// order, so [`Id`] accepts it. With a small-order `R` and `S = k·a`, the
    /// verification equation leaves `-[k]T`, which equals `R` for about one
    /// candidate in eight. Plain `verify` accepts that; `verify_strict`
    /// rejects the small-order `R`.
    #[test]
    fn small_order_r_is_rejected() {
        use curve25519_dalek::{
            constants::{ED25519_BASEPOINT_POINT, EIGHT_TORSION},
            scalar::Scalar,
        };
        use ed25519_dalek::Verifier;
        use sha2::{Digest as _, Sha512};

        let a = Scalar::from(0x5eed_u64);
        let torsion = EIGHT_TORSION[1];
        let point = a * ED25519_BASEPOINT_POINT + torsion;
        let issuer = Id::from_bytes(point.compress().to_bytes()).expect("mixed order is accepted");

        let (encoded, message, signature) = (2..=u8::MAX)
            .flat_map(|n| EIGHT_TORSION.iter().map(move |r| (n, r)))
            .find_map(|(n, r)| {
                let encoded = Delegation::new(issuer, id(n), id(1), Power::Edit).encode();
                let message = message::<Delegation>(encoded.as_bytes());
                let r_bytes = r.compress().to_bytes();
                let k = Scalar::from_bytes_mod_order_wide(
                    &Sha512::new()
                        .chain_update(r_bytes)
                        .chain_update(issuer.as_bytes())
                        .chain_update(&message)
                        .finalize()
                        .into(),
                );
                (k * torsion == -r).then(|| {
                    let signature = Signature::from_components(r_bytes, (k * a).to_bytes());
                    (encoded, message, signature)
                })
            })
            .expect("about one candidate in eight works");

        assert!(issuer.verifying_key().verify(&message, &signature).is_ok());
        assert_eq!(
            Signed::<Delegation>::from_parts(encoded, signature)
                .verify()
                .unwrap_err(),
            VerifyError::BadSignature
        );
    }

    /// `Signed` equality is the received bytes plus the signature, so the same
    /// payload under a different signature is a different value. `Verified`
    /// compares as the `Signed` it was built from.
    #[test]
    fn identity_is_bytes_and_signature() {
        let a = Signed::try_sign(&sample(), &signing_key(1)).expect("key is the issuer");
        let forged = Signed::from_parts(a.encoded().clone(), Signature::from_bytes(&[0u8; 64]));
        let read = Delegation::new(id(1), id(2), id(3), Power::Read);
        let other = Signed::try_sign(&read, &signing_key(1)).expect("key is the issuer");
        assert_ne!(a, forged);
        assert_ne!(a, other);

        let verified = a.clone().verify().expect("verifies");
        assert_eq!(verified, a.clone().verify().expect("verifies"));
        assert_ne!(verified, other.verify().expect("verifies"));
        assert_eq!(Verifiable::verifying_key(&verified), id(1).verifying_key());
    }

    #[test]
    #[cfg(feature = "std")]
    fn hash_agrees_with_eq() {
        use std::{
            collections::hash_map::DefaultHasher,
            hash::{Hash, Hasher},
        };
        fn hash<T: Hash>(value: &T) -> u64 {
            let mut state = DefaultHasher::new();
            value.hash(&mut state);
            state.finish()
        }

        let a = Signed::try_sign(&sample(), &signing_key(1)).expect("key is the issuer");
        let b = Signed::try_sign(&sample(), &signing_key(1)).expect("key is the issuer");
        let forged = Signed::from_parts(a.encoded().clone(), Signature::from_bytes(&[0u8; 64]));
        assert_eq!(hash(&a), hash(&b));
        assert_ne!(hash(&a), hash(&forged));

        let va = a.verify().expect("verifies");
        let vb = b.verify().expect("verifies");
        let read = Delegation::new(id(1), id(2), id(3), Power::Read);
        let vc = Signed::try_sign(&read, &signing_key(1))
            .expect("key is the issuer")
            .verify()
            .expect("verifies");
        assert_eq!(hash(&va), hash(&vb));
        assert_ne!(hash(&va), hash(&vc));
    }

    #[test]
    fn signing_with_a_key_that_is_not_the_issuer_is_refused() {
        assert_eq!(
            Signed::try_sign(&sample(), &signing_key(2)).unwrap_err(),
            SignError::NotTheIssuer
        );
    }

    /// The forgery `verify` must catch: a well-formed signature by Bob over a
    /// payload that names Alice as issuer.
    #[test]
    fn signer_must_be_the_payload_issuer() {
        let forger = signing_key(2);
        let encoded = sample().encode(); // issuer = id(1)
        let signature = forger.sign(&message::<Delegation>(encoded.as_bytes()));
        let forged = Signed::<Delegation>::from_parts(encoded, signature);
        assert_eq!(forged.verify().unwrap_err(), VerifyError::BadSignature);
    }

    #[test]
    fn tampered_bytes_fail() {
        // Edit → Read: still a canonical delegation, so only the signature
        // check can reject it.
        let signed = Signed::try_sign(&sample(), &signing_key(1)).expect("key is the issuer");
        let mut bytes = signed.encoded().clone().into_bytes();
        bytes[Id::LEN * 3] = Power::Read as u8;
        assert!(Delegation::decode(&bytes).is_ok());
        let tampered = Signed::<Delegation>::from_parts(
            Encoded::from_bytes_unchecked(bytes),
            *signed.signature(),
        );
        assert_eq!(tampered.verify().unwrap_err(), VerifyError::BadSignature);
    }

    #[test]
    fn valid_signature_over_non_canonical_bytes_fails_to_decode() {
        // Sign bytes that carry a trailing zero: signature is fine, decode is not.
        let key = signing_key(1);
        let mut bytes = sample().encode().into_bytes();
        bytes.push(0);
        let signature = key.sign(&message::<Delegation>(&bytes));
        let signed =
            Signed::<Delegation>::from_parts(Encoded::from_bytes_unchecked(bytes), signature);
        assert_eq!(
            signed.verify().unwrap_err(),
            VerifyError::Decode(DecodeError::TrailingBytes)
        );
    }

    #[test]
    fn works_for_revocations() {
        let revocation: Revocation<alloc::vec::Vec<u8>> =
            Revocation::new(id(1), sample().digest()).retaining([(id(3), alloc::vec![7])].into());
        let verified = Signed::try_sign(&revocation, &signing_key(1))
            .expect("key is the issuer")
            .verify()
            .expect("verifies");
        assert_eq!(verified.payload(), &revocation);
    }

    #[test]
    #[cfg(feature = "arbitrary")]
    fn sign_verify_round_trip_property() {
        bolero::check!()
            .with_arbitrary::<(Delegation, Revocation<alloc::vec::Vec<u8>>, [u8; 32])>()
            .for_each(|(d, r, seed)| {
                // Re-issue both under the generated key so they are signable.
                let key = SigningKey::from(*seed);
                let issuer = Id::from(&key);
                let d = Delegation { issuer, ..*d };
                let verified = Signed::try_sign(&d, &key)
                    .expect("key is the issuer")
                    .verify()
                    .expect("verifies");
                assert_eq!(verified.payload(), &d);

                let r = Revocation {
                    issuer,
                    ..r.clone()
                };
                let verified = Signed::try_sign(&r, &key)
                    .expect("key is the issuer")
                    .verify()
                    .expect("verifies");
                assert_eq!(verified.payload(), &r);
            });
    }
}
