//! `Signed<T>` over `Encoded<T>`, and the `Verified<T>` witness.
//!
//! A [`Signed<T>`] carries a value's canonical bytes and a signature over
//! exactly those bytes. The signer is not a separate field: the payload names
//! its own issuer, and [`Signed::verify`] checks the signature against the key
//! the payload names ([`Verifiable::verifying_key`]). A certificate that claims
//! one issuer and is signed by another does not verify. Nothing re-encodes the
//! payload to check it: the digest and the signature cover the same bytes by
//! construction.
//!
//! [`Verified<T>`] is a witness that a `Signed<T>` has had its bytes decoded
//! canonically and its signature checked against the decoded issuer. Its only
//! public constructor is [`Signed::verify`], so an unchecked certificate cannot
//! reach [`crate::keyline::Keyline::insert`].
//!
//! `keyhive_crypto` has a serde-based `Signed<T>` that `keyhive_core` uses; this
//! type is its `Encoded`-based counterpart.

// TODO(keyhive_types): lift `Signed` and `Verified` out of keyline once beekem migrates.

use crate::id::Id;
use core::fmt;
use ed25519_dalek::{Signature, Signer, SigningKey};
use keyhive_codec::{
    encoded::Encoded,
    error::DecodeError,
    traits::{Decode, Encode},
};
use keyhive_crypto::{digest::Digest, verifiable::Verifiable};

/// A value's canonical bytes and a signature over those bytes.
///
/// Equality is by encoded bytes and signature. Two `Signed<T>` with the same
/// payload and signer are equal: Ed25519 is deterministic.
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

    pub fn signature(&self) -> &Signature {
        &self.signature
    }

    /// Content address of the payload: BLAKE3 over the same bytes the signature covers.
    pub fn digest(&self) -> Digest<T> {
        Digest::of(&self.encoded)
    }
}

impl<T: Encode + Verifiable> Signed<T> {
    /// Encode and sign a value with the key it names as issuer.
    ///
    /// Fails if `key` is not the payload's issuer: a certificate signed by
    /// anyone else would never verify, so refusing to mint it is the only
    /// useful behaviour.
    pub fn try_sign(value: &T, key: &SigningKey) -> Result<Self, SignError> {
        if key.verifying_key() != value.verifying_key() {
            return Err(SignError::NotTheIssuer);
        }
        let encoded = value.encode();
        let signature = key.sign(encoded.as_bytes());
        Ok(Signed { encoded, signature })
    }
}

impl<T: Decode + Verifiable> Signed<T> {
    /// Decode the payload and check the signature against the issuer it names.
    ///
    /// Decoding comes first and rejects non-canonical bytes, so a `Verified<T>`
    /// always re-encodes to exactly the bytes that were signed. The signature
    /// is then checked with `verify_strict`, which rejects the malleable and
    /// small-order signatures that plain `verify` accepts, against
    /// `payload.verifying_key()` — never against a key the transport supplied.
    pub fn verify(self) -> Result<Verified<T>, VerifyError> {
        let payload = self.encoded.decode().inspect_err(|&e| {
            tracing::debug!(digest = %self.digest(), error = %e, "certificate failed to decode");
        })?;
        payload
            .verifying_key()
            .verify_strict(self.encoded.as_bytes(), &self.signature)
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

impl<T> fmt::Debug for Signed<T> {
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
    pub fn payload(&self) -> &T {
        &self.payload
    }

    /// Content address of the payload.
    pub fn digest(&self) -> Digest<T> {
        self.signed.digest()
    }

    /// The certificate as received, for forwarding without re-encoding.
    pub fn signed(&self) -> &Signed<T> {
        &self.signed
    }

    pub fn into_parts(self) -> (T, Signed<T>) {
        (self.payload, self.signed)
    }

    /// Construct without checking anything. Test fixtures only: lets the
    /// conformance suite build certificates without paying for signing.
    #[cfg(any(test, feature = "test_utils"))]
    pub fn assume(signed: Signed<T>) -> Self
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

impl<T: Verifiable> Verified<T> {
    /// The key that signed this certificate, as named by the payload.
    pub fn issuer(&self) -> Id {
        Id::new(self.payload.verifying_key())
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

impl<T: fmt::Debug> fmt::Debug for Verified<T> {
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
        access::Access,
        certificate::Certificate,
        delegation::Delegation,
        test_utils::{id, signing_key},
    };

    fn sample() -> Delegation {
        Delegation::new(id(1), id(2), id(3), Access::Edit)
    }

    #[test]
    fn sign_then_verify() {
        let signed = Signed::try_sign(&sample(), &signing_key(1)).expect("key is the issuer");
        let verified = signed.clone().verify().expect("verifies");
        assert_eq!(verified.payload(), &sample());
        assert_eq!(verified.issuer(), id(1));
        assert_eq!(verified.digest(), signed.digest());
        assert_eq!(verified.signed(), &signed);
    }

    #[test]
    fn signature_and_digest_cover_the_same_bytes() {
        let signed = Signed::try_sign(&sample(), &signing_key(1)).expect("key is the issuer");
        assert_eq!(signed.digest(), Digest::of(&sample().encode()));
    }

    #[test]
    fn deterministic() {
        let a = Signed::try_sign(&sample(), &signing_key(1)).expect("key is the issuer");
        let b = Signed::try_sign(&sample(), &signing_key(1)).expect("key is the issuer");
        assert_eq!(a, b);
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
        let encoded = sample().encode(); // iss = id(1)
        let signature = forger.sign(encoded.as_bytes());
        let forged = Signed::<Delegation>::from_parts(encoded, signature);
        assert_eq!(forged.verify().unwrap_err(), VerifyError::BadSignature);
    }

    #[test]
    fn tampered_bytes_fail() {
        let signed = Signed::try_sign(&sample(), &signing_key(1)).expect("key is the issuer");
        let mut bytes = signed.encoded().clone().into_bytes();
        bytes[40] ^= 1;
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
        let signature = key.sign(&bytes);
        let signed =
            Signed::<Delegation>::from_parts(Encoded::from_bytes_unchecked(bytes), signature);
        assert_eq!(
            signed.verify().unwrap_err(),
            VerifyError::Decode(DecodeError::TrailingBytes)
        );
    }

    #[test]
    fn works_for_certificates() {
        let cert = Certificate::from(sample());
        let verified = Signed::try_sign(&cert, &signing_key(1))
            .expect("key is the issuer")
            .verify()
            .expect("verifies");
        assert_eq!(verified.payload(), &cert);
    }

    #[test]
    #[cfg(feature = "arbitrary")]
    fn sign_verify_round_trip_property() {
        bolero::check!()
            .with_arbitrary::<(Certificate, [u8; 32])>()
            .for_each(|(cert, seed)| {
                // Re-issue the certificate under the generated key so it is signable.
                let key = SigningKey::from(*seed);
                let iss = Id::new(key.verifying_key());
                let cert = match cert {
                    Certificate::Delegation(d) => Certificate::Delegation(Delegation { iss, ..*d }),
                    Certificate::Revocation(r) => {
                        Certificate::Revocation(crate::revocation::Revocation { iss, ..*r })
                    }
                };
                let verified = Signed::try_sign(&cert, &key)
                    .expect("key is the issuer")
                    .verify()
                    .expect("verifies");
                assert_eq!(verified.payload(), &cert);
                assert_eq!(verified.issuer(), iss);
            });
    }
}
