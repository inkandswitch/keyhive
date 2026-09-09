//! `Signed<T>` over `Encoded<T>`, and the `Verified<T>` witness.
//!
//! A [`Signed<T>`] carries a value's canonical bytes, the signer, and a
//! signature over exactly those bytes. Nothing re-encodes the payload to check
//! it: the digest and the signature cover the same bytes by construction.
//!
//! [`Verified<T>`] is a witness that a `Signed<T>` has had its signature checked
//! and its bytes decoded canonically. Its only public constructor is
//! [`Signed::verify`], so an unchecked certificate cannot reach
//! [`crate::keyline::Keyline::insert`].
//!
//! `keyhive_crypto` has an older serde-based `Signed<T>` that `keyhive_core`
//! still uses. The two unify when the bespoke codec lands.

// TODO(keyhive_types): lift `Signed` and `Verified` out of keyline once beekem migrates.

use crate::id::Id;
use core::fmt;
use ed25519_dalek::{Signature, Signer, SigningKey};
use keyhive_codec::{
    encoded::Encoded,
    error::DecodeError,
    traits::{Decode, Encode},
};
use keyhive_crypto::digest::Digest;

/// A value's canonical bytes, the signer, and a signature over those bytes.
///
/// Equality is by encoded bytes, issuer, and signature. Two `Signed<T>` with
/// the same payload and signer are equal: Ed25519 is deterministic.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Signed<T> {
    encoded: Encoded<T>,
    issuer: Id,
    signature: Signature,
}

impl<T> Signed<T> {
    /// Assemble from parts received over a transport. Nothing is checked;
    /// call [`Signed::verify`] before trusting the payload.
    pub fn from_parts(encoded: Encoded<T>, issuer: Id, signature: Signature) -> Self {
        Signed {
            encoded,
            issuer,
            signature,
        }
    }

    pub fn encoded(&self) -> &Encoded<T> {
        &self.encoded
    }

    pub fn issuer(&self) -> Id {
        self.issuer
    }

    pub fn signature(&self) -> &Signature {
        &self.signature
    }

    /// Content address of the payload: BLAKE3 over the same bytes the signature covers.
    pub fn digest(&self) -> Digest<T> {
        Digest::of(&self.encoded)
    }
}

impl<T: Encode> Signed<T> {
    /// Encode and sign a value.
    pub fn sign(value: &T, key: &SigningKey) -> Self {
        let encoded = value.encode();
        let signature = key.sign(encoded.as_bytes());
        Signed {
            encoded,
            issuer: Id::new(key.verifying_key()),
            signature,
        }
    }
}

impl<T: Decode> Signed<T> {
    /// Check the signature against the issuer and decode the payload.
    ///
    /// Uses `verify_strict`, which rejects the malleable and small-order
    /// signatures that plain `verify` accepts. Decoding rejects non-canonical
    /// bytes, so a `Verified<T>` always re-encodes to exactly the bytes that
    /// were signed.
    pub fn verify(self) -> Result<Verified<T>, VerifyError> {
        self.issuer
            .verifying_key()
            .verify_strict(self.encoded.as_bytes(), &self.signature)
            .map_err(|_| VerifyError::BadSignature)?;
        let payload = self.encoded.decode()?;
        let digest = self.digest();
        Ok(Verified {
            payload,
            digest,
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
            issuer: self.issuer,
            signature: self.signature,
        }
    }
}

impl<T> PartialEq for Signed<T> {
    fn eq(&self, other: &Self) -> bool {
        self.encoded == other.encoded
            && self.issuer == other.issuer
            && self.signature == other.signature
    }
}

impl<T> Eq for Signed<T> {}

impl<T> core::hash::Hash for Signed<T> {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.encoded.hash(state);
        self.issuer.hash(state);
        self.signature.to_bytes().hash(state);
    }
}

impl<T> fmt::Debug for Signed<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Signed")
            .field("issuer", &self.issuer)
            .field("digest", &self.digest())
            .finish_non_exhaustive()
    }
}

/// A [`Signed<T>`] whose signature has been checked and whose bytes decoded
/// canonically. Constructed only by [`Signed::verify`].
pub struct Verified<T> {
    payload: T,
    digest: Digest<T>,
    signed: Signed<T>,
}

impl<T> Verified<T> {
    pub fn payload(&self) -> &T {
        &self.payload
    }

    pub fn digest(&self) -> Digest<T> {
        self.digest
    }

    pub fn issuer(&self) -> Id {
        self.signed.issuer
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
        let digest = signed.digest();
        Verified {
            payload,
            digest,
            signed,
        }
    }
}

impl<T: Clone> Clone for Verified<T> {
    fn clone(&self) -> Self {
        Verified {
            payload: self.payload.clone(),
            digest: self.digest,
            signed: self.signed.clone(),
        }
    }
}

impl<T: fmt::Debug> fmt::Debug for Verified<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Verified")
            .field("payload", &self.payload)
            .field("issuer", &self.signed.issuer)
            .field("digest", &self.digest)
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

/// Why a [`Signed<T>`] did not verify.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyError {
    /// The signature does not match the issuer and bytes.
    BadSignature,

    /// The bytes are not the canonical encoding of a `T`.
    Decode(DecodeError),
}

impl From<DecodeError> for VerifyError {
    fn from(e: DecodeError) -> Self {
        VerifyError::Decode(e)
    }
}

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VerifyError::BadSignature => f.write_str("signature does not verify"),
            VerifyError::Decode(e) => write!(f, "payload does not decode: {e}"),
        }
    }
}

impl core::error::Error for VerifyError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            VerifyError::BadSignature => None,
            VerifyError::Decode(e) => Some(e),
        }
    }
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
        let signed = Signed::sign(&sample(), &signing_key(1));
        let verified = signed.clone().verify().expect("verifies");
        assert_eq!(verified.payload(), &sample());
        assert_eq!(verified.issuer(), id(1));
        assert_eq!(verified.digest(), signed.digest());
        assert_eq!(verified.signed(), &signed);
    }

    #[test]
    fn signature_and_digest_cover_the_same_bytes() {
        let signed = Signed::sign(&sample(), &signing_key(1));
        assert_eq!(signed.digest(), Digest::of(&sample().encode()));
    }

    #[test]
    fn deterministic() {
        let a = Signed::sign(&sample(), &signing_key(1));
        let b = Signed::sign(&sample(), &signing_key(1));
        assert_eq!(a, b);
    }

    #[test]
    fn wrong_signer_fails() {
        let signed = Signed::sign(&sample(), &signing_key(1));
        let forged = Signed::from_parts(signed.encoded().clone(), id(2), *signed.signature());
        assert_eq!(forged.verify().unwrap_err(), VerifyError::BadSignature);
    }

    #[test]
    fn tampered_bytes_fail() {
        let signed = Signed::sign(&sample(), &signing_key(1));
        let mut bytes = signed.encoded().clone().into_bytes();
        bytes[40] ^= 1;
        let tampered = Signed::<Delegation>::from_parts(
            Encoded::from_bytes_unchecked(bytes),
            signed.issuer(),
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
        let signed = Signed::<Delegation>::from_parts(
            Encoded::from_bytes_unchecked(bytes),
            id(1),
            signature,
        );
        assert_eq!(
            signed.verify().unwrap_err(),
            VerifyError::Decode(DecodeError::TrailingBytes)
        );
    }

    #[test]
    fn works_for_certificates() {
        let cert = Certificate::from(sample());
        let verified = Signed::sign(&cert, &signing_key(1))
            .verify()
            .expect("verifies");
        assert_eq!(verified.payload(), &cert);
    }

    #[test]
    fn sign_verify_round_trip_property() {
        bolero::check!()
            .with_arbitrary::<(Certificate, [u8; 32])>()
            .for_each(|(cert, seed)| {
                let key = SigningKey::from(*seed);
                let verified = Signed::sign(cert, &key).verify().expect("verifies");
                assert_eq!(verified.payload(), cert);
                assert_eq!(verified.issuer(), Id::new(key.verifying_key()));
            });
    }
}
