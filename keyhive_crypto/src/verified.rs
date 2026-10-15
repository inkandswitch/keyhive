//! `Signed<T>` over `Encoded<T>`, and the `Verified<T>` witness.
//!
//! A [`Signed<T>`] carries a value's canonical bytes and a signature over
//! [`message`]: the Keyhive prefix, `T`'s version and kind, then those bytes.
//! The signer is not a separate field: the payload names its own issuer, and
//! [`Signed::verify`] checks the signature against the key the payload names
//! ([`Verifiable::verifying_key`]). A value that claims one issuer and is
//! signed by another does not verify. The digest and the signature cover the
//! same bytes by construction.
//!
//! On the wire a `Signed<T>` is `version ‖ kind ‖ signature ‖ payload`
//! ([`Encode`] and [`Decode`] below). The payload is last and runs to the end
//! of the input, so it needs no length; inside a larger message, frame the
//! whole value.
//!
//! [`Verified<T>`] is a witness that a `Signed<T>` has had its bytes decoded
//! canonically and its signature checked against the decoded issuer. Outside
//! the `unchecked` feature it is built only by [`Signed::verify`], or by
//! [`Verified::sign`] / [`Verified::sign_sync`], which verify what they sign.
//!
//! Signing goes through the signer traits, so the key can live in WebCrypto,
//! an HSM, or a KMS: [`AsyncSigner`] for those, and [`SyncSignerBasic`] for an
//! in-memory key.

use crate::{
    digest::Digest,
    signable::{message, Kinded, Signable},
    signed::SigningError,
    signer::{async_signer::AsyncSigner, sync_signer::SyncSignerBasic},
    verifiable::Verifiable,
};
use alloc::{sync::Arc, vec::Vec};
use core::{
    fmt,
    hash::{Hash, Hasher},
};
use ed25519_dalek::{Signature, VerifyingKey};
use future_form::FutureForm;
use keyhive_codec::{
    encoded::Encoded,
    error::DecodeError,
    traits::{Decode, Encode},
};

const SIGNATURE_LEN: usize = 64;

/// A value's canonical bytes and a signature over them.
///
/// Equality is by encoded bytes _and_ signature. Ed25519 signing as specified
/// in RFC 8032 is deterministic, so one key signing one payload twice yields
/// equal values. A signer that picks its nonce another way produces a
/// different signature that verifies just as well, and so a different
/// `Signed<T>` with the same [`Signed::digest`]. Compare digests or payloads
/// when "same statement" is what is meant.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(bound = ""))]
pub struct Signed<T> {
    encoded: Encoded<T>,
    signature: Signature,
}

impl<T> Signed<T> {
    /// Assemble from parts received over a transport. Nothing is checked;
    /// call [`Signed::verify`] before trusting the payload. To produce a
    /// signed value, use [`Verified::sign`], which signs [`message`].
    pub fn from_parts(encoded: Encoded<T>, signature: Signature) -> Self {
        Signed { encoded, signature }
    }

    /// The canonical bytes the signature covers.
    pub fn encoded(&self) -> &Encoded<T> {
        &self.encoded
    }

    /// The signature over [`message`] of [`Signed::encoded`].
    pub fn signature(&self) -> &Signature {
        &self.signature
    }
}

impl<T: Kinded> Signed<T> {
    /// Content address of the payload: BLAKE3 over the same bytes the signature covers.
    pub fn digest(&self) -> Digest<T> {
        Digest::of(&self.encoded)
    }
}

impl<T: Signable + Verifiable> Signed<T> {
    /// Decode the payload and check the signature against the issuer it names.
    ///
    /// The payload must decode and then re-encode to exactly the received
    /// bytes, so a `Verified<T>` is always canonical. The re-encode check
    /// covers what a decoder cannot vouch for itself, such as a consumer's own
    /// codec for a nested value. The signature is then checked with
    /// `verify_strict`, which rejects the malleable and small-order signatures
    /// that plain `verify` accepts, against `payload.verifying_key()`, never
    /// against a key the transport supplied.
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
                tracing::debug!(digest = %self.digest(), error = %e, "signed value failed to decode");
            })?;
        payload
            .verifying_key()
            .verify_strict(&message::<T>(self.encoded.as_bytes()), &self.signature)
            .map_err(|_| {
                tracing::debug!(digest = %self.digest(), "signature does not verify");
                VerifyError::BadSignature
            })?;
        Ok(Verified {
            payload,
            digest: self.digest(),
            signed: Arc::new(self),
        })
    }
}

impl<T: Kinded> Encode for Signed<T> {
    fn encode_into(&self, out: &mut Vec<u8>) {
        out.push(T::VERSION);
        out.push(T::KIND.to_u8());
        out.extend_from_slice(&self.signature.to_bytes());
        out.extend_from_slice(self.encoded.as_bytes());
    }
}

/// Checks the frame only: the version and kind, and that a signature is
/// there. The payload is kept as received; [`Signed::verify`] decodes it,
/// checks it is canonical, and checks the signature.
impl<T: Kinded> Decode for Signed<T> {
    fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let (version, kind) = header(bytes)?;
        if kind != T::KIND.to_u8() {
            return Err(DecodeError::UnexpectedKind(kind));
        }
        if version != T::VERSION {
            return Err(DecodeError::UnsupportedVersion { kind, version });
        }
        let (signature, payload) = bytes[2..]
            .split_first_chunk::<SIGNATURE_LEN>()
            .ok_or(DecodeError::UnexpectedEnd)?;
        Ok(Signed {
            encoded: Encoded::from_bytes_unchecked(payload.to_vec()),
            signature: Signature::from_bytes(signature),
        })
    }
}

/// A frame's version and kind bytes, for choosing what to decode it as.
pub fn header(bytes: &[u8]) -> Result<(u8, u8), DecodeError> {
    match bytes {
        [version, kind, ..] => Ok((*version, *kind)),
        _ => Err(DecodeError::UnexpectedEnd),
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

impl<T> Hash for Signed<T> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.encoded.hash(state);
        self.signature.to_bytes().hash(state);
    }
}

impl<T: Kinded> fmt::Debug for Signed<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Signed")
            .field("digest", &self.digest())
            .finish_non_exhaustive()
    }
}

/// A [`Signed<T>`] whose bytes decoded canonically and whose signature was
/// checked against the issuer the payload names. Constructed by
/// [`Signed::verify`], [`Verified::sign`] and [`Verified::sign_sync`] (and,
/// under the `unchecked` feature, by `Verified::assume`).
///
/// Shares its [`Signed<T>`] (an [`Arc`]), so a store can hand out the signed
/// form without copying it, and remembers its digest, so identifying it costs
/// no hashing.
pub struct Verified<T> {
    payload: T,
    signed: Arc<Signed<T>>,

    /// `signed.digest()`, computed once at verification: the value is
    /// immutable, and stores look it up on every step of a search.
    digest: Digest<T>,
}

impl<T> Verified<T> {
    /// The decoded payload.
    pub fn payload(&self) -> &T {
        &self.payload
    }

    /// The signed form as received, for forwarding without re-encoding.
    pub fn signed(&self) -> &Arc<Signed<T>> {
        &self.signed
    }

    /// The payload and the signed form it came from.
    pub fn into_parts(self) -> (T, Arc<Signed<T>>) {
        (self.payload, self.signed)
    }

    /// Content address of the payload, computed when it was verified.
    pub fn digest(&self) -> Digest<T> {
        self.digest
    }
}

impl<T: Signable + Verifiable> Verified<T> {
    /// Sign `value` with its issuer's signer, then verify the result.
    ///
    /// The signer may hold its key anywhere (WebCrypto, an HSM, a KMS); it
    /// sees only [`message`]. Verifying the output catches a signer that
    /// returns a bad signature here, not on a peer that receives the value.
    pub async fn sign<F: FutureForm, S: AsyncSigner<F>>(
        value: &T,
        signer: &S,
    ) -> Result<Self, SignError> {
        let (encoded, bytes) = signing_input(value, signer)?;
        let signature = signer.try_sign_bytes_async(&bytes).await?;
        Ok(Signed { encoded, signature }.verify()?)
    }

    /// [`Verified::sign`] for a signer that answers synchronously, such as an
    /// in-memory `ed25519_dalek::SigningKey`.
    pub fn sign_sync<S: SyncSignerBasic + Verifiable>(
        value: &T,
        signer: &S,
    ) -> Result<Self, SignError> {
        let (encoded, bytes) = signing_input(value, signer)?;
        let signature = signer.try_sign_bytes_sync_basic(&bytes)?;
        Ok(Signed { encoded, signature }.verify()?)
    }
}

#[cfg(feature = "unchecked")]
impl<T: Signable> Verified<T> {
    /// Decode without verifying the signature. Test fixtures only: lets a
    /// conformance suite build values without paying for signing.
    pub fn assume(signed: Signed<T>) -> Self {
        let payload = signed.encoded.decode().expect("test fixture must decode");
        Verified {
            payload,
            digest: signed.digest(),
            signed: Arc::new(signed),
        }
    }
}

impl<T: Verifiable> Verifiable for Verified<T> {
    fn verifying_key(&self) -> VerifyingKey {
        self.payload.verifying_key()
    }
}

impl<T: Clone> Clone for Verified<T> {
    fn clone(&self) -> Self {
        Verified {
            payload: self.payload.clone(),
            signed: Arc::clone(&self.signed),
            digest: self.digest,
        }
    }
}

impl<T: Kinded + fmt::Debug> fmt::Debug for Verified<T> {
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

impl<T> Hash for Verified<T> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.signed.hash(state)
    }
}

/// Why [`Verified::sign`] or [`Verified::sign_sync`] failed.
#[derive(Debug, thiserror::Error)]
pub enum SignError {
    /// The signer's key is not the issuer the payload names.
    #[error("signer is not the payload's issuer")]
    NotTheIssuer,

    /// The signer failed.
    #[error(transparent)]
    Signer(#[from] SigningError),

    /// The signer returned a signature that does not verify.
    #[error("signed value does not verify: {0}")]
    Unverifiable(#[from] VerifyError),
}

/// Why a [`Signed<T>`] did not verify.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum VerifyError {
    /// The signature does not match the issuer the payload names and the bytes.
    #[error("signature does not verify")]
    BadSignature,

    /// The bytes are not the canonical encoding of a `T`.
    #[error("payload is not a canonical encoding: {0}")]
    Decode(#[from] DecodeError),
}

/// The canonical encoding of `value`, and the bytes to sign. Refuses a signer
/// that is not the payload's issuer, since `verify` would reject its
/// signature.
fn signing_input<T: Signable + Verifiable, S: Verifiable>(
    value: &T,
    signer: &S,
) -> Result<(Encoded<T>, Vec<u8>), SignError> {
    if signer.verifying_key() != value.verifying_key() {
        return Err(SignError::NotTheIssuer);
    }
    let encoded = value.encode();
    let bytes = message::<T>(encoded.as_bytes());
    Ok((encoded, bytes))
}
