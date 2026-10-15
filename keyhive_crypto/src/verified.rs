//! `Signed<T>` over `Encoded<T>`, and the `Verified<T>` witness.
//!
//! A [`Signed<T>`] is a signed statement: its issuer, the canonical bytes of
//! its payload, and the issuer's signature over [`message`] (the frame without
//! its signature). Who signed is part of the
//! envelope, the same for every type, so [`Signed::verify`] always checks the
//! signature against the envelope's issuer, and a payload never needs to name
//! one. The digest and the signature cover the same bytes by construction.
//!
//! On the wire a `Signed<T>` is its frame,
//! `"KH" ‖ kind ‖ version ‖ issuer ‖ payload_len ‖ payload ‖ signature`
//! ([`Encode`], [`Decode`] and [`StreamDecode`] below). The length makes the
//! frame self-delimiting, so frames can be written back to back.
//!
//! [`Verified<T>`] is a witness that a `Signed<T>` has had its bytes decoded
//! canonically and its signature checked against its issuer. Outside the
//! `unchecked` feature it is built only by [`Signed::verify`], or by
//! [`Verified::sign`] / [`Verified::sign_sync`], which verify what they sign.
//!
//! Signing goes through the signer traits, so the key can live in WebCrypto,
//! an HSM, or a KMS: [`AsyncSigner`] for those, and [`SyncSignerBasic`] for an
//! in-memory key.

use crate::{
    digest::Digest,
    id::{Id, InvalidId},
    signable::{head, message, Kinded, Signable, TAG},
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
    traits::{decode_exact, Decode, Encode, StreamDecode},
};

const SIGNATURE_LEN: usize = 64;

/// The two-byte tag, then the kind and version bytes.
const HEADER_LEN: usize = 4;

/// A signed statement: its issuer, its payload's canonical bytes, and the
/// issuer's signature over them.
///
/// Equality is by issuer, encoded bytes _and_ signature. Ed25519 signing as
/// specified in RFC 8032 is deterministic, so one key signing one payload
/// twice yields equal values. A signer that picks its nonce another way
/// produces a different signature that verifies just as well, and so a
/// different `Signed<T>` with the same [`Signed::digest`]. Compare digests
/// when "same statement" is what is meant.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(bound = ""))]
pub struct Signed<T> {
    issuer: Id,
    encoded: Encoded<T>,
    signature: Signature,
}

impl<T> Signed<T> {
    /// Assemble from parts received over a transport. Nothing is checked;
    /// call [`Signed::verify`] before trusting the payload. To produce a
    /// signed statement, use [`Verified::sign`].
    pub fn from_parts(issuer: Id, encoded: Encoded<T>, signature: Signature) -> Self {
        Signed {
            issuer,
            encoded,
            signature,
        }
    }

    /// Who signed: the key the signature is checked against.
    pub fn issuer(&self) -> Id {
        self.issuer
    }

    /// The payload's canonical bytes.
    pub fn encoded(&self) -> &Encoded<T> {
        &self.encoded
    }

    /// The issuer's signature over [`message`].
    pub fn signature(&self) -> &Signature {
        &self.signature
    }
}

impl<T: Kinded> Signed<T> {
    /// The statement's identity: BLAKE3 over the same bytes the signature
    /// covers.
    pub fn digest(&self) -> Digest<T> {
        Digest::of(&self.issuer, &self.encoded)
    }
}

impl<T: Signable> Signed<T> {
    /// Decode the payload and check the signature against the issuer.
    ///
    /// The payload must decode and then re-encode to exactly the received
    /// bytes, so a `Verified<T>` is always canonical. The re-encode check
    /// covers what a decoder cannot vouch for itself, such as a consumer's own
    /// codec for a nested value. The signature is then checked with
    /// `verify_strict`, which rejects the malleable and small-order signatures
    /// that plain `verify` accepts.
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
        self.issuer
            .verifying_key()
            .verify_strict(
                &message::<T>(&self.issuer, self.encoded.as_bytes()),
                &self.signature,
            )
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
        let payload = self.encoded.as_bytes();
        out.extend_from_slice(&head::<T>(&self.issuer, payload.len()));
        out.extend_from_slice(payload);
        out.extend_from_slice(&self.signature.to_bytes());
    }
}

impl<T: Kinded> Decode for Signed<T> {
    fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        decode_exact(bytes)
    }
}

/// Checks the frame only: the tag, kind and version, a valid issuer, and that
/// the payload and a signature are there. The payload is kept as received;
/// [`Signed::verify`] decodes it, checks it is canonical, and checks the
/// signature.
impl<T: Kinded> StreamDecode for Signed<T> {
    fn decode_next(bytes: &[u8]) -> Result<(Self, &[u8]), DecodeError> {
        let (kind, version) = header(bytes)?;
        if kind != T::KIND.to_u8() {
            return Err(DecodeError::UnexpectedKind(kind));
        }
        if version != T::VERSION {
            return Err(DecodeError::UnsupportedVersion { kind, version });
        }
        let (issuer, rest) = Id::decode_next(&bytes[HEADER_LEN..]).map_err(|e| match e {
            DecodeError::InvalidField(_) => DecodeError::InvalidField("issuer"),
            other => other,
        })?;
        let (len, rest) = u64::decode_next(rest)?;
        let len = usize::try_from(len).map_err(|_| DecodeError::UnexpectedEnd)?;
        // Checked: on a 32-bit target a declared length near the maximum
        // overflows `len + SIGNATURE_LEN`.
        let framed = len
            .checked_add(SIGNATURE_LEN)
            .ok_or(DecodeError::UnexpectedEnd)?;
        if rest.len() < framed {
            return Err(DecodeError::UnexpectedEnd);
        }
        let (payload, rest) = rest.split_at(len);
        let (signature, rest) = rest
            .split_first_chunk::<SIGNATURE_LEN>()
            .expect("the payload and signature are there, checked above");
        Ok((
            Signed {
                issuer,
                encoded: Encoded::from_bytes_unchecked(payload.to_vec()),
                signature: Signature::from_bytes(signature),
            },
            rest,
        ))
    }
}

/// A frame's kind and version bytes, after checking its `KH` tag, for choosing
/// what to decode it as.
pub fn header(bytes: &[u8]) -> Result<(u8, u8), DecodeError> {
    match bytes {
        [k, h, kind, version, ..] if [*k, *h] == TAG => Ok((*kind, *version)),
        [k, h, ..] if [*k, *h] != TAG => Err(DecodeError::NotKeyhive),
        [k] if *k != TAG[0] => Err(DecodeError::NotKeyhive),
        _ => Err(DecodeError::UnexpectedEnd),
    }
}

// Manual impls: derives would add `T: Clone` / `T: PartialEq` bounds that the
// phantom-typed `Encoded<T>` does not need.
impl<T> Clone for Signed<T> {
    fn clone(&self) -> Self {
        Signed {
            issuer: self.issuer,
            encoded: self.encoded.clone(),
            signature: self.signature,
        }
    }
}

impl<T> PartialEq for Signed<T> {
    fn eq(&self, other: &Self) -> bool {
        self.issuer == other.issuer
            && self.encoded == other.encoded
            && self.signature == other.signature
    }
}

impl<T> Eq for Signed<T> {}

impl<T> Hash for Signed<T> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.issuer.hash(state);
        self.encoded.hash(state);
        self.signature.to_bytes().hash(state);
    }
}

impl<T: Kinded> fmt::Debug for Signed<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Signed")
            .field("issuer", &self.issuer)
            .field("digest", &self.digest())
            .finish_non_exhaustive()
    }
}

/// A [`Signed<T>`] whose bytes decoded canonically and whose signature was
/// checked against its issuer. Constructed by [`Signed::verify`],
/// [`Verified::sign`] and [`Verified::sign_sync`] (and, under the `unchecked`
/// feature, by `Verified::assume`).
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

    /// Who signed it.
    pub fn issuer(&self) -> Id {
        self.signed.issuer
    }

    /// The signed form as received, for forwarding without re-encoding.
    pub fn signed(&self) -> &Arc<Signed<T>> {
        &self.signed
    }

    /// The payload and the signed form it came from.
    pub fn into_parts(self) -> (T, Arc<Signed<T>>) {
        (self.payload, self.signed)
    }

    /// The statement's identity, computed when it was verified.
    pub fn digest(&self) -> Digest<T> {
        self.digest
    }
}

impl<T: Signable> Verified<T> {
    /// Sign `value` as `signer`, then verify the result.
    ///
    /// The issuer is the signer's key. The signer may hold its key anywhere
    /// (WebCrypto, an HSM, a KMS); it sees only [`message`]. Verifying the
    /// output catches a signer that returns a bad signature here, not on a
    /// peer that receives the statement.
    pub async fn sign<F: FutureForm, S: AsyncSigner<F>>(
        value: &T,
        signer: &S,
    ) -> Result<Self, SignError> {
        let (issuer, encoded, bytes) = signing_input(value, signer)?;
        let signature = signer.try_sign_bytes_async(&bytes).await?;
        Ok(Signed::from_parts(issuer, encoded, signature).verify()?)
    }

    /// [`Verified::sign`] for a signer that answers synchronously, such as an
    /// in-memory `ed25519_dalek::SigningKey`.
    pub fn sign_sync<S: SyncSignerBasic + Verifiable>(
        value: &T,
        signer: &S,
    ) -> Result<Self, SignError> {
        let (issuer, encoded, bytes) = signing_input(value, signer)?;
        let signature = signer.try_sign_bytes_sync_basic(&bytes)?;
        Ok(Signed::from_parts(issuer, encoded, signature).verify()?)
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

impl<T> Verifiable for Verified<T> {
    fn verifying_key(&self) -> VerifyingKey {
        self.signed.issuer.verifying_key()
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
            .field("issuer", &self.issuer())
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
    /// The signer's verifying key cannot be an issuer: it is not a canonical
    /// curve point of large order.
    #[error("signer's key cannot be an issuer: {0}")]
    InvalidIssuer(#[from] InvalidId),

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
    /// The signature does not match the issuer and the bytes.
    #[error("signature does not verify")]
    BadSignature,

    /// The bytes are not the canonical encoding of a `T`.
    #[error("payload is not a canonical encoding: {0}")]
    Decode(#[from] DecodeError),
}

/// The issuer (the signer's key), the canonical encoding of `value`, and the
/// bytes to sign.
fn signing_input<T: Signable, S: Verifiable>(
    value: &T,
    signer: &S,
) -> Result<(Id, Encoded<T>, Vec<u8>), SignError> {
    let issuer = Id::try_from(signer.verifying_key())?;
    let encoded = value.encode();
    let bytes = message::<T>(&issuer, encoded.as_bytes());
    Ok((issuer, encoded, bytes))
}
