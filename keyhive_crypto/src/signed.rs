//! Wrap data in signatures.

use super::{digest::Digest, verifiable::Verifiable};
#[cfg(feature = "std")]
use alloc::vec::Vec;
use core::{
    cmp::Ordering,
    fmt::{self, Debug},
    hash::{Hash, Hasher},
};
#[cfg(feature = "std")]
use dupe::Dupe;
#[cfg(feature = "std")]
use ed25519_dalek::Verifier;
use serde::{Deserialize, Serialize};
#[cfg(feature = "std")]
use std::sync::OnceLock;
#[cfg(feature = "std")]
use thiserror::Error;
#[cfg(feature = "std")]
use tracing::instrument;

/// A wrapper to add a signature and signer information to an arbitrary payload.
#[derive(Serialize, Deserialize)]
pub struct Signed<T: Serialize + Debug> {
    /// The data that was signed.
    pub payload: T,

    /// The verifying key of the signer (for verifying the signature).
    pub issuer: ed25519_dalek::VerifyingKey,

    /// The signature of the payload, which can be verified by the `verifying_key`.
    pub signature: ed25519_dalek::Signature,

    /// Digest hash (computed eagerly on construction).
    #[cfg(feature = "std")]
    #[serde(skip)]
    digest_hash: OnceLock<[u8; 32]>,
}

impl<T: Serialize + Debug> Debug for Signed<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Signed")
            .field("payload", &self.payload)
            .field("issuer", &format_args!("{}", HexKey(&self.issuer)))
            .field("signature", &format_args!("{}", HexSig(&self.signature)))
            .finish()
    }
}

struct HexSig<'a>(&'a ed25519_dalek::Signature);

impl fmt::Display for HexSig<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        crate::hex::bytes_as_hex(self.0.to_bytes().iter(), f)
    }
}

struct HexKey<'a>(&'a ed25519_dalek::VerifyingKey);

impl fmt::Display for HexKey<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        crate::hex::bytes_as_hex(self.0.as_bytes().iter(), f)
    }
}

/// Equality is based on issuer + signature only (payload is ignored).
impl<T: Serialize + Debug> PartialEq for Signed<T> {
    fn eq(&self, other: &Self) -> bool {
        self.issuer == other.issuer && self.signature == other.signature
    }
}

impl<T: Serialize + Debug> Eq for Signed<T> {}

/// Hash is based on issuer + signature bytes (payload is ignored).
impl<T: Serialize + Debug> Hash for Signed<T> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.issuer.hash(state);
        self.signature.to_bytes().hash(state);
    }
}

impl<T: Clone + Serialize + Debug> Clone for Signed<T> {
    fn clone(&self) -> Self {
        #[cfg(feature = "std")]
        let digest_hash = {
            let lock = OnceLock::new();
            if let Some(digest) = self.digest_hash.get() {
                let _ = lock.set(*digest);
            }
            lock
        };
        Self {
            payload: self.payload.clone(),
            issuer: self.issuer,
            signature: self.signature,
            #[cfg(feature = "std")]
            digest_hash,
        }
    }
}

impl<T: Serialize + Debug> Signed<T> {
    /// Create a new [`Signed`]. The digest hash will be computed eagerly.
    pub fn new(
        payload: T,
        issuer: ed25519_dalek::VerifyingKey,
        signature: ed25519_dalek::Signature,
    ) -> Self {
        let signed = Self {
            payload,
            issuer,
            signature,
            #[cfg(feature = "std")]
            digest_hash: OnceLock::new(),
        };
        #[cfg(feature = "std")]
        let _ = signed.digest();
        signed
    }

    /// Getter for the payload.
    pub fn payload(&self) -> &T {
        &self.payload
    }

    /// Get the digest, computing it if necessary.
    #[cfg(feature = "std")]
    pub fn digest(&self) -> Digest<Self> {
        let bytes = self.digest_hash.get_or_init(|| {
            let serialized = bincode::serialize(&self).expect("unable to serialize to bytes");
            let hash = blake3::hash(&serialized);
            hash.into()
        });
        Digest::from(*bytes)
    }

    /// Getter for the verifying key of the signer.
    pub fn issuer(&self) -> &ed25519_dalek::VerifyingKey {
        &self.issuer
    }

    /// Getter for the verifying key of the signer.
    pub fn signature(&self) -> &ed25519_dalek::Signature {
        &self.signature
    }

    /// Verify the payload and signature against the issuer's verifying key.
    ///
    /// Requires the `std` feature (uses [`bincode`] for serialization).
    ///
    /// # Examples
    ///
    /// ```
    /// # use keyhive_crypto::{
    /// #     signed::Signed,
    /// #     signer::{memory::MemorySigner, sync_signer::SyncSigner},
    /// # };
    /// #
    /// let signer = MemorySigner::generate(&mut rand::rngs::OsRng);
    /// let signed = signer.try_sign_sync("Hello, world!").unwrap();
    /// assert!(signed.try_verify().is_ok());
    /// ```
    #[cfg(feature = "std")]
    #[instrument(skip(self))]
    pub fn try_verify(&self) -> Result<(), VerificationError> {
        let buf: Vec<u8> = bincode::serialize(&self.payload)?;
        Ok(self
            .verifying_key()
            .verify(buf.as_slice(), &self.signature)?)
    }

    /// Map over the payload of the signed data.
    ///
    /// The digest hash is not preserved since the payload type changes.
    pub fn map<U: Serialize + Debug, F: FnOnce(T) -> U>(self, f: F) -> Signed<U> {
        Signed {
            payload: f(self.payload),
            issuer: self.issuer,
            signature: self.signature,
            #[cfg(feature = "std")]
            digest_hash: OnceLock::new(),
        }
    }
}

#[cfg(all(feature = "std", any(test, feature = "arbitrary")))]
mod arb {
    use core::fmt::Debug;
    use signature::SignerMut;

    fn arb_signing_key(
        unstructured: &mut arbitrary::Unstructured,
    ) -> arbitrary::Result<ed25519_dalek::SigningKey> {
        let bytes = unstructured.bytes(32)?;
        let arr = <[u8; 32]>::try_from(bytes).unwrap();
        Ok(ed25519_dalek::SigningKey::from_bytes(&arr))
    }

    impl<'a, T: serde::Serialize + Debug + arbitrary::Arbitrary<'a>> arbitrary::Arbitrary<'a>
        for super::Signed<T>
    {
        fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
            let payload = T::arbitrary(u)?;
            let mut key = arb_signing_key(u)?;
            let encoded = bincode::serialize(&payload).unwrap();
            let signature = key.sign(&encoded);
            Ok(super::Signed {
                payload,
                issuer: key.verifying_key(),
                signature,
                digest_hash: std::sync::OnceLock::new(),
            })
        }
    }
}

impl<T: Serialize + PartialOrd + Debug> PartialOrd for Signed<T> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        match self
            .verifying_key()
            .as_bytes()
            .partial_cmp(other.verifying_key().as_bytes())
        {
            Some(Ordering::Equal) => match self
                .signature
                .to_bytes()
                .partial_cmp(&other.signature.to_bytes())
            {
                Some(Ordering::Equal) => self.payload.partial_cmp(&other.payload),
                unequal => unequal,
            },
            unequal => unequal,
        }
    }
}

impl<T: Serialize + Ord + Debug> Ord for Signed<T> {
    fn cmp(&self, other: &Self) -> Ordering {
        match self
            .verifying_key()
            .as_bytes()
            .cmp(other.verifying_key().as_bytes())
        {
            Ordering::Equal => match self.signature.to_bytes().cmp(&other.signature.to_bytes()) {
                Ordering::Equal => self.payload.cmp(&other.payload),
                unequal => unequal,
            },
            unequal => unequal,
        }
    }
}

#[cfg(feature = "std")]
impl<T: Dupe + Serialize + Debug> Dupe for Signed<T> {
    fn dupe(&self) -> Self {
        let digest_hash = OnceLock::new();
        if let Some(digest) = self.digest_hash.get() {
            let _ = digest_hash.set(*digest);
        }
        Signed {
            payload: self.payload.dupe(),
            issuer: self.issuer,
            signature: self.signature,
            digest_hash,
        }
    }
}

impl<T: Serialize + Debug> Verifiable for Signed<T> {
    fn verifying_key(&self) -> ed25519_dalek::VerifyingKey {
        self.issuer
    }
}

#[cfg(feature = "std")]
#[derive(Debug, Error)]
pub enum VerificationError {
    #[error("Signature verification failed: {0}")]
    SignatureVerificationFailed(#[from] signature::Error),

    #[error("Payload deserialization failed: {0}")]
    SerializationFailed(#[from] bincode::Error),
}

#[cfg(not(feature = "std"))]
#[derive(Debug)]
pub enum VerificationError {
    SignatureVerificationFailed(signature::Error),
}

#[cfg(not(feature = "std"))]
impl fmt::Display for VerificationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SignatureVerificationFailed(e) => {
                write!(f, "Signature verification failed: {e}")
            }
        }
    }
}

#[cfg(not(feature = "std"))]
impl From<signature::Error> for VerificationError {
    fn from(e: signature::Error) -> Self {
        Self::SignatureVerificationFailed(e)
    }
}

#[cfg(feature = "std")]
#[derive(Debug, Error)]
pub enum SigningError {
    #[error("Signing failed: {0}")]
    SigningFailed(#[from] ed25519_dalek::SignatureError),

    #[error("Payload serialization failed: {0}")]
    SerializationFailed(#[from] bincode::Error),
}

#[cfg(not(feature = "std"))]
#[derive(Debug)]
pub enum SigningError {
    SigningFailed(ed25519_dalek::SignatureError),
}

#[cfg(not(feature = "std"))]
impl fmt::Display for SigningError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SigningFailed(e) => write!(f, "Signing failed: {e}"),
        }
    }
}

#[cfg(not(feature = "std"))]
impl From<ed25519_dalek::SignatureError> for SigningError {
    fn from(e: ed25519_dalek::SignatureError) -> Self {
        Self::SigningFailed(e)
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        digest::Digest,
        signer::{memory::MemorySigner, sync_signer::SyncSigner},
    };
    use alloc::string::ToString;
    use rand::rngs::OsRng;

    #[test]
    fn test_memoized_digest_equals_computed_digest() {
        let mut csprng = OsRng;
        let signer = MemorySigner::generate(&mut csprng);
        let payload = "test payload".to_string();
        let signed = signer.try_sign_sync(payload).unwrap();
        let memoized = signed.digest();
        let computed = Digest::hash(&signed);
        assert_eq!(
            memoized.raw.as_bytes(),
            computed.raw.as_bytes(),
            "memoized_digest() should have the same output as Digest::hash()"
        );
    }
}
