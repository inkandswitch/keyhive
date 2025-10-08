//! Wrap data in signatures.

use super::verifiable::Verifiable;
use crate::principal::identifier::Identifier;
use derivative::Derivative;
use dupe::Dupe;
use ed25519_dalek::Verifier;
use serde::{Deserialize, Serialize};
use std::{
    cmp::Ordering,
    fmt::Debug,
    hash::{Hash, Hasher},
};
use thiserror::Error;
use tracing::instrument;

/// A wrapper to add a signature and signer information to an arbitrary payload.
#[derive(Clone, Derivative, Serialize, Deserialize)]
#[derivative(Debug, PartialEq, Eq, Hash)]
pub struct Signed<T: Serialize + Debug> {
    /// The data that was signed.
    #[derivative(PartialEq = "ignore", Hash = "ignore")]
    pub(crate) payload: T,

    /// The verifying key of the signer (for verifying the signature).
    #[derivative(Debug(format_with = "format_key"))]
    pub(crate) issuer: ed25519_dalek::VerifyingKey,

    /// The signature of the payload, which can be verified by the `verifying_key`.
    #[derivative(Hash(hash_with = "hash_signature"))]
    #[derivative(Debug(format_with = "format_sig"))]
    pub(crate) signature: ed25519_dalek::Signature,
}

fn format_sig(sig: &ed25519_dalek::Signature, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    crate::util::hex::bytes_as_hex(sig.to_bytes().iter(), f)
}

fn format_key(
    key: &ed25519_dalek::VerifyingKey,
    f: &mut std::fmt::Formatter<'_>,
) -> std::fmt::Result {
    crate::util::hex::bytes_as_hex(key.as_bytes().iter(), f)
}

fn hash_signature<H: Hasher>(signature: &ed25519_dalek::Signature, state: &mut H) {
    signature.to_bytes().hash(state);
}

impl<T: Serialize + Debug> Signed<T> {
    /// Getter for the payload.
    pub fn payload(&self) -> &T {
        &self.payload
    }

    /// Getter for the [`Identifier`] of the signer.
    pub fn id(&self) -> Identifier {
        self.verifying_key().into()
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
    /// # Examples
    ///
    /// ```
    /// # use keyhive_core::crypto::signed::Signed;
    /// # use keyhive_core::crypto::signer::memory::MemorySigner;
    /// # use keyhive_core::crypto::signer::sync_signer::SyncSigner;
    /// #
    /// let signer = MemorySigner::generate(&mut rand::rngs::OsRng);
    /// let signed = signer.try_sign_sync("Hello, world!").unwrap();
    /// assert!(signed.try_verify().is_ok());
    /// ```
    #[instrument]
    pub fn try_verify(&self) -> Result<(), VerificationError> {
        let buf: Vec<u8> = bincode::serialize(&self.payload)?;
        Ok(self
            .verifying_key()
            .verify(buf.as_slice(), &self.signature)?)
    }

    /// Map over the paylaod of the signed data.
    ///
    /// This is primarily useful if you need to
    pub(crate) fn map<U: Serialize + Debug, F: FnOnce(T) -> U>(self, f: F) -> Signed<U> {
        Signed {
            payload: f(self.payload),
            issuer: self.issuer,
            signature: self.signature,
        }
    }
}

#[cfg(any(test, feature = "arbitrary"))]
mod arb {
    use signature::SignerMut;
    use std::fmt::Debug;

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

impl<T: Dupe + Serialize + Debug> Dupe for Signed<T> {
    fn dupe(&self) -> Self {
        Signed {
            payload: self.payload.dupe(),
            issuer: self.issuer,
            signature: self.signature,
        }
    }
}

impl<T: Serialize + Debug> Verifiable for Signed<T> {
    fn verifying_key(&self) -> ed25519_dalek::VerifyingKey {
        self.issuer
    }
}

#[derive(Debug, Error)]
pub enum VerificationError {
    #[error("Signature verification failed: {0}")]
    SignatureVerificationFailed(#[from] signature::Error),

    #[error("Payload deserialization failed: {0}")]
    SerializationFailed(#[from] bincode::Error),
}

#[derive(Debug, Error)]
pub enum SigningError {
    #[error("Signing failed: {0}")]
    SigningFailed(#[from] ed25519_dalek::SignatureError),

    #[error("Payload serialization failed: {0}")]
    SerializationFailed(#[from] bincode::Error),
}
