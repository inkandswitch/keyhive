//! Wrap data in signatures.

use crate::principal::identifier::Identifier;
use ed25519_dalek::{Signer, Verifier};
use serde::{Deserialize, Serialize};
use std::{
    cmp::Ordering,
    hash::{Hash, Hasher},
};
use thiserror::Error;

/// A wrapper to add a signature and signer information to an arbitrary payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signed<T: Serialize> {
    /// The data that was signed.
    payload: T,

    /// The verifying key of the signer (for verifying the signature).
    verifying_key: ed25519_dalek::VerifyingKey,

    /// The signature of the payload, which can be verified by the `verifying_key`.
    signature: ed25519_dalek::Signature,
}

impl<T: Serialize> Signed<T> {
    pub fn try_sign(payload: T, signer: &ed25519_dalek::SigningKey) -> Result<Self, SigningError> {
        let mut payload_bytes: Vec<u8> = vec![];
        ciborium::into_writer(&payload, &mut payload_bytes)?;

        Ok(Signed {
            payload,
            verifying_key: signer.verifying_key(),
            signature: signer.try_sign(payload_bytes.as_slice())?,
        })
    }

    pub fn payload(&self) -> &T {
        &self.payload
    }

    pub fn verifying_key(&self) -> &ed25519_dalek::VerifyingKey {
        &self.verifying_key
    }

    pub fn id(&self) -> Identifier {
        self.verifying_key.into()
    }

    pub fn signature(&self) -> &ed25519_dalek::Signature {
        &self.signature
    }

    pub fn try_verify(&self) -> Result<(), VerificationError> {
        let mut buf = vec![];
        ciborium::into_writer(&self.payload, &mut buf)?;
        Ok(self.verifying_key.verify(buf.as_slice(), &self.signature)?)
    }

    pub fn map<U: Serialize, F: FnOnce(T) -> U>(self, f: F) -> Signed<U> {
        Signed {
            payload: f(self.payload),
            verifying_key: self.verifying_key,
            signature: self.signature,
        }
    }
}

impl<T: Serialize + PartialOrd> PartialOrd for Signed<T> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        match self
            .verifying_key
            .as_bytes()
            .partial_cmp(other.verifying_key.as_bytes())
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

impl<T: Serialize + Ord> Ord for Signed<T> {
    fn cmp(&self, other: &Self) -> Ordering {
        match self
            .verifying_key
            .as_bytes()
            .cmp(other.verifying_key.as_bytes())
        {
            Ordering::Equal => match self.signature.to_bytes().cmp(&other.signature.to_bytes()) {
                Ordering::Equal => self.payload.cmp(&other.payload),
                unequal => unequal,
            },
            unequal => unequal,
        }
    }
}

// FIXME test
impl<T: Serialize> Hash for Signed<T> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.verifying_key.as_bytes().hash(state);
        self.signature.to_bytes().hash(state);

        let mut buf = vec![];
        ciborium::into_writer(&self.payload, &mut buf)
            .expect("unable to serialize payload for hashing");
        buf.hash(state);
    }
}

#[derive(Debug, Error)]
pub enum VerificationError {
    #[error("Signature verification failed: {0}")]
    SignatureVerificationFailed(#[from] signature::Error),

    #[error("Payload deserialization failed: {0}")]
    SerializationFailed(#[from] ciborium::ser::Error<std::io::Error>),
}

#[derive(Debug, Error)]
pub enum SigningError {
    #[error("Signing failed: {0}")]
    SigningFailed(#[from] ed25519_dalek::SignatureError),

    #[error("Payload serialization failed: {0}")]
    SerializationFailed(#[from] ciborium::ser::Error<std::io::Error>),
}
