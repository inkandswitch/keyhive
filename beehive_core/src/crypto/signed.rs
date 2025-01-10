//! Wrap data in signatures.

use crate::principal::{identifier::Identifier, verifiable::Verifiable};
use dupe::Dupe;
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
    pub(crate) payload: T,

    /// The verifying key of the signer (for verifying the signature).
    pub(crate) issuer: ed25519_dalek::VerifyingKey,

    /// The signature of the payload, which can be verified by the `verifying_key`.
    pub(crate) signature: ed25519_dalek::Signature,
}

impl<T: Serialize> Signed<T> {
    pub fn try_sign(payload: T, signer: &ed25519_dalek::SigningKey) -> Result<Self, SigningError> {
        let payload_bytes: Vec<u8> = bincode::serialize(&payload)?;

        Ok(Signed {
            payload,
            issuer: signer.verifying_key(),
            signature: signer.try_sign(payload_bytes.as_slice())?,
        })
    }

    pub fn payload(&self) -> &T {
        &self.payload
    }

    pub fn id(&self) -> Identifier {
        self.verifying_key().into()
    }

    pub fn issuer(&self) -> &ed25519_dalek::VerifyingKey {
        &self.issuer
    }

    pub fn signature(&self) -> &ed25519_dalek::Signature {
        &self.signature
    }

    pub fn try_verify(&self) -> Result<(), VerificationError> {
        let buf: Vec<u8> = bincode::serialize(&self.payload)?;
        Ok(self
            .verifying_key()
            .verify(buf.as_slice(), &self.signature)?)
    }

    pub fn map<U: Serialize, F: FnOnce(T) -> U>(self, f: F) -> Signed<U> {
        Signed {
            payload: f(self.payload),
            issuer: self.issuer,
            signature: self.signature,
        }
    }
}

impl<T: Serialize + PartialOrd> PartialOrd for Signed<T> {
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

impl<T: Serialize + Ord> Ord for Signed<T> {
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

impl<T: Dupe + Serialize> Dupe for Signed<T> {
    fn dupe(&self) -> Self {
        Signed {
            payload: self.payload.dupe(),
            issuer: self.issuer,
            signature: self.signature,
        }
    }
}

impl<T: Serialize> Verifiable for Signed<T> {
    fn verifying_key(&self) -> ed25519_dalek::VerifyingKey {
        self.issuer
    }
}

impl<T: Serialize> Hash for Signed<T> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.issuer.hash(state);
        self.signature.to_bytes().hash(state);

        let encoded: Vec<u8> = bincode::serialize(&self.payload).expect("serialization failed");
        encoded.hash(state);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_round_trip() {
        let sk = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
        let signed = Signed::try_sign(vec![1, 2, 3], &sk).unwrap();
        assert!(signed.try_verify().is_ok());
    }
}
