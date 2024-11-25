//! Wrap data in signatures.

use super::{
    signature::Signature, signing_key::SigningKey, verifiable::Verifiable,
    verifying_key::VerifyingKey,
};
use crate::principal::identifier::Identifier;
use ed25519_dalek::Signer;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// A wrapper to add a signature and signer information to an arbitrary payload.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Signed<T: Serialize> {
    /// The data that was signed.
    payload: T,

    /// The verifying key of the signer (for verifying the signature).
    verifying_key: VerifyingKey,

    /// The signature of the payload, which can be verified by the `verifying_key`.
    signature: Signature,
}

impl<T: Serialize> Signed<T> {
    pub fn try_sign(payload: T, signer: &SigningKey) -> Result<Self, SigningError> {
        let payload_bytes: Vec<u8> = bincode::serialize(&payload)?;

        Ok(Signed {
            payload,
            verifying_key: signer.verifying_key(),
            signature: signer.try_sign(payload_bytes.as_slice())?.into(),
        })
    }

    pub fn try_verify(&self) -> Result<(), VerificationError> {
        let buf: Vec<u8> = bincode::serialize(&self.payload)?;
        Ok(self.verifying_key.verify(buf.as_slice(), &self.signature)?)
    }

    pub fn payload(&self) -> &T {
        &self.payload
    }

    pub fn verifying_key(&self) -> &VerifyingKey {
        &self.verifying_key
    }

    pub fn id(&self) -> Identifier {
        self.verifying_key.into()
    }

    pub fn signature(&self) -> &Signature {
        &self.signature
    }

    pub fn map<U: Serialize, F: FnOnce(T) -> U>(self, f: F) -> Signed<U> {
        Signed {
            payload: f(self.payload),
            verifying_key: self.verifying_key,
            signature: self.signature,
        }
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
