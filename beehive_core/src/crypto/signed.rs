//! Wrap data in signatures.

use crate::principal::{
    agent::signer::{AgentSigner, SignerId},
    identifier::Identifier,
    verifiable::Verifiable,
};
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
    pub(crate) signed_by: SignerId,

    /// The signature of the payload, which can be verified by the `verifying_key`.
    pub(crate) signature: ed25519_dalek::Signature,
}

impl<T: Serialize> Signed<T> {
    pub fn try_sign(payload: T, signer: &AgentSigner) -> Result<Self, SigningError> {
        let payload_bytes: Vec<u8> = bincode::serialize(&payload)?;

        Ok(Signed {
            payload,
            signed_by: signer.id(),
            signature: signer.key().try_sign(payload_bytes.as_slice())?,
        })
    }

    pub fn payload(&self) -> &T {
        &self.payload
    }

    pub fn id(&self) -> Identifier {
        self.verifying_key().into()
    }

    pub fn signed_by(&self) -> &SignerId {
        &self.signed_by
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
            signed_by: self.signed_by,
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
            signed_by: self.signed_by.dupe(),
            signature: self.signature,
        }
    }
}

impl<T: Serialize> Verifiable for Signed<T> {
    fn verifying_key(&self) -> ed25519_dalek::VerifyingKey {
        self.signed_by.verifying_key()
    }
}

// FIXME test
impl<T: Serialize> Hash for Signed<T> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.signed_by.verifying_key().as_bytes().hash(state);
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
    use crate::principal::group::id::GroupId;

    #[test]
    fn test_round_trip() {
        let sk = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
        let id = GroupId(ed25519_dalek::VerifyingKey::from(&sk).into()).into();
        let signer = AgentSigner::new(id, sk).unwrap();

        let signed = Signed::try_sign(vec![1, 2, 3], &signer).unwrap();
        assert!(signed.try_verify().is_ok());
    }
}
