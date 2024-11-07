//! Wrap data in signatures.

use crate::principal::identifier::Identifier;
use ed25519_dalek::{Signer, Verifier};
use serde::{Deserialize, Serialize};
use std::{
    cmp::Ordering,
    hash::{Hash, Hasher},
};

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
    pub fn sign(payload: T, signer: &ed25519_dalek::SigningKey) -> Self {
        let payload_bytes: Vec<u8> = serde_cbor::to_vec(&payload).expect("FIXME");

        Signed {
            payload,
            verifying_key: signer.verifying_key(),
            signature: signer.sign(payload_bytes.as_slice()),
        }
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

    pub fn verify(&self) -> Result<(), signature::Error> {
        self.verifying_key.verify(
            serde_cbor::to_vec(&self.payload).expect("FIXME").as_slice(),
            &self.signature,
        )
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
        serde_cbor::to_vec(&self.payload)
            .expect("unable to serialize payload for hashing")
            .hash(state);
    }
}
