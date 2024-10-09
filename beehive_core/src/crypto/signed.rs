//! Wrap data in signatures.

use base64::prelude::*;
use ed25519_dalek::Signer;
use ed25519_dalek::Verifier;
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::fmt;
use std::hash::{Hash, Hasher};

/// A wrapper to add a signature and signer information to an arbitrary payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signed<T> {
    /// The data that was signed.
    pub(crate) payload: T,

    /// The verifying key of the signer (for verifying the signature).
    pub(crate) verifying_key: ed25519_dalek::VerifyingKey,

    /// The signature of the payload, which can be verified by the `verifying_key`.
    pub(crate) signature: ed25519_dalek::Signature,
}

impl<T> Signed<T> {
    pub fn payload(&self) -> &T {
        &self.payload
    }

    pub fn verifying_key(&self) -> ed25519_dalek::VerifyingKey {
        self.verifying_key
    }

    pub fn signature(&self) -> ed25519_dalek::Signature {
        self.signature
    }
}

impl<T: Clone> Signed<T>
where
    Vec<u8>: From<T>,
{
    pub fn sign(payload: T, signer: &ed25519_dalek::SigningKey) -> Self {
        let payload_bytes: Vec<u8> = payload.clone().into();

        Signed {
            payload,
            verifying_key: signer.verifying_key(),
            signature: signer.sign(payload_bytes.as_slice()),
        }
    }

    pub fn verify(&self) -> Result<(), signature::Error> {
        self.verifying_key.verify(
            Vec::<u8>::from(self.payload.clone()).as_slice(),
            &self.signature,
        )
    }

    pub fn map<U, F: FnOnce(T) -> U>(self, f: F) -> Signed<U> {
        Signed {
            payload: f(self.payload),
            verifying_key: self.verifying_key,
            signature: self.signature,
        }
    }
}

impl<T: fmt::Display> fmt::Display for Signed<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Signed {{ payload: {}, verifying_key: {}, signature: {} }}",
            self.payload,
            BASE64_STANDARD.encode(self.verifying_key.as_bytes()),
            self.signature
        )
    }
}

impl<T> From<Signed<T>> for Vec<u8>
where
    Vec<u8>: From<T>,
{
    fn from(signed: Signed<T>) -> Self {
        let mut buf: Vec<u8> = signed.payload.into();
        buf.append(&mut signed.verifying_key.to_bytes().to_vec());
        buf.append(&mut signed.signature.to_vec());
        buf
    }
}

impl<T: PartialOrd> PartialOrd for Signed<T> {
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

impl<T: Ord> Ord for Signed<T> {
    fn cmp(&self, other: &Self) -> Ordering {
        match self
            .verifying_key
            .as_bytes()
            .cmp(&other.verifying_key.as_bytes())
        {
            Ordering::Equal => match self.signature.to_bytes().cmp(&other.signature.to_bytes()) {
                Ordering::Equal => self.payload.cmp(&other.payload),
                unequal => unequal,
            },
            unequal => unequal,
        }
    }
}

impl<T: Hash> Hash for Signed<T> {
    fn hash<H>(&self, state: &mut H)
    where
        H: Hasher,
    {
        self.payload.hash(state);
        self.verifying_key.hash(state);
        self.signature.to_vec().hash(state);
    }
}
