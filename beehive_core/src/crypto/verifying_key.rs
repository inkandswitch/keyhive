use super::signature::Signature;
use dupe::Dupe;
use ed25519_dalek::Verifier;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct VerifyingKey([u8; 32]);

impl VerifyingKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, ConversionError> {
        ed25519_dalek::VerifyingKey::from_bytes(&bytes)
            .map(Into::into)
            .map_err(|_| ConversionError)
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn verify(&self, message: &[u8], signature: &Signature) -> Result<(), signature::Error> {
        ed25519_dalek::VerifyingKey::from(*self).verify(message, &(*signature).into())
    }
}

impl From<ed25519_dalek::VerifyingKey> for VerifyingKey {
    fn from(key: ed25519_dalek::VerifyingKey) -> Self {
        VerifyingKey(key.to_bytes())
    }
}

impl From<VerifyingKey> for ed25519_dalek::VerifyingKey {
    fn from(key: VerifyingKey) -> Self {
        ed25519_dalek::VerifyingKey::from_bytes(&key.0).unwrap()
    }
}

impl Dupe for VerifyingKey {
    fn dupe(&self) -> Self {
        *self
    }
}

#[derive(Debug, Clone, Copy, Dupe, Error)]
#[error("Unable to convert byte from array")]
pub struct ConversionError;
