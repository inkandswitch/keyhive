use super::{signature::Signature, verifiable::Verifiable, verifying_key::VerifyingKey};
use dupe::Dupe;
use ed25519_dalek::Signer;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct SigningKey([u8; 32]);

impl SigningKey {
    pub fn generate<R: rand::RngCore + rand::CryptoRng>(csprng: &mut R) -> Self {
        Self(ed25519_dalek::SigningKey::generate(csprng).to_bytes())
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }
}

impl Dupe for SigningKey {
    fn dupe(&self) -> Self {
        Self(self.0)
    }
}

impl Signer<Signature> for SigningKey {
    fn try_sign(&self, message: &[u8]) -> Result<Signature, ed25519_dalek::SignatureError> {
        Ok(ed25519_dalek::SigningKey::from(self.0)
            .try_sign(message)?
            .into())
    }
}

impl Verifiable for SigningKey {
    fn verifying_key(&self) -> VerifyingKey {
        ed25519_dalek::SigningKey::from(self.clone())
            .verifying_key()
            .into()
    }
}

impl From<ed25519_dalek::SigningKey> for SigningKey {
    fn from(key: ed25519_dalek::SigningKey) -> Self {
        Self(key.to_bytes())
    }
}

impl From<SigningKey> for ed25519_dalek::SigningKey {
    fn from(key: SigningKey) -> Self {
        ed25519_dalek::SigningKey::from_bytes(&key.0)
    }
}

impl From<[u8; 32]> for SigningKey {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}
