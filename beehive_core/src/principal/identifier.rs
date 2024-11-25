//! The universally unique identifier of an [`Agent`](crate::principal::agentAgent).

use crate::crypto::{signing_key::SigningKey, verifiable::Verifiable, verifying_key::VerifyingKey};
use dupe::Dupe;
use serde::{Deserialize, Serialize};

/// A unique identifier for an [`Agent`](crate::principal::agentAgent).
///
/// This is a newtype for a [`VerifyingKey`].
/// It is used to identify an agent in the system. Since signing keys are only
/// available to the one agent and not shared, this identifier is provably unique.
#[derive(
    Debug, Copy, Dupe, Clone, Hash, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize,
)]
pub struct Identifier(pub VerifyingKey);

impl Identifier {
    #[cfg(feature = "test_utils")]
    pub fn generate<R: rand::CryptoRng + rand::RngCore>(csprng: &mut R) -> Self {
        SigningKey::generate(csprng).verifying_key().into()
    }

    /// Lower the [`Identifier`] to an owned binary representation.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// Lower the [`Identifier`] to a borrowed binary representation.
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }

    pub fn as_slice(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl std::fmt::Display for Identifier {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        self.as_slice()
            .iter()
            .fold(Ok(()), |_, byte| write!(f, "{:#x}", byte))
    }
}

impl Verifiable for Identifier {
    fn verifying_key(&self) -> VerifyingKey {
        self.0
    }
}

impl From<VerifyingKey> for Identifier {
    fn from(verifying_key: VerifyingKey) -> Self {
        Self(verifying_key)
    }
}

impl From<ed25519_dalek::VerifyingKey> for Identifier {
    fn from(verifying_key: ed25519_dalek::VerifyingKey) -> Self {
        Self(verifying_key.into())
    }
}

impl From<Identifier> for VerifyingKey {
    fn from(identifier: Identifier) -> Self {
        identifier.0
    }
}

impl From<Identifier> for ed25519_dalek::VerifyingKey {
    fn from(identifier: Identifier) -> Self {
        identifier.0.into()
    }
}
