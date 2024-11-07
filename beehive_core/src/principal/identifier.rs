//! The universally unique identifier of an [`Agent`](crate::principal::agentAgent).

use super::verifiable::Verifiable;
use serde::{Deserialize, Serialize};

/// A unique identifier for an [`Agent`](crate::principal::agentAgent).
///
/// This is a newtype for a [`VerifyingKey`](ed25519_dalek::VerifyingKey).
/// It is used to identify an agent in the system. Since signing keys are only
/// available to the one agent and not shared, this identifier is provably unique.
#[derive(Debug, Copy, Serialize, Deserialize)]
pub struct Identifier(pub ed25519_dalek::VerifyingKey);

impl Identifier {
    #[cfg(feature = "test_utils")]
    pub fn generate() -> Self {
        ed25519_dalek::SigningKey::generate(&mut rand::thread_rng())
            .verifying_key()
            .into()
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

impl Clone for Identifier {
    fn clone(&self) -> Self {
        *self
    }
}

impl std::hash::Hash for Identifier {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.as_bytes().hash(state)
    }
}

impl std::fmt::Display for Identifier {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        self.as_slice()
            .iter()
            .fold(Ok(()), |_, byte| write!(f, "{:#x}", byte))
    }
}

impl PartialEq for Identifier {
    fn eq(&self, other: &Self) -> bool {
        self.as_bytes() == other.as_bytes()
    }
}

impl Eq for Identifier {}

impl PartialOrd for Identifier {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Identifier {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.as_bytes().cmp(other.as_bytes())
    }
}

impl Verifiable for Identifier {
    fn verifying_key(&self) -> ed25519_dalek::VerifyingKey {
        self.0
    }
}

impl From<ed25519_dalek::VerifyingKey> for Identifier {
    fn from(verifying_key: ed25519_dalek::VerifyingKey) -> Self {
        Self(verifying_key)
    }
}

impl From<Identifier> for ed25519_dalek::VerifyingKey {
    fn from(identifier: Identifier) -> Self {
        identifier.0
    }
}

impl From<ed25519_dalek::SigningKey> for Identifier {
    fn from(sk: ed25519_dalek::SigningKey) -> Self {
        sk.verifying_key().into()
    }
}
