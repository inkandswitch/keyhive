//! The universally unique identifier of an [`Agent`](crate::principal::agentAgent).

use crate::crypto::verifiable::Verifiable;
use dupe::Dupe;
use serde::{Deserialize, Serialize};

#[cfg(any(feature = "test_utils", test))]
use tracing::instrument;

/// A unique identifier for an [`Agent`](crate::principal::agentAgent).
///
/// This is a newtype for a [`VerifyingKey`](ed25519_dalek::VerifyingKey).
/// It is used to identify an agent in the system. Since signing keys are only
/// available to the one agent and not shared, this identifier is provably unique.
#[derive(Copy, Serialize, Deserialize)]
pub struct Identifier(pub ed25519_dalek::VerifyingKey);

impl Identifier {
    #[cfg(any(feature = "test_utils", test))]
    #[instrument(skip_all)]
    pub fn generate<R: rand::CryptoRng + rand::RngCore>(csprng: &mut R) -> Self {
        ed25519_dalek::SigningKey::generate(csprng)
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

    /// Returns the underlying bytes as a slice.
    pub fn as_slice(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

#[cfg(any(test, feature = "arbitrary"))]
impl<'a> arbitrary::Arbitrary<'a> for Identifier {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let bytes = u.bytes(32)?;
        let arr = <[u8; 32]>::try_from(bytes).unwrap();
        let key = ed25519_dalek::SigningKey::from_bytes(&arr);
        Ok(key.verifying_key().into())
    }
}

impl Clone for Identifier {
    fn clone(&self) -> Self {
        *self
    }
}

impl Dupe for Identifier {
    fn dupe(&self) -> Self {
        *self
    }
}

impl std::hash::Hash for Identifier {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.as_bytes().hash(state)
    }
}

impl std::fmt::LowerHex for Identifier {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        crate::util::hex::bytes_as_hex(self.0.as_bytes().iter(), f)
    }
}

impl std::fmt::Display for Identifier {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{:#x}", self)
    }
}

impl std::fmt::Debug for Identifier {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "Identifier({})", self)
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

impl From<&ed25519_dalek::VerifyingKey> for Identifier {
    fn from(verifying_key: &ed25519_dalek::VerifyingKey) -> Self {
        Self(*verifying_key)
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
