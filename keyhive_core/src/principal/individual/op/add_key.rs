use crate::crypto::share_key::ShareKey;
use dupe::Dupe;
use serde::{Deserialize, Serialize};

/// Add a new key to the prekeys.
#[derive(Debug, Clone, Dupe, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(any(test, feature = "arbitrary"), derive(arbitrary::Arbitrary))]
pub struct AddKeyOp {
    /// The key to add.
    pub share_key: ShareKey,
}

impl AddKeyOp {
    #[cfg(any(test, feature = "test_utils"))]
    pub fn generate<R: rand::CryptoRng + rand::RngCore>(csprng: &mut R) -> Self {
        Self {
            share_key: ShareKey::generate(csprng),
        }
    }
}
