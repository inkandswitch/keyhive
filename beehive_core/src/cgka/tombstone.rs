use std::fmt;

use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, PartialEq, Eq, Hash, Deserialize, Serialize)]
// FIXME
// #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize, Serialize)]
pub struct CgkaTombstoneId([u8; 32]);

impl CgkaTombstoneId {
    /// Generate a new tombstone id.
    pub fn generate<R: rand::RngCore + rand::CryptoRng>(csprng: &mut R) -> Self {
        let mut id = [0; 32];
        csprng.fill_bytes(&mut id);
        Self(id)
    }

    // FIXME
    pub fn debug_id(&self) -> Vec<u8> {
        self.0.iter().take(4).copied().collect()
    }
}

// FIXME
impl fmt::Debug for CgkaTombstoneId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "CgkaTombstoneId({:?})",
            self.0.iter().take(4).collect::<Vec<_>>()
        )
    }
}
