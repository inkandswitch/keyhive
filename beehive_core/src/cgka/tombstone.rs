use serde::{Deserialize, Serialize};


#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize, Serialize)]
pub struct CgkaTombstoneId([u8; 32]);

impl CgkaTombstoneId {
    /// Generate a new tombstone id.
    pub fn generate<R: rand::RngCore + rand::CryptoRng>(csprng: &mut R) -> Self {
        let mut id = [0; 32];
        csprng.fill_bytes(&mut id);
        Self(id)
    }
}
