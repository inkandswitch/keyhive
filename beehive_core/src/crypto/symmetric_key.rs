use chacha20poly1305::{KeyInit, XChaCha20Poly1305};

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SymmetricKey([u8; 32]);

impl SymmetricKey {
    pub fn new(key: [u8; 32]) -> Self {
        Self(key)
    }

    pub fn generate() -> Self {
        let key = rand::random();
        Self(key)
    }

    pub fn key(&self) -> XChaCha20Poly1305 {
        XChaCha20Poly1305::new(&self.0.into())
    }
}

impl From<[u8; 32]> for SymmetricKey {
    fn from(key: [u8; 32]) -> Self {
        Self::new(key)
    }
}

impl From<SymmetricKey> for [u8; 32] {
    fn from(key: SymmetricKey) -> Self {
        key.0
    }
}
