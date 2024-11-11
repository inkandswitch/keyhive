use super::domain_separator::SEPARATOR_STR;

pub trait Separable: Sized {
    fn from_32_bytes(array: [u8; 32]) -> Self;

    fn derive_from_bytes(bytes: &[u8]) -> Self {
        Self::from_32_bytes(blake3::derive_key(SEPARATOR_STR, bytes))
    }
}
