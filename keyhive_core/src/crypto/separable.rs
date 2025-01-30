use super::domain_separator::SEPARATOR_STR;

pub trait Separable: Sized {
    /// Directly lift a `[u8; 32]` array into a `Self`.
    ///
    /// This method should only be implemented, but not used directly.
    /// Use [`derive_from_bytes`] instead.
    fn directly_from_32_bytes(array: [u8; 32]) -> Self;

    fn derive_from_bytes(bytes: &[u8]) -> Self {
        Self::directly_from_32_bytes(blake3::derive_key(SEPARATOR_STR, bytes))
    }
}
