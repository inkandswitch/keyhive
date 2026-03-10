//! Trait for types that are derivable but domain-separated.

use super::domain_separator::SEPARATOR_STR;

/// A trait for types that get domain-separated.
pub trait Separable: Sized {
    /// Directly lift a `[u8; 32]` array into a `Self`.
    ///
    /// <div class="warning">
    ///
    /// This method should only be implemented, but not used directly.
    /// Use [`derive_from_bytes`][`Self::derive_from_bytes`] instead.
    ///
    /// </div>
    ///
    /// # Examples
    ///
    /// ```
    /// # use keyhive_core::crypto::{
    /// #    separable::Separable,
    /// #    symmetric_key::SymmetricKey
    /// # };
    ///
    /// let key = SymmetricKey::directly_from_32_bytes([0; 32]);
    /// assert_eq!(key.as_slice(), &[0; 32]); // NOTE unchanged!
    /// ```
    fn directly_from_32_bytes(array: [u8; 32]) -> Self;

    /// Derive a `Self` from a byte slice and the [`SEPARATOR_STR`].
    ///
    /// # Examples
    ///
    /// ```
    /// # use keyhive_core::crypto::{
    /// #    separable::Separable,
    /// #    symmetric_key::SymmetricKey
    /// # };
    ///
    /// let key = SymmetricKey::derive_from_bytes(&[0; 32]);
    /// assert_eq!(
    ///     key.as_slice(),
    ///     &[0x21, 0xD6, 0xEF, 0x21, 0x89, 0x70, 0xEA, 0x57,
    ///       0xFC, 0xD4, 0x6B, 0x43, 0xE1, 0xF8, 0xD7, 0xE9,
    ///       0xB1, 0x02, 0xE5, 0xE4, 0xD6, 0x64, 0x5B, 0xD2,
    ///       0x48, 0x83, 0xEA, 0x70, 0xB8, 0xB3, 0x93, 0xFE]
    /// );
    /// ```
    fn derive_from_bytes(bytes: &[u8]) -> Self {
        Self::directly_from_32_bytes(blake3::derive_key(SEPARATOR_STR, bytes))
    }
}
