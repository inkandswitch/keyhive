//! A cryptographic "read" capability (pointer & key).

use super::symmetric_key::SymmetricKey;

/// A cryptographic "read" capability.
///
/// Sometimes referred to as a "decryption pointer", this capability uniquely
/// identifies some ciphertext, and provides its [`SymmetricKey`].
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ReadCap<I> {
    /// The identifier of the ciphertext that the associated key decrypts
    pub id: I,

    /// The symmetric key that decrypts the envelope
    pub key: SymmetricKey,
}
