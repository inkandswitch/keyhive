use super::{envelope::Envelope, hash::Hash, symmetric_key::SymmetricKey};

/// A "decryption pointer" / read capability
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CausalKey<T> {
    /// The identifier (hash of most recent op) of the payload that this key decrypts
    pub hash: Hash<T>,

    /// The symmetric key that decrypts the envelope
    pub key: SymmetricKey,
}
