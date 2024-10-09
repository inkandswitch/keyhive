use super::{envelope::Envelope, hash::Hash, symmetric_key::SymmetricKey};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CausalKey<T> {
    pub hash: Hash<Envelope<T>>,
    pub key: SymmetricKey,
}
