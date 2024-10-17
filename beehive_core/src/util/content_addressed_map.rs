use crate::crypto::digest::Digest;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// A content-addressed map.
///
/// Since all operations are referenced by their hash,
/// a map that indexes by the same cryptographic hash is convenient.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct CaMap<T: Serialize>(BTreeMap<Digest<T>, T>);

impl<T: Serialize> CaMap<T> {
    /// Create an empty [`CaMap`].
    ///
    /// # Examples
    ///
    /// ```
    /// # use beehive_core::util::content_addressed_map::CaMap;
    /// let fresh: CaMap<String> = CaMap::new();
    /// assert_eq!(fresh.len(), 0);
    /// ```
    pub fn new() -> Self {
        Self(std::collections::BTreeMap::new())
    }

    pub fn from_iter<I: IntoIterator<Item = T>>(iter: I) -> Self {
        Self(
            iter.into_iter()
                .map(|preimage| (Digest::hash(&preimage), preimage))
                .collect(),
        )
    }

    pub fn insert(&mut self, value: T) -> Digest<T> {
        let key: Digest<T> = Digest::hash(&value);
        self.0.insert(key, value);
        key
    }

    pub fn remove(&mut self, hash: &Digest<T>) -> Option<T> {
        self.0.remove(hash)
    }

    pub fn get(&self, hash: &Digest<T>) -> Option<&T> {
        self.0.get(hash)
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&Digest<T>, &T)> {
        self.0.iter()
    }

    pub fn keys(&self) -> std::collections::btree_map::Keys<'_, Digest<T>, T> {
        self.0.keys()
    }
    pub fn values(&self) -> std::collections::btree_map::Values<'_, Digest<T>, T> {
        self.0.values()
    }

    pub fn into_keys(self) -> impl Iterator<Item = Digest<T>> {
        self.0.into_keys()
    }

    pub fn into_values(self) -> impl Iterator<Item = T> {
        self.0.into_values()
    }

    pub fn contains_value(&self, value: &T) -> bool {
        let hash = Digest::hash(value);
        self.contains_key(&hash)
    }

    pub fn contains_key(&self, hash: &Digest<T>) -> bool {
        self.0.contains_key(hash)
    }
}
