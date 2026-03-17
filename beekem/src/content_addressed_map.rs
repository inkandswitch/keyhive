//! A content-addressed map backed by cryptographic digests.

use crate::{
    collections::Map,
    transact::{Fork, Merge},
};
use alloc::{collections::BTreeMap, sync::Arc, vec::Vec};
use core::hash::{Hash, Hasher};
use keyhive_crypto::digest::Digest;
use serde::{Deserialize, Serialize};

/// A content-addressed map.
///
/// Since all operations are referenced by their hash,
/// a map that indexes by the same cryptographic hash is convenient.
#[derive(Debug, PartialEq, Eq, Deserialize)]
pub struct CaMap<T: Serialize>(pub Map<Digest<T>, Arc<T>>);

impl<T: Serialize> Clone for CaMap<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<T: Serialize> CaMap<T> {
    /// Create an empty [`CaMap`].
    pub fn new() -> Self {
        Self(Map::new())
    }

    /// Add a new value to the map, and return the associated [`Digest`].
    pub fn insert(&mut self, value: Arc<T>) -> Digest<T> {
        let key: Digest<T> = Digest::hash(&value);
        self.0.insert(key, value);
        key
    }

    /// Inserts, and returns if the value was newly inserted.
    pub fn insert_checked(&mut self, value: Arc<T>) -> (Digest<T>, bool) {
        let key: Digest<T> = Digest::hash(&value);
        let is_new = self.0.insert(key, value);
        (key, is_new.is_none())
    }

    /// Remove an element from the map by its [`Digest`].
    pub fn remove_by_hash(&mut self, hash: &Digest<T>) -> Option<Arc<T>> {
        self.0.remove(hash)
    }

    /// Remove an element from the map by its value.
    pub fn remove_by_value(&mut self, value: &T) -> Option<Arc<T>> {
        let hash = Digest::hash(value);
        self.remove_by_hash(&hash)
    }

    /// Get a reference to the value for the given hash.
    pub fn get(&self, hash: &Digest<T>) -> Option<&Arc<T>> {
        self.0.get(hash)
    }

    /// Return the number of entries.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the map is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Iterate over key-value pairs.
    pub fn iter(&self) -> impl Iterator<Item = (&Digest<T>, &Arc<T>)> {
        self.0.iter()
    }

    /// Iterate over keys.
    pub fn keys(&self) -> impl Iterator<Item = &Digest<T>> {
        self.0.keys()
    }

    /// Iterate over values.
    pub fn values(&self) -> impl Iterator<Item = &Arc<T>> {
        self.0.values()
    }

    /// Consume the map and iterate over keys.
    pub fn into_keys(self) -> impl Iterator<Item = Digest<T>> {
        self.0.into_keys()
    }

    /// Consume the map and iterate over values.
    pub fn into_values(self) -> impl Iterator<Item = Arc<T>> {
        self.0.into_values()
    }

    /// Whether the map contains the given value.
    pub fn contains_value(&self, value: &T) -> bool {
        let hash = Digest::hash(value);
        self.contains_key(&hash)
    }

    /// Whether the map contains the given hash key.
    pub fn contains_key(&self, hash: &Digest<T>) -> bool {
        self.0.contains_key(hash)
    }

    /// Build a [`CaMap`] from an iterator of `Arc<T>` values.
    #[cfg(any(test, feature = "test_utils"))]
    pub fn from_iter_direct(elements: impl IntoIterator<Item = Arc<T>>) -> Self {
        let mut cam = CaMap::new();
        for rc in elements.into_iter() {
            cam.0.insert(Digest::hash(rc.as_ref()), rc);
        }
        cam
    }
}

impl<T: Serialize> Default for CaMap<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Serialize> Fork for CaMap<T> {
    type Forked = Self;

    fn fork(&self) -> Self::Forked {
        self.clone()
    }
}

impl<T: Serialize> Merge for CaMap<T> {
    fn merge(&mut self, other: Self) {
        for (k, v) in other.0 {
            self.0.entry(k).or_insert(v);
        }
    }
}

impl<T: Serialize> FromIterator<T> for CaMap<T> {
    fn from_iter<I>(iter: I) -> Self
    where
        I: IntoIterator<Item = T>,
    {
        Self(
            iter.into_iter()
                .map(|preimage| (Digest::hash(&preimage), Arc::new(preimage)))
                .collect(),
        )
    }
}

impl<T: Serialize + PartialEq> PartialOrd for CaMap<T> {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(
            self.0
                .keys()
                .collect::<Vec<_>>()
                .cmp(&other.0.keys().collect::<Vec<_>>()),
        )
    }
}

impl<T: Serialize + Eq> Ord for CaMap<T> {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.partial_cmp(other)
            .expect("hashes are always comparable")
    }
}

impl<T: Serialize> Serialize for CaMap<T> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let tree: BTreeMap<&Digest<T>, &T> = self.0.iter().map(|(k, v)| (k, v.as_ref())).collect();
        tree.serialize(serializer)
    }
}

impl<T: Serialize> Extend<(Digest<T>, Arc<T>)> for CaMap<T> {
    fn extend<I>(&mut self, iter: I)
    where
        I: IntoIterator<Item = (Digest<T>, Arc<T>)>,
    {
        self.0.extend(iter);
    }
}

impl<T: Serialize> Hash for CaMap<T> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        let mut keys: Vec<_> = self.0.keys().collect();
        keys.sort();
        keys.hash(state);
    }
}
