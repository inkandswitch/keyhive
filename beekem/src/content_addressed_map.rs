use crate::{
    crypto::digest::Digest,
    transact::{fork::Fork, merge::Merge},
};
use derive_where::derive_where;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashMap},
    sync::Arc,
};

/// A content-addressed map.
///
/// Since all operations are referenced by their hash,
/// a map that indexes by the same cryptographic hash is convenient.
#[derive(Debug, PartialEq, Eq, Deserialize)]
#[derive_where(Clone)]
pub struct CaMap<T: Serialize>(pub(crate) HashMap<Digest<T>, Arc<T>>);

impl<T: Serialize> CaMap<T> {
    /// Create an empty [`CaMap`].
    ///
    /// # Examples
    ///
    /// ```
    /// # use keyhive_core::util::content_addressed_map::CaMap;
    /// let fresh: CaMap<String> = CaMap::new();
    /// assert_eq!(fresh.len(), 0);
    /// ```
    pub fn new() -> Self {
        Self(HashMap::new())
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

    pub fn remove_by_value(&mut self, value: &T) -> Option<Arc<T>> {
        let hash = Digest::hash(value);
        self.remove_by_hash(&hash)
    }

    pub fn get(&self, hash: &Digest<T>) -> Option<&Arc<T>> {
        self.0.get(hash)
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&Digest<T>, &Arc<T>)> {
        self.0.iter()
    }

    #[cfg(any(test, feature = "test_utils"))]
    pub fn from_iter_direct(elements: impl IntoIterator<Item = Arc<T>>) -> Self {
        let mut cam = CaMap::new();
        for rc in elements.into_iter() {
            cam.0.insert(Digest::hash(rc.as_ref()), rc);
        }
        cam
    }

    pub fn keys(&self) -> std::collections::hash_map::Keys<'_, Digest<T>, Arc<T>> {
        self.0.keys()
    }
    pub fn values(&self) -> std::collections::hash_map::Values<'_, Digest<T>, Arc<T>> {
        // Sorted because BTreeMap
        self.0.values()
    }

    pub fn into_keys(self) -> impl Iterator<Item = Digest<T>> {
        self.0.into_keys()
    }

    pub fn into_values(self) -> impl Iterator<Item = Arc<T>> {
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
    /// Build a [`CaMap`] from a type that can be converted [`IntoIterator`].
    ///
    /// # Example
    ///
    /// ```
    /// # use std::sync::Arc;
    /// # use keyhive_core::{crypto::digest::Digest, util::content_addressed_map::CaMap};
    /// let observed: CaMap<u8> = CaMap::from_iter([1, 2, 3]);
    /// assert_eq!(observed.len(), 3);
    /// assert_eq!(observed.get(&Digest::hash(&2)), Some(&Arc::new(2)));
    /// ```
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
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(
            self.0
                .keys()
                .collect::<Vec<_>>()
                .cmp(&other.0.keys().collect::<Vec<_>>()),
        )
    }
}

impl<T: Serialize + Eq> Ord for CaMap<T> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
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

impl<T: Serialize> std::hash::Hash for CaMap<T> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        let mut keys: Vec<_> = self.0.keys().collect();
        keys.sort();
        keys.hash(state);
    }
}
