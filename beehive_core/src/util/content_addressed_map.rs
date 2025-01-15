use crate::crypto::digest::Digest;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, rc::Rc};

/// A content-addressed map.
///
/// Since all operations are referenced by their hash,
/// a map that indexes by the same cryptographic hash is convenient.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CaMap<T: Serialize>(pub(crate) BTreeMap<Digest<T>, Rc<T>>);

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

    /// Add a new value to the map, and return the associated [`Digest`].
    pub fn insert(&mut self, value: Rc<T>) -> Digest<T> {
        let key: Digest<T> = Digest::hash(&value);
        self.0.insert(key, value);
        key
    }

    /// Remove an element from the map by its [`Digest`].
    pub fn remove_by_hash(&mut self, hash: &Digest<T>) -> Option<Rc<T>> {
        self.0.remove(hash)
    }

    pub fn remove_by_value(&mut self, value: &T) -> Option<Rc<T>> {
        let hash = Digest::hash(value);
        self.remove_by_hash(&hash)
    }

    pub fn get(&self, hash: &Digest<T>) -> Option<&Rc<T>> {
        self.0.get(hash)
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&Digest<T>, &Rc<T>)> {
        self.0.iter()
    }

    #[cfg(test)]
    pub(crate) fn from_iter_direct(elements: impl IntoIterator<Item = Rc<T>>) -> Self {
        let mut cam = CaMap::new();
        for rc in elements.into_iter() {
            cam.0.insert(Digest::hash(rc.as_ref()), rc);
        }
        cam
    }

    pub fn keys(&self) -> std::collections::btree_map::Keys<'_, Digest<T>, Rc<T>> {
        self.0.keys()
    }
    pub fn values(&self) -> std::collections::btree_map::Values<'_, Digest<T>, Rc<T>> {
        // Sorted because BTreeMap
        self.0.values()
    }

    pub fn into_keys(self) -> impl Iterator<Item = Digest<T>> {
        self.0.into_keys()
    }

    pub fn into_values(self) -> impl Iterator<Item = Rc<T>> {
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

impl<T: Serialize> FromIterator<T> for CaMap<T> {
    /// Build a [`CaMap`] from a type that can be converted [`IntoIterator`].
    ///
    /// # Example
    ///
    /// ```
    /// # use std::rc::Rc;
    /// # use beehive_core::{crypto::digest::Digest, util::content_addressed_map::CaMap};
    /// let observed: CaMap<u8> = CaMap::from_iter([1, 2, 3]);
    /// assert_eq!(observed.len(), 3);
    /// assert_eq!(observed.get(&Digest::hash(&2)), Some(&Rc::new(2)));
    /// ```
    fn from_iter<I>(iter: I) -> Self
    where
        I: IntoIterator<Item = T>,
    {
        Self(
            iter.into_iter()
                .map(|preimage| (Digest::hash(&preimage), Rc::new(preimage)))
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

impl<'de, T: Serialize + Deserialize<'de>> Deserialize<'de> for CaMap<T> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let tree = BTreeMap::<Digest<T>, T>::deserialize(deserializer)?;
        let rcs: BTreeMap<Digest<T>, Rc<T>> =
            tree.into_iter().map(|(k, v)| (k, Rc::new(v))).collect();
        Ok(Self(rcs))
    }
}

impl<T: Serialize> Extend<(Digest<T>, Rc<T>)> for CaMap<T> {
    fn extend<I>(&mut self, iter: I)
    where
        I: IntoIterator<Item = (Digest<T>, Rc<T>)>,
    {
        self.0.extend(iter);
    }
}
