use crate::transact::{fork::Fork, merge::Merge};
use derive_where::derive_where;
use keyhive_crypto::digest::Digest;
use std::{
    cmp::Ordering,
    collections::HashMap,
    hash::{Hash, Hasher},
    sync::Arc,
};

/// A value that names itself: the digest of what it is.
pub trait ContentAddressed: Sized {
    fn content_digest(&self) -> Digest<Self>;
}

/// A content-addressed map, each value under its [`ContentAddressed`] digest.
#[derive(Debug, PartialEq, Eq)]
#[derive_where(Clone)]
pub struct CaMap<T: ContentAddressed>(pub(crate) HashMap<Digest<T>, Arc<T>>);

impl<T: ContentAddressed> CaMap<T> {
    /// Create an empty [`CaMap`].
    ///
    pub fn new() -> Self {
        Self(HashMap::new())
    }

    /// Add a new value to the map, and return the associated [`Digest`].
    pub fn insert(&mut self, value: Arc<T>) -> Digest<T> {
        let key = value.content_digest();
        self.0.insert(key, value);
        key
    }

    /// Inserts, and returns if the value was newly inserted.
    pub fn insert_checked(&mut self, value: Arc<T>) -> (Digest<T>, bool) {
        let key = value.content_digest();
        let is_new = self.0.insert(key, value);
        (key, is_new.is_none())
    }

    /// Remove an element from the map by its [`Digest`].
    pub fn remove_by_hash(&mut self, hash: &Digest<T>) -> Option<Arc<T>> {
        self.0.remove(hash)
    }

    pub fn remove_by_value(&mut self, value: &T) -> Option<Arc<T>> {
        let hash = value.content_digest();
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
            cam.0.insert(rc.content_digest(), rc);
        }
        cam
    }

    pub fn keys(&self) -> std::collections::hash_map::Keys<'_, Digest<T>, Arc<T>> {
        self.0.keys()
    }
    pub fn values(&self) -> std::collections::hash_map::Values<'_, Digest<T>, Arc<T>> {
        self.0.values()
    }

    pub fn into_keys(self) -> impl Iterator<Item = Digest<T>> {
        self.0.into_keys()
    }

    pub fn into_values(self) -> impl Iterator<Item = Arc<T>> {
        self.0.into_values()
    }

    pub fn contains_value(&self, value: &T) -> bool {
        let hash = value.content_digest();
        self.contains_key(&hash)
    }

    pub fn contains_key(&self, hash: &Digest<T>) -> bool {
        self.0.contains_key(hash)
    }
}

impl<T: ContentAddressed> Default for CaMap<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: ContentAddressed> Fork for CaMap<T> {
    type Forked = Self;

    fn fork(&self) -> Self::Forked {
        self.clone()
    }
}

impl<T: ContentAddressed> Merge for CaMap<T> {
    fn merge(&mut self, other: Self) {
        for (k, v) in other.0 {
            self.0.entry(k).or_insert(v);
        }
    }
}

impl<T: ContentAddressed> FromIterator<T> for CaMap<T> {
    /// Build a [`CaMap`] from values, each under its digest.
    fn from_iter<I>(iter: I) -> Self
    where
        I: IntoIterator<Item = T>,
    {
        Self(
            iter.into_iter()
                .map(|preimage| (preimage.content_digest(), Arc::new(preimage)))
                .collect(),
        )
    }
}

impl<T: ContentAddressed + PartialEq> PartialOrd for CaMap<T> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(
            self.0
                .keys()
                .collect::<Vec<_>>()
                .cmp(&other.0.keys().collect::<Vec<_>>()),
        )
    }
}

impl<T: ContentAddressed + Eq> Ord for CaMap<T> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.partial_cmp(other)
            .expect("hashes are always comparable")
    }
}

impl<T: ContentAddressed> IntoIterator for CaMap<T> {
    type Item = (Digest<T>, Arc<T>);
    type IntoIter = std::collections::hash_map::IntoIter<Digest<T>, Arc<T>>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<'a, T: ContentAddressed> IntoIterator for &'a CaMap<T> {
    type Item = (&'a Digest<T>, &'a Arc<T>);
    type IntoIter = std::collections::hash_map::Iter<'a, Digest<T>, Arc<T>>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

impl<T: ContentAddressed> Extend<(Digest<T>, Arc<T>)> for CaMap<T> {
    fn extend<I>(&mut self, iter: I)
    where
        I: IntoIterator<Item = (Digest<T>, Arc<T>)>,
    {
        self.0.extend(iter);
    }
}

impl<T: ContentAddressed> Hash for CaMap<T> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        let mut keys: Vec<_> = self.0.keys().collect();
        keys.sort();
        keys.hash(state);
    }
}
