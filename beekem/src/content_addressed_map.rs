//! Verified statements keyed by their digest.

use crate::{
    collections::Map,
    transact::{Fork, Merge},
};
use alloc::{sync::Arc, vec::Vec};
use core::{
    fmt,
    hash::{Hash, Hasher},
};
use keyhive_crypto::{digest::Digest, signable::Kinded, verified::Verified};

/// Verified statements keyed by [`Verified::digest`], the digest of who
/// signed each and what it says.
///
/// Two signatures over one statement have one digest, so the map keeps
/// whichever it saw first.
pub struct CaMap<T>(Map<Digest<T>, Arc<Verified<T>>>);

impl<T> CaMap<T> {
    pub fn new() -> Self {
        Self(Map::new())
    }

    /// Insert `value` under its digest, unless that digest is present.
    /// Returns the digest.
    pub fn insert(&mut self, value: Arc<Verified<T>>) -> Digest<T> {
        let key = value.digest();
        self.0.entry(key).or_insert(value);
        key
    }

    pub fn get(&self, hash: &Digest<T>) -> Option<&Arc<Verified<T>>> {
        self.0.get(hash)
    }

    pub fn contains_key(&self, hash: &Digest<T>) -> bool {
        self.0.contains_key(hash)
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&Digest<T>, &Arc<Verified<T>>)> {
        self.0.iter()
    }

    pub fn keys(&self) -> impl Iterator<Item = &Digest<T>> {
        self.0.keys()
    }

    pub fn values(&self) -> impl Iterator<Item = &Arc<Verified<T>>> {
        self.0.values()
    }
}

impl<T> Clone for CaMap<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<T> Default for CaMap<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Kinded + fmt::Debug> fmt::Debug for CaMap<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_map().entries(self.0.iter()).finish()
    }
}

/// Equal when they hold the same digests: a digest names one statement.
impl<T> PartialEq for CaMap<T> {
    fn eq(&self, other: &Self) -> bool {
        self.0.len() == other.0.len() && self.0.keys().all(|k| other.0.contains_key(k))
    }
}

impl<T> Eq for CaMap<T> {}

impl<T> Hash for CaMap<T> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        let mut keys: Vec<_> = self.0.keys().collect();
        keys.sort();
        keys.hash(state);
    }
}

impl<T> Fork for CaMap<T> {
    type Forked = Self;

    fn fork(&self) -> Self::Forked {
        self.clone()
    }
}

impl<T> Merge for CaMap<T> {
    fn merge(&mut self, other: Self) {
        for (k, v) in other.0 {
            self.0.entry(k).or_insert(v);
        }
    }
}
