use serde::{Deserialize, Serialize};
use std::{
    cmp::Eq,
    hash::{Hash, Hasher},
};

#[derive(Debug, Clone, Default)]
pub struct HashMap<K, V>(pub std::collections::HashMap<K, V>);

impl<K: Hash + Eq, V> HashMap<K, V> {
    pub fn new() -> Self {
        Self(std::collections::HashMap::new())
    }

    pub fn get<Q>(&self, key: &Q) -> Option<&V>
    where
        K: std::borrow::Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        self.0.get(key)
    }

    pub fn get_mut<Q>(&mut self, key: &Q) -> Option<&mut V>
    where
        K: std::borrow::Borrow<Q>,
        Q: Hash + Eq,
    {
        self.0.get_mut(key)
    }

    pub fn insert(&mut self, key: K, value: V) -> Option<V> {
        self.0.insert(key, value)
    }

    pub fn remove<Q>(&mut self, key: &Q) -> Option<V>
    where
        K: std::borrow::Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        self.0.remove(key)
    }

    pub fn keys(&self) -> std::collections::hash_map::Keys<K, V> {
        self.0.keys()
    }

    pub fn values(&self) -> std::collections::hash_map::Values<K, V> {
        self.0.values()
    }

    pub fn into_sorted(&self) -> Vec<(&K, &V)>
    where
        K: Ord,
    {
        let mut slice: Vec<(&K, &V)> = self.0.iter().collect();
        slice.sort_by_key(|(k, _)| *k);
        slice
    }

    pub fn iter(&self) -> std::collections::hash_map::Iter<K, V> {
        self.0.iter()
    }
}

impl<K: Eq + Hash, V: PartialEq> PartialEq for HashMap<K, V> {
    fn eq(&self, other: &Self) -> bool {
        self.0.eq(&other.0)
    }
}

impl<K: Eq + Hash, V: Eq> Eq for HashMap<K, V> {}

impl<K: Ord + Eq + Hash + Clone, V: Hash> Hash for HashMap<K, V> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.into_sorted().iter().for_each(|(k, v)| {
            k.hash(state);
            v.hash(state);
        });
    }
}

impl<K: Eq + Hash, V> FromIterator<(K, V)> for HashMap<K, V> {
    fn from_iter<T: IntoIterator<Item = (K, V)>>(iter: T) -> Self {
        Self(iter.into_iter().collect())
    }
}

impl<K: Serialize, V: Serialize> Serialize for HashMap<K, V> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(serializer)
    }
}

impl<'de, K: Deserialize<'de> + Eq + Hash, V: Deserialize<'de>> Deserialize<'de> for HashMap<K, V> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let map = std::collections::HashMap::deserialize(deserializer)?;
        Ok(Self(map))
    }
}
