use serde::{Deserialize, Serialize};
use std::{
    collections::{hash_map::RandomState, HashSet},
    hash::{DefaultHasher, Hash, Hasher},
};

#[derive(Debug, Clone)]
pub struct WrappedHashSet<T, S = RandomState>(HashSet<T, S>);

impl<T> WrappedHashSet<T, RandomState> {
    pub fn new() -> Self {
        WrappedHashSet(HashSet::new())
    }

    pub fn iter(&self) -> std::collections::hash_set::Iter<T> {
        self.0.iter()
    }

    pub fn hash_sorted(&self) -> Vec<&T>
    where
        T: Hash,
    {
        let map: std::collections::BTreeMap<u64, &T> = self
            .0
            .iter()
            .map(|x| {
                let mut hasher = DefaultHasher::new();
                (*x).hash(&mut hasher);
                (hasher.finish(), x)
            })
            .collect();

        map.values().map(|x| *x).collect()
    }
}

impl<T: Ord + Hash> Hash for WrappedHashSet<T, RandomState> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.hash_sorted().hash(state);
    }
}

impl<T: Hash + PartialEq> PartialEq for WrappedHashSet<T, RandomState> {
    fn eq(&self, other: &Self) -> bool {
        self.hash_sorted()
            .iter()
            .zip(other.hash_sorted().iter())
            .all(|(x, y)| x == y)
    }
}

impl<T: Hash + Eq> Eq for WrappedHashSet<T, RandomState> {}

impl<T: Hash + PartialOrd> PartialOrd for WrappedHashSet<T, RandomState> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.hash_sorted().partial_cmp(&other.hash_sorted())
    }
}

impl<T: Hash + Ord> Ord for WrappedHashSet<T, RandomState> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.hash_sorted().cmp(&other.hash_sorted())
    }
}

impl<T: Hash + Serialize> Serialize for WrappedHashSet<T, RandomState> {
    fn serialize<S: serde::ser::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.hash_sorted().serialize(serializer)
    }
}

impl<'de, T: Eq + Hash + Deserialize<'de>> Deserialize<'de> for WrappedHashSet<T, RandomState> {
    fn deserialize<D: serde::de::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let v = Vec::<T>::deserialize(deserializer)?;
        Ok(WrappedHashSet(HashSet::from_iter(v)))
    }
}
