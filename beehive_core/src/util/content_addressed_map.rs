use crate::crypto::hash::Hash;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::marker::PhantomData;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaMap<T> {
    store: BTreeMap<Hash<T>, T>,
}

impl<T: PartialEq + std::hash::Hash> PartialEq for CaMap<T> {
    fn eq(&self, other: &Self) -> bool {
        self.store == other.store
    }
}

impl<T: Eq + std::hash::Hash> Eq for CaMap<T> {}

impl<T: std::hash::Hash> CaMap<T> {
    pub fn new() -> Self {
        Self {
            store: std::collections::BTreeMap::new(),
        }
    }

    pub fn from_iter<I>(iter: I) -> Self
    where
        T: Into<Vec<u8>> + Clone,
        I: IntoIterator<Item = T>,
    {
        Self {
            store: iter
                .into_iter()
                .map(|preimage| (Hash::hash(preimage.clone()), preimage))
                .collect(),
        }
    }

    pub fn insert(&mut self, value: T) -> Hash<T>
    where
        T: Clone + Into<Vec<u8>>, // FIXME hash insteaf of vecu8
    {
        let bytes: Vec<u8> = value.clone().into();
        let key: Hash<T> = Hash {
            raw: blake3::hash(bytes.as_slice()),
            _phantom: PhantomData,
        };

        self.store.insert(key, value);
        key
    }

    pub fn remove(&mut self, hash: &Hash<T>) -> Option<T> {
        self.store.remove(hash)
    }

    pub fn get(&self, hash: &Hash<T>) -> Option<&T> {
        self.store.get(hash)
    }

    pub fn len(&self) -> usize {
        self.store.len()
    }

    pub fn is_empty(&self) -> bool {
        self.store.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&Hash<T>, &T)> {
        self.store.iter()
    }

    pub fn into_values(self) -> impl Iterator<Item = T> {
        self.store.into_values()
    }

    pub fn into_keys(self) -> impl Iterator<Item = Hash<T>> {
        self.store.into_keys()
    }

    pub fn contains_key(&self, hash: &Hash<T>) -> bool {
        self.store.contains_key(hash)
    }
}

impl<T: Clone + std::hash::Hash> std::hash::Hash for CaMap<T> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.store
            .clone()
            .into_keys()
            .collect::<Vec<Hash<T>>>()
            .sort()
            .hash(state) // FIXME use BLAKE3
    }
}
