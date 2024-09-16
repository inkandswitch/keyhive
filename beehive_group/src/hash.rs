use std::marker::PhantomData;

#[derive(Debug)]
pub struct Hash<T> {
    pub raw: blake3::Hash,
    phantom: PhantomData<T>,
}

impl<T> Copy for Hash<T> {}

impl<T> Clone for Hash<T> {
    fn clone(&self) -> Self {
        Self {
            raw: self.raw,
            phantom: PhantomData,
        }
    }
}

impl<T> PartialEq for Hash<T> {
    fn eq(&self, other: &Self) -> bool {
        self.raw.as_bytes() == other.raw.as_bytes()
    }
}

impl<T> Eq for Hash<T> {}

impl<T> PartialOrd for Hash<T> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.raw.as_bytes().partial_cmp(&other.raw.as_bytes())
    }
}

impl<T> Ord for Hash<T> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.raw.as_bytes().cmp(&other.raw.as_bytes())
    }
}

impl<T> std::hash::Hash for Hash<T> {
    fn hash<H>(&self, state: &mut H)
    where
        H: std::hash::Hasher,
    {
        self.raw.hash(state)
    }
}

impl<T> From<blake3::Hash> for Hash<T> {
    fn from(hash: blake3::Hash) -> Self {
        Self {
            raw: hash,
            phantom: PhantomData,
        }
    }
}

impl<T> From<[u8; 32]> for Hash<T> {
    fn from(bytes: [u8; 32]) -> Self {
        Self {
            raw: blake3::Hash::from(bytes),
            phantom: PhantomData,
        }
    }
}

impl<T> From<Hash<T>> for blake3::Hash {
    fn from(hash: Hash<T>) -> blake3::Hash {
        hash.raw
    }
}

impl<T> From<Hash<T>> for [u8; 32] {
    fn from(hash: Hash<T>) -> [u8; 32] {
        hash.raw.into()
    }
}

impl<T> Hash<T> {
    pub fn hash(preimage: T) -> Self
    where
        T: Into<Vec<u8>>,
    {
        Self {
            raw: blake3::hash(preimage.into().as_slice()),
            phantom: PhantomData,
        }
    }

    pub fn hash_slice(slice: &[u8]) -> Self {
        Self {
            raw: blake3::hash(slice),
            phantom: PhantomData,
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.raw.as_bytes()
    }

    // FIXME make a trait for levels?
    pub fn trailing_zero_bytes(&self) -> u8 {
        let mut count = 0;

        for byte in self.raw.as_bytes().into_iter().rev() {
            if *byte == 0 {
                count += 1;
            } else {
                break;
            }
        }

        count
    }

    pub fn trailing_zeros(&self) -> u8 {
        let mut count = 0;

        for byte in self.raw.as_bytes().into_iter().rev() {
            let zeros = byte.count_zeros() as u8;
            count += zeros;

            if zeros != 8 {
                break;
            }
        }

        count
    }
}

//////////////
//////////////

#[derive(Debug, Clone)]
pub struct CAStore<T> {
    store: std::collections::HashMap<Hash<T>, T>,
}

impl<T: PartialEq + std::hash::Hash> PartialEq for CAStore<T> {
    fn eq(&self, other: &Self) -> bool {
        self.store == other.store
    }
}

impl<T: Eq + std::hash::Hash> Eq for CAStore<T> {}

impl<T: std::hash::Hash> CAStore<T> {
    pub fn new() -> Self {
        Self {
            store: std::collections::HashMap::new(),
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
        T: Clone + Into<Vec<u8>>,
    {
        let bytes: Vec<u8> = value.clone().into();
        let key: Hash<T> = Hash {
            raw: blake3::hash(bytes.as_slice()),
            phantom: PhantomData,
        };

        self.store.insert(key, value);
        key
    }

    pub fn get(&self, hash: &Hash<T>) -> Option<&T> {
        self.store.get(hash)
    }

    pub fn remove(&mut self, hash: &Hash<T>) -> Option<T> {
        self.store.remove(hash)
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
}

impl<T: Clone + std::hash::Hash> std::hash::Hash for CAStore<T> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.store
            .clone()
            .into_keys()
            .collect::<Vec<Hash<T>>>()
            .sort()
            .hash(state) // FIXME use BLAKE3
    }
}
