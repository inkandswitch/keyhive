use serde::Deserialize;
use std::fmt;
use std::marker::PhantomData;

#[derive(Debug)]
pub struct Hash<T> {
    pub raw: blake3::Hash,
    pub(crate) _phantom: PhantomData<T>,
}

impl<T> serde::Serialize for Hash<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.raw.as_bytes().serialize(serializer)
    }
}

impl<'de, T> serde::Deserialize<'de> for Hash<T> {
    fn deserialize<D>(deserializer: D) -> Result<Hash<T>, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes: [u8; 32] = Deserialize::deserialize(deserializer)?;
        Ok(Hash {
            raw: blake3::Hash::from(bytes),
            _phantom: PhantomData,
        })
    }
}

impl<T> fmt::Display for Hash<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Hash({})", self.raw.to_hex())
    }
}

impl<T> Copy for Hash<T> {}

impl<T> Clone for Hash<T> {
    fn clone(&self) -> Self {
        Self {
            raw: self.raw,
            _phantom: PhantomData,
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
            _phantom: PhantomData,
        }
    }
}

impl<T> From<[u8; 32]> for Hash<T> {
    fn from(bytes: [u8; 32]) -> Self {
        Self {
            raw: blake3::Hash::from(bytes),
            _phantom: PhantomData,
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
            _phantom: PhantomData,
        }
    }

    pub fn hash_slice(slice: &[u8]) -> Self {
        Self {
            raw: blake3::hash(slice),
            _phantom: PhantomData,
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
