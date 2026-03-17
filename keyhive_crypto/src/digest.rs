//! Helpers for working with hashes.

use alloc::vec::Vec;
use core::{
    fmt,
    hash::{Hash, Hasher},
    marker::PhantomData,
};
use serde::{Deserialize, Serialize};

/// A [`blake3::Hash`] tagged with which type it is a hash of.
///
/// This makes it easy to trace the origin type of hash identifiers flowing through the system.
///
/// # Examples
///
/// ```
/// # use keyhive_crypto::digest::Digest;
/// #
/// let string_hash: Digest<String> = Digest::hash(&"hello world".to_string());
/// let array_hash: Digest<[u8; 3]> = Digest::hash(&[1, 2, 3]);
/// let bytes_hash: Digest<Vec<u8>> = Digest::hash(&vec![42, 99]);
/// ```
#[derive(Debug)]
pub struct Digest<T: Serialize> {
    /// The underlying, unparameterized [`blake3::Hash`].
    pub raw: blake3::Hash,

    /// A phantom parameter to retain the type of the preimage.
    pub _phantom: PhantomData<T>,
}

impl<T: Serialize> Digest<T> {
    /// Digest a value and retain its type as a phantom parameter.
    ///
    /// Requires the `std` feature (uses [`bincode`] for serialization).
    ///
    /// # Examples
    ///
    /// ```
    /// # use keyhive_crypto::digest::Digest;
    /// #
    /// let digest = Digest::hash(&vec![1u8, 2, 3]);
    /// assert_eq!(digest.as_slice().len(), 32);
    /// ```
    #[cfg(feature = "std")]
    pub fn hash(preimage: &T) -> Self {
        let bytes: Vec<u8> = bincode::serialize(&preimage).expect("unable to serialize to bytes");

        Self {
            raw: blake3::hash(bytes.as_slice()),
            _phantom: PhantomData,
        }
    }

    /// Get the hash as a byte slice.
    ///
    /// # Examples
    ///
    /// ```
    /// # use keyhive_crypto::digest::Digest;
    /// #
    /// let digest = Digest::hash(&vec![1u8, 2, 3]);
    /// assert_eq!(
    ///     digest.as_slice(),
    ///     &[0x2A, 0x6D, 0x7F, 0x5B, 0x7F, 0x2A, 0x4A, 0x64,
    ///       0xA0, 0x14, 0x8F, 0xFC, 0xFA, 0x96, 0x94, 0x46,
    ///       0xEF, 0xD0, 0x95, 0xBE, 0xFE, 0x79, 0x79, 0x91,
    ///       0x29, 0xAB, 0x54, 0x8F, 0x8F, 0xC4, 0x42, 0x2B]
    /// );
    /// ```
    pub fn as_slice(&self) -> &[u8] {
        self.raw.as_bytes()
    }

    /// Returns the number of trailing zero _bits_ in the hash.
    ///
    /// # Example
    ///
    /// ```
    /// # use keyhive_crypto::digest::Digest;
    /// #
    /// let hash = Digest::hash(&"hello world!".to_string());
    /// assert_eq!(hash.trailing_zeros(), 3);
    ///
    /// let another_hash = Digest::hash(&"different!*".to_string());
    /// assert_eq!(another_hash.trailing_zeros(), 5);
    /// ```
    pub fn trailing_zeros(&self) -> u8 {
        let mut count = 0;

        for byte in self.raw.as_bytes().iter().rev() {
            let zeros = byte.count_zeros() as u8;
            count += zeros;

            if zeros != 8 {
                break;
            }
        }

        count
    }

    /// Returns the number of trailing zero _bytes_ in the hash.
    ///
    /// # Example
    ///
    /// ```
    /// # use keyhive_crypto::digest::Digest;
    /// #
    /// let hash = Digest::hash(&"hello world");
    /// assert_eq!(hash.trailing_zero_bytes(), 0);
    /// ```
    pub fn trailing_zero_bytes(&self) -> u8 {
        let mut count = 0;

        for byte in self.raw.as_bytes().iter().rev() {
            if *byte == 0 {
                count += 1;
            } else {
                break;
            }
        }

        count
    }

    /// Coerce a `Digest<T>` into a `Digest<U>`, preserving the underlying hash.
    ///
    /// This is useful for implementing `From` conversions between digest types
    /// that are considered equivalent (e.g. static/dynamic variants of the same type).
    pub fn coerce<U: Serialize>(&self) -> Digest<U> {
        Digest {
            raw: self.raw,
            _phantom: PhantomData,
        }
    }
}

#[cfg(all(feature = "std", any(test, feature = "arbitrary")))]
impl<'a, T: arbitrary::Arbitrary<'a> + Serialize> arbitrary::Arbitrary<'a> for Digest<T> {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let preimage = T::arbitrary(u)?;
        Ok(Digest::hash(&preimage))
    }
}

impl<T: Serialize> Serialize for Digest<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.raw.as_bytes().serialize(serializer)
    }
}

impl<'de, T: Serialize> serde::Deserialize<'de> for Digest<T> {
    fn deserialize<D>(deserializer: D) -> Result<Digest<T>, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes: [u8; 32] = Deserialize::deserialize(deserializer)?;
        Ok(Digest {
            raw: blake3::Hash::from(bytes),
            _phantom: PhantomData,
        })
    }
}

impl<T: Serialize> fmt::Display for Digest<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Digest({})", self.raw.to_hex())
    }
}

impl<T: Serialize> Copy for Digest<T> {}

impl<T: Serialize> Clone for Digest<T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T: Serialize> PartialEq for Digest<T> {
    fn eq(&self, other: &Self) -> bool {
        self.raw.as_bytes() == other.raw.as_bytes()
    }
}

impl<T: Serialize> Eq for Digest<T> {}

impl<T: Serialize> PartialOrd for Digest<T> {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl<T: Serialize> Ord for Digest<T> {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.raw.as_bytes().cmp(other.raw.as_bytes())
    }
}

impl<T: Serialize> Hash for Digest<T> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.raw.hash(state)
    }
}

impl<T: Serialize> From<blake3::Hash> for Digest<T> {
    fn from(hash: blake3::Hash) -> Self {
        Self {
            raw: hash,
            _phantom: PhantomData,
        }
    }
}

impl<T: Serialize> From<[u8; 32]> for Digest<T> {
    fn from(bytes: [u8; 32]) -> Self {
        Self {
            raw: blake3::Hash::from(bytes),
            _phantom: PhantomData,
        }
    }
}

impl<T: Serialize> From<Digest<T>> for blake3::Hash {
    fn from(hash: Digest<T>) -> Self {
        hash.raw
    }
}

impl<T: Serialize> From<Digest<T>> for [u8; 32] {
    fn from(hash: Digest<T>) -> [u8; 32] {
        hash.raw.into()
    }
}

impl<T: Serialize> From<Digest<T>> for Vec<u8> {
    fn from(hash: Digest<T>) -> Vec<u8> {
        hash.raw.as_bytes().to_vec()
    }
}
