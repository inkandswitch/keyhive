//! The [`Encoded<T>`] byte container.

use crate::{
    error::DecodeError,
    traits::{Decode, Encode},
};
use alloc::vec::Vec;
use core::{
    cmp::Ordering,
    fmt,
    hash::{Hash, Hasher},
    marker::PhantomData,
};

/// The canonical bytes of a `T`, tagged with the type they encode.
///
/// Equality, ordering, and hashing are by bytes. For certificate types this is
/// certificate identity, so a set of `Encoded<Certificate>` needs no separate
/// digest index.
///
/// The phantom is `fn() -> T` so that `Encoded<T>` is covariant in `T` and is
/// `Send + Sync` regardless of `T`.
pub struct Encoded<T> {
    bytes: Vec<u8>,
    _phantom: PhantomData<fn() -> T>,
}

impl<T> Encoded<T> {
    /// Wrap bytes that are already known to be the canonical encoding of a `T`.
    ///
    /// This is `pub` so that codec implementations and transports can construct
    /// an `Encoded<T>` from received bytes; it does not itself check anything.
    /// Callers that need the value MUST go through [`Encoded::decode`], which
    /// enforces canonicality.
    pub fn from_bytes_unchecked(bytes: Vec<u8>) -> Self {
        Self {
            bytes,
            _phantom: PhantomData,
        }
    }

    /// The encoded bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Consume, returning the encoded bytes.
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    /// Length of the encoding in bytes.
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Whether the encoding is empty.
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

impl<T: Encode> Encoded<T> {
    /// Encode a value.
    pub fn new(value: &T) -> Self {
        value.encode()
    }
}

impl<T: Decode> Encoded<T> {
    /// Decode the value, rejecting non-canonical bytes.
    pub fn decode(&self) -> Result<T, DecodeError> {
        T::decode(&self.bytes)
    }
}

impl<T> Clone for Encoded<T> {
    fn clone(&self) -> Self {
        Self::from_bytes_unchecked(self.bytes.clone())
    }
}

impl<T> fmt::Debug for Encoded<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Encoded<{}>({} bytes)",
            core::any::type_name::<T>(),
            self.bytes.len()
        )
    }
}

impl<T> PartialEq for Encoded<T> {
    fn eq(&self, other: &Self) -> bool {
        self.bytes == other.bytes
    }
}

impl<T> Eq for Encoded<T> {}

impl<T> PartialOrd for Encoded<T> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<T> Ord for Encoded<T> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.bytes.cmp(&other.bytes)
    }
}

impl<T> Hash for Encoded<T> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.bytes.hash(state)
    }
}

impl<T> AsRef<[u8]> for Encoded<T> {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

#[cfg(feature = "serde")]
impl<T> serde::Serialize for Encoded<T> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(&self.bytes)
    }
}

#[cfg(feature = "serde")]
impl<'de, T> serde::Deserialize<'de> for Encoded<T> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let bytes: Vec<u8> = serde::Deserialize::deserialize(deserializer)?;
        Ok(Self::from_bytes_unchecked(bytes))
    }
}
