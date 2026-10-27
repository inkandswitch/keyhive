//! The [`Encoded<T>`] byte container.

use crate::{error::DecodeError, traits::Decode};
use alloc::vec::Vec;
use core::{
    cmp::Ordering,
    fmt,
    hash::{Hash, Hasher},
    marker::PhantomData,
};

/// Bytes that claim to encode a `T`, tagged with the type.
///
/// The type does not check the claim. [`Encode::encode`](crate::traits::Encode::encode) produces canonical
/// bytes, but [`Encoded::from_bytes_unchecked`] wraps whatever a transport
/// received; [`Encoded::decode`] is the check. Equality, ordering, and hashing
/// are by bytes, so for bytes that decode canonically, equal bytes mean equal
/// values.
///
/// The phantom is `fn() -> T` so that `Encoded<T>` is covariant in `T` and is
/// `Send + Sync` regardless of `T`.
pub struct Encoded<T> {
    bytes: Vec<u8>,
    _phantom: PhantomData<fn() -> T>,
}

impl<T> Encoded<T> {
    /// Wrap bytes that claim to encode a `T`, without checking the claim.
    ///
    /// For codec implementations and transports holding received bytes. Get
    /// the value through [`Encoded::decode`], which enforces canonicality.
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

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::hash::DefaultHasher;

    fn sample() -> Encoded<()> {
        Encoded::from_bytes_unchecked(alloc::vec![1, 2, 3, 255])
    }

    fn other() -> Encoded<()> {
        Encoded::from_bytes_unchecked(alloc::vec![1, 2, 4])
    }

    fn hash(value: &Encoded<()>) -> u64 {
        let mut state = DefaultHasher::new();
        value.hash(&mut state);
        state.finish()
    }

    #[test]
    fn length_and_bytes() {
        assert_eq!(sample().len(), 4);
        assert!(!sample().is_empty());
        assert!(Encoded::<()>::from_bytes_unchecked(Vec::new()).is_empty());
        assert_eq!(sample().as_ref(), &[1, 2, 3, 255]);
        assert_eq!(sample().as_bytes(), sample().as_ref());
    }

    /// Identity, order, and hash are all by bytes, and agree with each other.
    #[test]
    fn identity_is_bytes() {
        assert_eq!(sample(), sample());
        assert_ne!(sample(), other());
        assert_eq!(
            sample().cmp(&other()),
            [1u8, 2, 3, 255][..].cmp(&[1, 2, 4][..])
        );
        assert_eq!(sample().partial_cmp(&other()), Some(Ordering::Less));
        assert_eq!(hash(&sample()), hash(&sample()));
    }
}
