//! Helpers for working with hashes.

use super::signed::Signed;
use crate::{
    content::reference::ContentRef,
    event::Event,
    listener::membership::MembershipListener,
    principal::group::{
        delegation::{Delegation, StaticDelegation},
        membership_operation::{MembershipOperation, StaticMembershipOperation},
        revocation::{Revocation, StaticRevocation},
    },
};
use serde::{Deserialize, Serialize};
use std::{
    fmt,
    hash::{Hash, Hasher},
    marker::PhantomData,
};

/// A [`blake3::Digest`] tagged with which type it is a hash of.
///
/// This makes it easy to trace hash identifiers through the system.
///
/// # Example
///
/// ```
/// # use beehive_core::crypto::digest::Digest;
/// let string_hash: Digest<String> = Digest::hash(&"hello world".to_string());
/// let array_hash: Digest<[u8; 3]> = Digest::hash(&[1, 2, 3]);
/// let bytes_hash: Digest<Vec<u8>> = Digest::hash(&vec![42, 99]);
/// ```
#[derive(Debug)]
pub struct Digest<T: Serialize> {
    /// The underlying, unparameterized [`blake3::Digest`].
    pub raw: blake3::Hash,

    /// A phantom parameter to retain the type of the preimage.
    pub(crate) _phantom: PhantomData<T>,
}

impl<T: Serialize> Digest<T> {
    /// Digest a value and retain its type as a phantom parameter.
    pub fn hash(preimage: &T) -> Self {
        let bytes: Vec<u8> = bincode::serialize(&preimage).expect("unable to serialize to bytes");

        Self {
            raw: blake3::hash(bytes.as_slice()),
            _phantom: PhantomData,
        }
    }

    /// Get the hash as a byte slice.
    pub fn as_slice(&self) -> &[u8] {
        self.raw.as_bytes()
    }

    /// Returns the number of trailing zero _bits_ in the hash.
    ///
    /// # Example
    ///
    /// ```
    /// # use beehive_core::crypto::digest::Digest;
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
    /// # use beehive_core::crypto::digest::Digest;
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

    // NOTE a private helper for implementing From instances.
    // We do this instead of exposing it because only certain hash types
    // are considered equivalent.
    fn coerce<U: Serialize>(&self) -> Digest<U> {
        Digest {
            raw: self.raw,
            _phantom: PhantomData,
        }
    }
}

#[cfg(any(test, feature = "arbitrary"))]
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
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl<T: Serialize> Ord for Digest<T> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
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

// Casts

impl<T: ContentRef, L: MembershipListener<T>> From<Digest<Signed<Delegation<T, L>>>>
    for Digest<Signed<StaticDelegation<T>>>
{
    fn from(hash: Digest<Signed<Delegation<T, L>>>) -> Self {
        hash.coerce()
    }
}

impl<T: ContentRef, L: MembershipListener<T>> From<Digest<Signed<StaticDelegation<T>>>>
    for Digest<Signed<Delegation<T, L>>>
{
    fn from(hash: Digest<Signed<StaticDelegation<T>>>) -> Self {
        hash.coerce()
    }
}

impl<T: ContentRef, L: MembershipListener<T>> From<Digest<Signed<Revocation<T, L>>>>
    for Digest<Signed<StaticRevocation<T>>>
{
    fn from(hash: Digest<Signed<Revocation<T, L>>>) -> Self {
        hash.coerce()
    }
}

impl<T: ContentRef, L: MembershipListener<T>> From<Digest<Signed<StaticRevocation<T>>>>
    for Digest<Signed<Revocation<T, L>>>
{
    fn from(hash: Digest<Signed<StaticRevocation<T>>>) -> Self {
        hash.coerce()
    }
}

impl<T: ContentRef, L: MembershipListener<T>> From<&Digest<Signed<Delegation<T, L>>>>
    for Digest<Signed<StaticDelegation<T>>>
{
    fn from(hash: &Digest<Signed<Delegation<T, L>>>) -> Self {
        hash.coerce()
    }
}

impl<T: ContentRef, L: MembershipListener<T>> From<&Digest<Signed<StaticDelegation<T>>>>
    for Digest<Signed<Delegation<T, L>>>
{
    fn from(hash: &Digest<Signed<StaticDelegation<T>>>) -> Self {
        hash.coerce()
    }
}

impl<T: ContentRef, L: MembershipListener<T>> From<&Digest<Signed<Revocation<T, L>>>>
    for Digest<Signed<StaticRevocation<T>>>
{
    fn from(hash: &Digest<Signed<Revocation<T, L>>>) -> Self {
        hash.coerce()
    }
}

impl<T: ContentRef, L: MembershipListener<T>> From<&Digest<Signed<StaticRevocation<T>>>>
    for Digest<Signed<Revocation<T, L>>>
{
    fn from(hash: &Digest<Signed<StaticRevocation<T>>>) -> Self {
        hash.coerce()
    }
}

impl<T: ContentRef> From<Digest<Signed<StaticRevocation<T>>>>
    for Digest<StaticMembershipOperation<T>>
{
    fn from(hash: Digest<Signed<StaticRevocation<T>>>) -> Self {
        hash.coerce()
    }
}

impl<T: ContentRef> From<Digest<Signed<StaticDelegation<T>>>>
    for Digest<StaticMembershipOperation<T>>
{
    fn from(hash: Digest<Signed<StaticDelegation<T>>>) -> Self {
        hash.coerce()
    }
}

impl<T: ContentRef, L: MembershipListener<T>> From<Digest<MembershipOperation<T, L>>>
    for Digest<StaticMembershipOperation<T>>
{
    fn from(hash: Digest<MembershipOperation<T, L>>) -> Self {
        hash.coerce()
    }
}

impl<T: ContentRef> From<Digest<StaticMembershipOperation<T>>>
    for Digest<Signed<StaticDelegation<T>>>
{
    fn from(hash: Digest<StaticMembershipOperation<T>>) -> Self {
        hash.coerce()
    }
}

impl<T: ContentRef, L: MembershipListener<T>> From<Digest<StaticMembershipOperation<T>>>
    for Digest<Signed<Delegation<T, L>>>
{
    fn from(hash: Digest<StaticMembershipOperation<T>>) -> Self {
        hash.coerce()
    }
}

impl<T: ContentRef, L: MembershipListener<T>> From<Digest<StaticMembershipOperation<T>>>
    for Digest<Signed<Revocation<T, L>>>
{
    fn from(hash: Digest<StaticMembershipOperation<T>>) -> Self {
        hash.coerce()
    }
}

impl<T: ContentRef> From<Digest<StaticMembershipOperation<T>>>
    for Digest<Signed<StaticRevocation<T>>>
{
    fn from(hash: Digest<StaticMembershipOperation<T>>) -> Self {
        hash.coerce()
    }
}

impl<T: ContentRef, L: MembershipListener<T>> From<Digest<StaticMembershipOperation<T>>>
    for Digest<MembershipOperation<T, L>>
{
    fn from(hash: Digest<StaticMembershipOperation<T>>) -> Self {
        hash.coerce()
    }
}

impl<T: ContentRef, L: MembershipListener<T>> From<&Digest<StaticMembershipOperation<T>>>
    for Digest<MembershipOperation<T, L>>
{
    fn from(hash: &Digest<StaticMembershipOperation<T>>) -> Self {
        hash.coerce()
    }
}

impl<T: ContentRef, L: MembershipListener<T>> From<Digest<MembershipOperation<T, L>>>
    for Digest<Signed<Delegation<T, L>>>
{
    fn from(hash: Digest<MembershipOperation<T, L>>) -> Self {
        hash.coerce()
    }
}

impl<T: ContentRef, L: MembershipListener<T>> From<Digest<MembershipOperation<T, L>>>
    for Digest<Signed<Revocation<T, L>>>
{
    fn from(hash: Digest<MembershipOperation<T, L>>) -> Self {
        hash.coerce()
    }
}

impl<T: ContentRef, L: MembershipListener<T>> From<&Digest<MembershipOperation<T, L>>>
    for Digest<Signed<Delegation<T, L>>>
{
    fn from(hash: &Digest<MembershipOperation<T, L>>) -> Self {
        hash.coerce()
    }
}

impl<T: ContentRef, L: MembershipListener<T>> From<&Digest<MembershipOperation<T, L>>>
    for Digest<Signed<Revocation<T, L>>>
{
    fn from(hash: &Digest<MembershipOperation<T, L>>) -> Self {
        hash.coerce()
    }
}

impl<T: ContentRef, L: MembershipListener<T>> From<Digest<Signed<Delegation<T, L>>>>
    for Digest<MembershipOperation<T, L>>
{
    fn from(hash: Digest<Signed<Delegation<T, L>>>) -> Self {
        hash.coerce()
    }
}

impl<T: ContentRef, L: MembershipListener<T>> From<&Digest<Signed<Delegation<T, L>>>>
    for Digest<MembershipOperation<T, L>>
{
    fn from(hash: &Digest<Signed<Delegation<T, L>>>) -> Self {
        hash.coerce()
    }
}

impl<T: ContentRef, L: MembershipListener<T>> From<Digest<Signed<Revocation<T, L>>>>
    for Digest<MembershipOperation<T, L>>
{
    fn from(hash: Digest<Signed<Revocation<T, L>>>) -> Self {
        hash.coerce()
    }
}

impl<T: ContentRef, L: MembershipListener<T>> From<&Digest<Signed<Revocation<T, L>>>>
    for Digest<MembershipOperation<T, L>>
{
    fn from(hash: &Digest<Signed<Revocation<T, L>>>) -> Self {
        hash.coerce()
    }
}

impl<T: ContentRef, L: MembershipListener<T>> From<Digest<MembershipOperation<T, L>>>
    for Digest<Event<T, L>>
{
    fn from(hash: Digest<MembershipOperation<T, L>>) -> Self {
        hash.coerce()
    }
}
