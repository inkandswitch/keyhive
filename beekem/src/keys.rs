//! Share key management for CGKA tree nodes.

use crate::{
    encrypted::{EncryptedSecret, Sealable},
    error::CgkaError,
    id::TreeId,
    node_versions::NodeVersions,
    transact::{Fork, Merge},
};
use alloc::{collections::BTreeMap, string::ToString, vec, vec::Vec};
use keyhive_crypto::share_key::{ShareKey, ShareSecretKey};
use nonempty::NonEmpty;
use zeroize::Zeroizing;

/// A key pair at a BeeKEM leaf.
pub type LeafKeyPair = (ShareKey, ShareSecretKey);

/// A [`ShareKeyMap`] stores the secret keys for all of the public keys
/// on your path that you have encountered so far (either because you added them
/// to your path as part of an update or decrypted them when decrypting your path).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ShareKeyMap(BTreeMap<ShareKey, ShareSecretKey>);

impl ShareKeyMap {
    pub fn new() -> Self {
        ShareKeyMap(BTreeMap::new())
    }

    pub fn insert(&mut self, pk: ShareKey, sk: ShareSecretKey) {
        self.0.insert(pk, sk);
    }

    pub fn get(&self, pk: &ShareKey) -> Option<&ShareSecretKey> {
        self.0.get(pk)
    }

    pub fn contains_key(&self, pk: &ShareKey) -> bool {
        self.0.contains_key(pk)
    }

    pub fn try_decrypt_encryption<T: Sealable>(
        &self,
        doc_id: TreeId,
        encrypter_pk: ShareKey,
        encrypted: &EncryptedSecret<T>,
    ) -> Result<Zeroizing<Vec<u8>>, CgkaError> {
        let sk = self
            .get(&encrypted.paired_pk)
            .ok_or(CgkaError::SecretKeyNotFound)?;
        encrypted
            .try_paired_decrypt(doc_id, sk, &encrypter_pk)
            .map_err(|e| CgkaError::Decryption(e.to_string()))
    }

    /// The number of share keys in the map.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the map contains no share keys.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn extend(&mut self, other: &ShareKeyMap) {
        self.0
            .extend(other.0.iter().map(|(pk, sk)| (*pk, sk.clone())));
    }
}

impl Fork for ShareKeyMap {
    type Forked = Self;

    fn fork(&self) -> Self::Forked {
        self.clone()
    }
}

impl Merge for ShareKeyMap {
    fn merge(&mut self, fork: Self::Forked) {
        self.0.extend(fork.0)
    }
}

impl core::hash::Hash for ShareKeyMap {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.0.keys().for_each(|k| k.hash(state));
    }
}

/// Node keys can be either a single share key or a set of conflict keys.
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
#[cfg_attr(any(test, feature = "arbitrary"), derive(arbitrary::Arbitrary))]
pub enum NodeKeys {
    ShareKey(ShareKey),
    ConflictKeys(ConflictKeys),
}

impl From<ShareKey> for NodeKeys {
    fn from(item: ShareKey) -> Self {
        NodeKeys::ShareKey(item)
    }
}

/// Keys that were concurrently added to the same node.
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
#[cfg_attr(any(test, feature = "arbitrary"), derive(arbitrary::Arbitrary))]
pub struct ConflictKeys {
    pub first: ShareKey,
    pub second: ShareKey,
    pub more: Vec<ShareKey>,
}

impl ConflictKeys {
    pub fn push(&mut self, key: ShareKey) {
        self.more.push(key);
    }

    pub fn contains(&self, key: &ShareKey) -> bool {
        self.first == *key || self.second == *key || self.more.contains(key)
    }

    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        2 + self.more.len()
    }

    pub fn iter(&self) -> impl Iterator<Item = &ShareKey> {
        core::iter::once(&self.first)
            .chain(core::iter::once(&self.second))
            .chain(self.more.iter())
    }
}

impl From<ConflictKeys> for NodeKeys {
    fn from(keys: ConflictKeys) -> Self {
        NodeKeys::ConflictKeys(keys)
    }
}

impl From<ConflictKeys> for Vec<ShareKey> {
    fn from(keys: ConflictKeys) -> Self {
        let mut all_keys = vec![keys.first, keys.second];
        all_keys.append(&mut keys.more.clone());
        all_keys
    }
}

impl NodeKeys {
    pub fn keys(&self) -> Vec<ShareKey> {
        match self {
            Self::ShareKey(pk) => vec![*pk],
            Self::ConflictKeys(keys) => keys.clone().into(),
        }
    }

    pub fn lowest(&self) -> ShareKey {
        match self {
            Self::ShareKey(pk) => *pk,
            Self::ConflictKeys(keys) => keys
                .iter()
                .copied()
                .min()
                .expect("ConflictKeys holds at least two keys"),
        }
    }

    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        match self {
            Self::ShareKey(_) => 1,
            Self::ConflictKeys(keys) => keys.len(),
        }
    }

    pub fn contains_key(&self, key: &ShareKey) -> bool {
        match self {
            Self::ShareKey(pk) => key == pk,
            Self::ConflictKeys(keys) => keys.contains(key),
        }
    }

    /// The `NodeKeys` with `keys`, which must be ascending.
    pub(crate) fn from_ascending(keys: NonEmpty<ShareKey>) -> Self {
        let NonEmpty { head: first, tail } = keys;
        let mut keys = tail.into_iter();
        match keys.next() {
            None => NodeKeys::ShareKey(first),
            Some(second) => ConflictKeys {
                first,
                second,
                more: keys.collect(),
            }
            .into(),
        }
    }
}

/// A value at a tree node that has a share key.
pub trait HasShareKey {
    /// The value's share key.
    fn share_key(&self) -> ShareKey;
}

impl HasShareKey for ShareKey {
    fn share_key(&self) -> ShareKey {
        *self
    }
}

impl<V: HasShareKey + Ord + Clone> NodeVersions<V> {
    /// The node's share keys, one per version.
    pub fn node_keys(&self) -> NodeKeys {
        NodeKeys::from_ascending(self.values().map(HasShareKey::share_key))
    }
}
