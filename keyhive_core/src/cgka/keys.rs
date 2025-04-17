use crate::{
    crypto::{
        encrypted::EncryptedSecret,
        share_key::{ShareKey, ShareSecretKey},
    },
    transact::{fork::Fork, merge::Merge},
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use super::error::CgkaError;

/// A [`ShareKeyMap`] is used to store the secret keys for all of the public keys
/// on your path that you have encountered so far (either because you added them
/// to your path as part of an update or decrypted them when decrypting your path).
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
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

    pub fn try_decrypt_encryption(
        &self,
        encrypter_pk: ShareKey,
        encrypted: &EncryptedSecret<ShareSecretKey>,
    ) -> Result<Vec<u8>, CgkaError> {
        let sk = self
            .get(&encrypted.paired_pk)
            .ok_or(CgkaError::SecretKeyNotFound)?;
        let key = sk.derive_symmetric_key(&encrypter_pk);
        let mut buf = encrypted.ciphertext.clone();
        key.try_decrypt(encrypted.nonce, &mut buf)
            .map_err(|e| CgkaError::Decryption(e.to_string()))?;
        Ok(buf)
    }

    pub fn extend(&mut self, other: &ShareKeyMap) {
        self.0.extend(other.0.iter());
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

impl std::hash::Hash for ShareKeyMap {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.keys().for_each(|k| k.hash(state));
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize)]
#[cfg_attr(any(test, feature = "arbitrary"), derive(arbitrary::Arbitrary))]
pub enum NodeKey {
    ShareKey(ShareKey),
    ConflictKeys(ConflictKeys),
}

impl From<ShareKey> for NodeKey {
    fn from(item: ShareKey) -> Self {
        NodeKey::ShareKey(item)
    }
}

/// Keys that were concurrently added to the same node.
#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize)]
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
        std::iter::once(&self.first)
            .chain(std::iter::once(&self.second))
            .chain(self.more.iter())
    }
}

impl From<ConflictKeys> for NodeKey {
    fn from(keys: ConflictKeys) -> Self {
        NodeKey::ConflictKeys(keys)
    }
}

impl From<ConflictKeys> for Vec<ShareKey> {
    fn from(keys: ConflictKeys) -> Self {
        let mut all_keys = vec![keys.first, keys.second];
        all_keys.append(&mut keys.more.clone());
        all_keys
    }
}

impl NodeKey {
    pub fn keys(&self) -> Vec<ShareKey> {
        match self {
            Self::ShareKey(pk) => vec![*pk],
            Self::ConflictKeys(keys) => keys.clone().into(),
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

    /// Merge in a new [`NodeKey`].
    ///
    /// # Arguments
    ///
    /// * `self`
    /// * `new_key` —  The new key to merge into the existing keys.
    /// * `removed` —  The keys removed as part of a [`PathChange`](super::beekem::PathChange).
    ///                It's possible that `self` will be one of those,
    ///                in which case a new key is substituted.
    pub fn merge(&self, new_key: &NodeKey, removed: &[ShareKey]) -> Self {
        match self {
            NodeKey::ShareKey(key) => {
                if removed.contains(key) {
                    new_key.clone()
                } else {
                    let mut new_keys = new_key.keys();
                    new_keys.push(*key);
                    new_keys.sort();

                    match new_keys.as_slice() {
                        [] => unreachable!("No keys to merge"),
                        [first] => NodeKey::ShareKey(*first),
                        [first, second] => ConflictKeys {
                            first: *first,
                            second: *second,
                            more: vec![],
                        }
                        .into(),
                        [first, second, more @ ..] => ConflictKeys {
                            first: *first,
                            second: *second,
                            more: more.to_vec(),
                        }
                        .into(),
                    }
                }
            }
            NodeKey::ConflictKeys(keys) => {
                let mut new_keys = new_key.keys();
                for k in keys.iter() {
                    if !removed.contains(k) {
                        new_keys.push(*k);
                    }
                }
                new_keys.sort_by_key(|pk| *pk);

                match new_keys.as_slice() {
                    [] => unreachable!("No keys to merge"),
                    [first] => NodeKey::ShareKey(*first),
                    [first, second] => ConflictKeys {
                        first: *first,
                        second: *second,
                        more: vec![],
                    }
                    .into(),
                    [first, second, more @ ..] => ConflictKeys {
                        first: *first,
                        second: *second,
                        more: more.to_vec(),
                    }
                    .into(),
                }
            }
        }
    }
}
