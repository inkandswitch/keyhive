use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

pub type PublicKey = x25519_dalek::PublicKey;
pub type SecretKey = x25519_dalek::StaticSecret;

/// A SecretKeyMap is used to store the secret keys for all of the public keys
/// on your path that you have encountered so far (either because you added them
/// to your path as part of an update or decrypted them when decrypting your path).
#[derive(Clone, Deserialize, Serialize)]
pub struct SecretKeyMap(BTreeMap<Vec<u8>, SecretKey>);

impl SecretKeyMap {
    pub fn new() -> Self {
        SecretKeyMap(BTreeMap::new())
    }

    pub fn insert(&mut self, pk: PublicKey, sk: SecretKey) {
        self.0.insert(pk_to_bytes(&pk), sk);
    }

    pub fn get(&self, pk: &PublicKey) -> Option<&SecretKey> {
        self.0.get(&pk_to_bytes(pk))
    }

    pub fn contains_key(&self, pk: &PublicKey) -> bool {
        self.0.contains_key(&pk_to_bytes(pk))
    }
}

impl Default for SecretKeyMap {
    fn default() -> Self {
        Self::new()
    }
}

fn pk_to_bytes(pk: &PublicKey) -> Vec<u8> {
    pk.to_bytes().into()
}

#[derive(Clone, Eq, PartialEq, Deserialize, Serialize)]
pub enum NodeKey {
    PublicKey(PublicKey),
    // TODO: Check key count to be more than 1 when instantiating.
    ConflictKeys(Vec<PublicKey>),
}

impl NodeKey {
    pub fn keys(&self) -> Vec<PublicKey> {
        match self {
            Self::PublicKey(pk) => vec![*pk],
            Self::ConflictKeys(keys) => keys.clone(),
        }
    }

    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        match self {
            Self::PublicKey(_) => 1,
            Self::ConflictKeys(keys) => keys.len(),
        }
    }

    pub fn contains_key(&self, key: &PublicKey) -> bool {
        match self {
            Self::PublicKey(pk) => key == pk,
            Self::ConflictKeys(keys) => keys.contains(key),
        }
    }

    pub fn merge(&self, new_key: &NodeKey, removed: &[PublicKey]) -> Self {
        match self {
            NodeKey::ConflictKeys(keys) => {
                let mut new_keys = new_key.keys();
                for k in keys {
                    if !removed.contains(k) {
                        new_keys.push(*k);
                    }
                }
                new_keys.sort_by_key(|pk| pk.to_bytes());
                NodeKey::ConflictKeys(new_keys)
            }
            NodeKey::PublicKey(key) => {
                if removed.contains(key) {
                    new_key.clone()
                } else {
                    let mut new_keys = vec![*key];
                    new_keys.append(&mut new_key.keys());
                    new_keys.sort_by_key(|pk| pk.to_bytes());
                    NodeKey::ConflictKeys(new_keys)
                }
            }
        }
    }
}
