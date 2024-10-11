use std::{
    cmp::Ordering,
    collections::{BTreeMap, HashSet},
};

use serde::{Deserialize, Serialize};
use x25519_dalek::StaticSecret;

use crate::crypto::encrypted::NestedEncrypted;

use super::{
    crypto::{decrypt_nested_secret, generate_shared_key},
    error::CgkaError,
    keys::{NodeKey, PublicKey, SecretKey, SecretKeyMap},
    treemath::TreeNodeIndex,
};

#[derive(Clone, Deserialize, Serialize)]
pub struct SecretStore {
    /// Invariant: Public keys are in lexicographic order.
    /// Every encrypted secret key (and hence version) corresponds to a single public key.
    /// Invariant: there should always be at least one version.
    versions: Vec<SecretStoreVersion>,
}

impl SecretStore {
    pub fn new(
        pk: PublicKey,
        encrypter_pk: PublicKey,
        encrypter_paired_pk: Option<NodeKey>,
        sk: BTreeMap<TreeNodeIndex, NestedEncrypted<SecretKey>>,
    ) -> Self {
        let version = SecretStoreVersion {
            pk,
            sk,
            encrypter_pk,
            encrypter_paired_node_key: encrypter_paired_pk,
        };
        Self {
            versions: vec![version],
        }
    }

    pub fn has_conflict(&self) -> bool {
        self.versions.len() > 1
    }

    pub fn node_key(&self) -> NodeKey {
        if self.versions.len() == 1 {
            NodeKey::PublicKey(self.versions[0].pk)
        } else {
            NodeKey::ConflictKeys(self.versions.iter().map(|s| s.pk).collect())
        }
    }

    pub fn decrypt_secret(
        &self,
        child_node_key: &NodeKey,
        child_sks: &mut SecretKeyMap,
        seen_idxs: &[TreeNodeIndex],
    ) -> Result<SecretKey, CgkaError> {
        if self.has_conflict() {
            return Err(CgkaError::UnexpectedKeyConflict);
        }
        self.versions[0].decrypt_secret(child_node_key, child_sks, seen_idxs)
    }

    pub fn decrypt_undecrypted_secrets(
        &self,
        // child_idx: TreeNodeIndex,
        child_node_key: &NodeKey,
        child_sks: &mut SecretKeyMap,
        seen_idxs: &[TreeNodeIndex],
    ) -> Result<(), CgkaError> {
        for version in &self.versions {
            if !child_sks.contains_key(&version.pk) {
                let secret = version.decrypt_secret(child_node_key, child_sks, seen_idxs)?;
                child_sks.insert(version.pk, secret);
            }
        }
        Ok(())
    }

    // TODO: Is it possible we're bringing in duplicate keys here?
    pub fn merge(
        &mut self,
        other: &SecretStore,
        removed_keys: &[PublicKey],
    ) -> Result<(), CgkaError> {
        self.remove_keys_from(removed_keys)?;
        self.versions.append(&mut other.versions.clone());
        self.sort_keys();
        Ok(())
    }

    // TODO: Make this more performant.
    fn remove_keys_from(&mut self, removed_keys: &[PublicKey]) -> Result<(), CgkaError> {
        if removed_keys.is_empty() {
            return Ok(());
        }
        let mut remove_idxs = HashSet::new();
        let mut new_versions = Vec::new();
        for (idx, version) in self.versions.iter().enumerate() {
            if removed_keys.contains(&version.pk) {
                remove_idxs.insert(idx);
            } else {
                new_versions.push(self.versions[idx].clone());
            }
        }
        self.versions = new_versions;
        Ok(())
    }

    fn sort_keys(&mut self) {
        self.versions.sort();
    }
}

#[derive(Clone, Deserialize, Serialize)]
pub(crate) struct SecretStoreVersion {
    /// Every encrypted secret key (and hence version) corresponds to a single public key.
    pub(crate) pk: PublicKey,
    /// This is a map in order to handle the case of blank siblings, when we must encrypt
    /// the same secret key separately for each public key in the sibling resolution.
    pub(crate) sk: BTreeMap<TreeNodeIndex, NestedEncrypted<SecretKey>>,
    /// The PublicKey of the child that encrypted this parent.
    pub(crate) encrypter_pk: PublicKey,
    /// If this is None, the sibling subtree was blank when encrypting this parent.
    /// Otherwise, it represents the first node in the sibling resolution, which the
    /// encrypter used for its own Diffie Hellman shared secret.
    /// Invariant: PublicKeys must be in lexicographic order
    pub(crate) encrypter_paired_node_key: Option<NodeKey>,
}

impl SecretStoreVersion {
    pub(crate) fn decrypt_secret(
        &self,
        child_node_key: &NodeKey,
        child_sks: &SecretKeyMap,
        seen_idxs: &[TreeNodeIndex],
    ) -> Result<SecretKey, CgkaError> {
        let is_encrypter = child_node_key.contains_key(&self.encrypter_pk);
        let mut lookup_idx = seen_idxs.last().ok_or(CgkaError::EncryptedSecretNotFound)?;
        // TODO: Refactor with fewer lines
        if !self.sk.contains_key(lookup_idx) {
            let mut found = false;
            for idx in seen_idxs.iter().rev().skip(1) {
                if self.sk.contains_key(idx) {
                    lookup_idx = idx;
                    found = true;
                    break;
                }
            }
            if !found {
                return Err(CgkaError::EncryptedSecretNotFound);
            }
        }
        let encrypted = self
            .sk
            .get(lookup_idx)
            .ok_or(CgkaError::EncryptedSecretNotFound)?;
        let decrypt_keys: Vec<SecretKey> = if is_encrypter {
            let secret_key = child_sks
                .get(&self.encrypter_pk)
                .ok_or(CgkaError::SecretKeyNotFound)?;
            if let Some(pair_keys) = &self.encrypter_paired_node_key {
                pair_keys
                    .keys()
                    .iter()
                    .map(|pk| generate_shared_key(pk, secret_key))
                    .collect()
            } else {
                vec![secret_key.clone()]
            }
        } else {
            encrypted
                .paired_pks
                .iter()
                .map(|pk| {
                    let secret_key_result = child_sks.get(pk);
                    if let Some(secret_key) = secret_key_result {
                        Ok(generate_shared_key(&self.encrypter_pk, secret_key))
                    } else {
                        Err(CgkaError::SecretKeyNotFound)
                    }
                })
                .collect::<Result<Vec<StaticSecret>, CgkaError>>()?
        };
        decrypt_nested_secret(encrypted, &decrypt_keys)
    }
}

impl PartialEq for SecretStoreVersion {
    fn eq(&self, other: &Self) -> bool {
        self.pk == other.pk
            && self.encrypter_pk == other.encrypter_pk
            && self.encrypter_paired_node_key == other.encrypter_paired_node_key
        // TODO: Hashes
        // && self.sk.hash() == other.sk.hash()
    }
}
impl Eq for SecretStoreVersion {}

impl Ord for SecretStoreVersion {
    fn cmp(&self, other: &Self) -> Ordering {
        self.pk.to_bytes().cmp(&other.pk.to_bytes())
    }
}

impl PartialOrd for SecretStoreVersion {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
