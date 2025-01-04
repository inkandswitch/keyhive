use super::{
    error::CgkaError,
    keys::{ConflictKeys, NodeKey, ShareKeyMap},
    treemath::TreeNodeIndex,
};
use crate::crypto::{
    encrypted::NestedEncrypted,
    share_key::{ShareKey, ShareSecretKey},
};
use serde::{Deserialize, Serialize};
use std::{
    cmp::Ordering,
    collections::{BTreeMap, HashSet},
};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize, Serialize)]
pub struct SecretStore {
    /// Every encrypted secret key (and hence version) corresponds to a single
    /// public key.
    /// Invariant: public keys are in lexicographic order.
    /// Invariant: there should always be at least one version.
    versions: Vec<SecretStoreVersion>,
}

impl SecretStore {
    pub fn new(
        pk: ShareKey,
        encrypter_pk: ShareKey,
        sk: BTreeMap<TreeNodeIndex, NestedEncrypted<ShareSecretKey>>,
    ) -> Self {
        let version = SecretStoreVersion {
            pk,
            sk,
            encrypter_pk,
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
            NodeKey::ShareKey(self.versions[0].pk)
        } else {
            match self
                .versions
                .iter()
                .map(|s| s.pk)
                .collect::<Vec<_>>()
                .as_slice()
            {
                [] => unreachable!("There will always be at least one key"),
                [pk] => NodeKey::ShareKey(*pk),
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

    pub fn decrypt_secret(
        &self,
        child_node_key: &NodeKey,
        child_sks: &mut ShareKeyMap,
        seen_idxs: &[TreeNodeIndex],
    ) -> Result<ShareSecretKey, CgkaError> {
        if self.has_conflict() {
            return Err(CgkaError::UnexpectedKeyConflict);
        }
        self.versions[0].decrypt_secret(child_node_key, child_sks, seen_idxs)
    }

    pub fn decrypt_undecrypted_secrets(
        &self,
        child_node_key: &NodeKey,
        child_sks: &mut ShareKeyMap,
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
        removed_keys: &[ShareKey],
    ) -> Result<(), CgkaError> {
        self.remove_keys_from(removed_keys)?;
        self.versions.append(&mut other.versions.clone());
        self.sort_keys();
        Ok(())
    }

    // TODO: Make this more performant.
    fn remove_keys_from(&mut self, removed_keys: &[ShareKey]) -> Result<(), CgkaError> {
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

#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize, Serialize)]
pub(crate) struct SecretStoreVersion {
    /// Every encrypted secret key (and hence version) corresponds to a single public
    /// key.
    pub(crate) pk: ShareKey,
    /// This is a map in order to handle the case of blank siblings, when we must encrypt
    /// the same secret key separately for each public key in the sibling resolution.
    pub(crate) sk: BTreeMap<TreeNodeIndex, NestedEncrypted<ShareSecretKey>>,
    /// The PublicKey of the child that encrypted this parent.
    pub(crate) encrypter_pk: ShareKey,
}

impl SecretStoreVersion {
    pub(crate) fn decrypt_secret(
        &self,
        child_node_key: &NodeKey,
        child_sks: &ShareKeyMap,
        seen_idxs: &[TreeNodeIndex],
    ) -> Result<ShareSecretKey, CgkaError> {
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

        let decrypted: Vec<u8> = if is_encrypter {
            let secret_key = child_sks
                .get(&self.encrypter_pk)
                .ok_or(CgkaError::SecretKeyNotFound)?;

            encrypted
                .try_encrypter_decrypt(secret_key)
                .map_err(|e| CgkaError::Decryption(e.to_string()))?
        } else {
            child_sks.decrypt_nested_sibling_encryption(self.encrypter_pk, encrypted)?
        };

        let arr: [u8; 32] = decrypted.try_into().map_err(|_| CgkaError::Conversion)?;
        Ok(ShareSecretKey::force_from_bytes(arr))
    }
}

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
