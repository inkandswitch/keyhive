use super::{
    error::CgkaError,
    keys::{ConflictKeys, NodeKey},
    treemath::TreeNodeIndex,
};
use crate::{
    crypto::{
        encrypted::EncryptedSecret,
        share_key::{ShareKey, ShareSecretKey},
        signed::SigningError,
    },
    store::secret_key::traits::{DecryptionError, ShareSecretStore},
};
use derive_where::derive_where;
use serde::{Deserialize, Serialize};
use std::{
    cmp::Ordering,
    collections::{BTreeMap, HashSet},
};
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[cfg_attr(any(test, feature = "arbitrary"), derive(arbitrary::Arbitrary))]
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
        sk: BTreeMap<TreeNodeIndex, EncryptedSecret<ShareSecretKey>>,
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

    pub async fn decrypt_secret<S: ShareSecretStore>(
        &self,
        child_node_key: &NodeKey,
        child_sks: &mut S,
        seen_idxs: &[TreeNodeIndex],
    ) -> Result<S::SecretKey, DecryptSecretError<S>> {
        if self.has_conflict() {
            return Err(CgkaError::UnexpectedKeyConflict)?;
        }

        let secret = self.versions[0]
            .decrypt_secret(child_node_key, child_sks, seen_idxs)
            .await?;

        let imported = child_sks
            .import_secret_key(secret)
            .await
            .map_err(DecryptSecretError::ImportKeyError)?;

        Ok(imported)
    }

    // TODO: Is it possible we're bringing in duplicate keys here?
    pub fn merge(&mut self, other: &SecretStore, removed_keys: &HashSet<ShareKey>) {
        self.remove_keys_from(removed_keys);
        self.versions.append(&mut other.versions.clone());
    }

    fn remove_keys_from(&mut self, removed_keys: &HashSet<ShareKey>) {
        if removed_keys.is_empty() {
            return;
        }
        let mut new_versions = Vec::new();
        for (idx, version) in self.versions.iter().enumerate() {
            if !removed_keys.contains(&version.pk) {
                new_versions.push(self.versions[idx].clone());
            }
        }
        self.versions = new_versions;
    }
}

#[derive(Error)]
#[derive_where(Debug)]
pub enum DecryptSecretError<K: ShareSecretStore> {
    #[error(transparent)]
    CgkaError(#[from] CgkaError),

    #[error("Failed to decrypt the secret: {0}")]
    DecryptSecretError(#[from] StoreDecryptSecretError<K>),

    #[error("Failed to find a secret key: {0}")]
    GetSecretError(K::GetSecretError),

    #[error("Failed to import the secret key: {0}")]
    ImportKeyError(K::ImportKeyError),

    #[error("Unable to sign: {0}")]
    SigningError(#[from] SigningError),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[cfg_attr(any(test, feature = "arbitrary"), derive(arbitrary::Arbitrary))]
pub(crate) struct SecretStoreVersion {
    /// Every encrypted secret key (and hence version) corresponds to a single public
    /// key.
    pub(crate) pk: ShareKey,
    /// This is a map in order to handle the case of blank siblings, when we must encrypt
    /// the same secret key separately for each public key in the sibling resolution.
    pub(crate) sk: BTreeMap<TreeNodeIndex, EncryptedSecret<ShareSecretKey>>,
    /// The PublicKey of the child that encrypted this parent.
    pub(crate) encrypter_pk: ShareKey,
}

impl SecretStoreVersion {
    pub(crate) async fn decrypt_secret<S: ShareSecretStore>(
        &self,
        child_node_key: &NodeKey,
        child_sks: &S,
        seen_idxs: &[TreeNodeIndex],
    ) -> Result<ShareSecretKey, StoreDecryptSecretError<S>> {
        let is_encrypter = child_node_key.contains_key(&self.encrypter_pk);
        let mut lookup_idx = seen_idxs.last().ok_or(CgkaError::EncryptedSecretNotFound)?;
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
                return Err(CgkaError::EncryptedSecretNotFound)?;
            }
        }
        let encrypted = self
            .sk
            .get(lookup_idx)
            .ok_or(CgkaError::EncryptedSecretNotFound)?;

        let decrypted: Vec<u8> = if is_encrypter {
            let secret_key = child_sks
                .get_secret_key(&self.encrypter_pk)
                .await
                .map_err(StoreDecryptSecretError::GetSecretError)?
                .ok_or(CgkaError::SecretKeyNotFound)?;

            encrypted
                .try_encrypter_decrypt(&secret_key)
                .await
                .map_err(|e| CgkaError::Decryption(e.to_string()))?
        } else {
            child_sks
                .try_decrypt_encryption(self.encrypter_pk, encrypted)
                .await?
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

#[derive(Error)]
#[derive_where(Debug)]
pub enum StoreDecryptSecretError<K: ShareSecretStore> {
    #[error(transparent)]
    DecryptionError(#[from] DecryptionError<K>),

    #[error(transparent)]
    CgkaError(#[from] CgkaError),

    #[error("Failed to get the secret key: {0}")]
    GetSecretError(K::GetSecretError),
}
