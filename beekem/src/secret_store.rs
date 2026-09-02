//! Secret store for inner tree nodes.

use crate::{
    collections::Set,
    encrypted::EncryptedSecret,
    error::CgkaError,
    keys::{ConflictKeys, NodeKey, ShareKeyMap},
    treemath::TreeNodeIndex,
};
use alloc::{collections::BTreeMap, string::ToString, vec, vec::Vec};
use core::cmp::Ordering;
use keyhive_crypto::share_key::{ShareKey, ShareSecretKey};
use nonempty::NonEmpty;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SecretStore {
    /// Every encrypted secret key (and hence version) corresponds to a single
    /// public key. There must be at least one.
    versions: NonEmpty<SecretStoreVersion>,
}

/// We implement here since deriving would require turning on a feature of
/// `NonEmpty` to get its `Arbitrary`.
#[cfg(any(test, feature = "arbitrary"))]
impl<'a> arbitrary::Arbitrary<'a> for SecretStore {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self {
            versions: NonEmpty {
                head: SecretStoreVersion::arbitrary(u)?,
                tail: Vec::<SecretStoreVersion>::arbitrary(u)?,
            },
        })
    }
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
            versions: NonEmpty::new(version),
        }
    }

    pub fn has_conflict(&self) -> bool {
        self.versions.len() > 1
    }

    pub fn node_key(&self) -> NodeKey {
        match self.versions.tail.as_slice() {
            [] => NodeKey::ShareKey(self.versions.head.pk),
            [second] => ConflictKeys {
                first: self.versions.head.pk,
                second: second.pk,
                more: vec![],
            }
            .into(),
            [second, more @ ..] => ConflictKeys {
                first: self.versions.head.pk,
                second: second.pk,
                more: more.iter().map(|v| v.pk).collect(),
            }
            .into(),
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
        self.versions
            .head
            .decrypt_secret(child_node_key, child_sks, seen_idxs)
    }

    /// Drop the versions corresponding to `removed_keys` and then merge `other`.
    pub fn merge(&mut self, other: &SecretStore, removed_keys: &Set<ShareKey>) {
        let kept: Vec<SecretStoreVersion> = self
            .versions
            .iter()
            .filter(|version| !removed_keys.contains(&version.pk))
            .cloned()
            .collect();

        self.versions = match NonEmpty::from_vec(kept) {
            Some(mut merged) => {
                merged.extend(other.versions.iter().cloned());
                merged
            }
            None => other.versions.clone(),
        };
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[cfg_attr(any(test, feature = "arbitrary"), derive(arbitrary::Arbitrary))]
pub struct SecretStoreVersion {
    /// Every encrypted secret key (and hence version) corresponds to a single public
    /// key.
    pub pk: ShareKey,
    /// This is a map in order to handle the case of blank siblings, when we must encrypt
    /// the same secret key separately for each public key in the sibling resolution.
    pub sk: BTreeMap<TreeNodeIndex, EncryptedSecret<ShareSecretKey>>,
    /// The PublicKey of the child that encrypted this parent.
    pub encrypter_pk: ShareKey,
}

impl SecretStoreVersion {
    pub fn decrypt_secret(
        &self,
        child_node_key: &NodeKey,
        child_sks: &mut ShareKeyMap,
        seen_idxs: &[TreeNodeIndex],
    ) -> Result<ShareSecretKey, CgkaError> {
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
            child_sks.try_decrypt_encryption(self.encrypter_pk, encrypted)?
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
