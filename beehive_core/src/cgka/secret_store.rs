use super::{
    error::CgkaError,
    keys::{ConflictKeys, NodeKey, ShareKeyMap},
    treemath::{LeafNodeIndex, TreeNodeIndex},
};
use crate::{
    crypto::{
        encrypted::NestedEncrypted,
        share_key::{ShareKey, ShareSecretKey},
    },
    principal::individual::id::IndividualId,
};
use nonempty::NonEmpty;
use serde::{Deserialize, Serialize};
use std::{
    cmp::Ordering,
    collections::{BTreeMap, HashMap, HashSet},
    fmt,
};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize, Serialize)]
pub struct SecretStore {
    /// Invariant: Public keys are in lexicographic order.
    /// Every encrypted secret key (and hence version) corresponds to a single public key.
    /// Invariant: there should always be at least one version.
    versions: Vec<SecretStoreVersion>,
}

impl SecretStore {
    pub fn new() -> Self {
        Self {
            versions: Default::default(),
        }
    }

    pub fn from_keys(
        pk: ShareKey,
        encrypter_pk: ShareKey,
        // FIXME
        // encrypter_sk: Option<NestedEncrypted<ShareSecretKey>>,
        sk: BTreeMap<TreeNodeIndex, NestedEncrypted<ShareSecretKey>>,
        leaves: BTreeMap<LeafNodeIndex, IndividualId>,
    ) -> Self {
        let version = SecretStoreVersion {
            pk,
            sk,
            encrypter_pk,
            // FIXME
            // encrypter_sk,
            leaves,
        };
        Self {
            versions: vec![version],
        }
    }

    pub fn clear(&mut self) {
        self.versions.clear();
    }

    pub fn has_single_key(&self) -> bool {
        self.versions.len() == 1
    }

    pub fn has_keys(&self) -> bool {
        !self.versions.is_empty()
    }

    pub fn has_conflict(&self) -> bool {
        self.versions.len() > 1
    }

    pub fn node_key(&self) -> Option<NodeKey> {
        if !self.has_keys() {
            return None;
        }
        Some(if self.versions.len() == 1 {
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
        })
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
        if !self.has_keys() {
            return Err(CgkaError::ShareKeyNotFound);
        }
        self.versions[0].decrypt_secret(child_node_key, child_sks, seen_idxs)
    }

    pub fn decrypt_undecrypted_secrets(
        &self,
        child_node_key: &NodeKey,
        child_sks: &mut ShareKeyMap,
        seen_idxs: &[TreeNodeIndex],
    ) -> Result<(), CgkaError> {
        println!("-- decrypt_undecrypted_secrets()");
        for version in &self.versions {
            println!("NEXT VERSION: {:?}, encrypter_pk: {:?}", version, version.encrypter_pk);
            println!("\nChild node key: {:?}", child_node_key);
            println!("\nSeen idxs: {:?}", seen_idxs);
            if !child_sks.contains_key(&version.pk) {
                println!("-- -- decrypting for version pk {:?}", version.pk);
                let secret = version.decrypt_secret(child_node_key, child_sks, seen_idxs)?;
                child_sks.insert(version.pk, secret);
            }
        }
        println!("-- -- EXITING decrypt_undecrypted");
        Ok(())
    }

    // TODO: Is it possible we're bringing in duplicate keys here?
    pub fn merge(
        &mut self,
        other: &SecretStore,
        removed_keys: &[ShareKey],
    ) -> Result<(), CgkaError> {
        self.remove_keys_from(removed_keys)?;
        println!("-- -- MERGING SECRET STORE {:?}", other.versions);
        self.versions.append(&mut other.versions.clone());
        println!("-- -- -- Node key after merge: {:?}", self.node_key());
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

    pub fn encryption_contributors(
        &self,
    ) -> (
        HashMap<TreeNodeIndex, NodeKey>,
        HashMap<LeafNodeIndex, IndividualId>,
    ) {
        let mut m: HashMap<TreeNodeIndex, NonEmpty<ShareKey>> = HashMap::new();
        let mut leaves: HashMap<LeafNodeIndex, IndividualId> = HashMap::new();
        for v in &self.versions {
            println!("-- -- -- Encrypter pk is {:?}", v.encrypter_pk);
            for (idx, nested) in &v.sk {
                if m.contains_key(&idx) {
                    let ks = m.get_mut(&idx).expect("key to exist");
                    for l in &nested.layers {
                        ks.push(l.0);
                    }
                } else {
                    m.insert(
                        *idx,
                        NonEmpty::from_vec(nested.layers.iter().map(|l| l.0).collect::<Vec<_>>())
                            .expect("FIXME"),
                    );
                }
                if let TreeNodeIndex::Leaf(l_idx) = idx {
                    leaves.insert(*l_idx, *v.leaves.get(&l_idx).expect("leaf to be present"));
                }
            }
        }
        (
            m.iter()
                .map(|(idx, keys)| (*idx, keys.into()))
                .collect::<HashMap<_, _>>(),
            leaves,
        )
    }

    fn sort_keys(&mut self) {
        self.versions.sort();
    }
}

impl Default for SecretStore {
    fn default() -> Self {
        Self::new()
    }
}

// FIXME
// #[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[derive(Clone, PartialEq, Eq, Hash, Deserialize, Serialize)]
pub(crate) struct SecretStoreVersion {
    /// Every encrypted secret key (and hence version) corresponds to a single public key.
    pub(crate) pk: ShareKey,
    /// This is a map in order to handle the case of blank siblings, when we must encrypt
    /// the same secret key separately for each public key in the sibling resolution.
    pub(crate) sk: BTreeMap<TreeNodeIndex, NestedEncrypted<ShareSecretKey>>,
    /// The ids of any leaf nodes represented in the secrets map
    pub(crate) leaves: BTreeMap<LeafNodeIndex, IndividualId>,
    /// The PublicKey of the child that encrypted this parent.
    pub(crate) encrypter_pk: ShareKey,
    // FIXME
    // /// The encrypted secret key for the encrypter
    // pub(crate) encrypter_sk: Option<NestedEncrypted<ShareSecretKey>>,
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
                println!("-- -- !found key for idx in seen_idxs {:?}", seen_idxs);
                return Err(CgkaError::EncryptedSecretNotFound);
            }
        }
        let encrypted = self
            .sk
            .get(lookup_idx)
            .ok_or(CgkaError::EncryptedSecretNotFound)?;
        let decrypted: Vec<u8> = if is_encrypter {
            // FIXME
            // println!("-- -- Looking up encrypter sk");
            // let Some(ref encrypted) = self.encrypter_sk else {
            //     return Err(CgkaError::EncryptedSecretNotFound);
            // };
            println!("\n\n\n\nSecretStore::decrypt_secret() lookup secret key");
            let secret_key = child_sks
                .get(&self.encrypter_pk)
                .ok_or(CgkaError::SecretKeyNotFound)?;

            encrypted
                .try_encrypter_decrypt(secret_key)
                .map_err(|e| CgkaError::Decryption(e.to_string()))?
        } else {
            // println!("-- -- about to get from node sk BTreeMap");
            // let encrypted = self
            //     .sk
            //     .get(lookup_idx)
            //     .ok_or(CgkaError::EncryptedSecretNotFound)?;
            // println!("-- -- GOT from node sk BTreeMap");
            child_sks.decrypt_nested_sibling_encryption(self.encrypter_pk, encrypted)?
        };
        println!("-- -- GOT SK");

        let arr: [u8; 32] = decrypted.try_into().map_err(|_| CgkaError::Conversion)?;
        Ok(ShareSecretKey::force_from_bytes(arr))
    }
}

impl fmt::Debug for SecretStoreVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SecretStoreVersion(pk:{:?},sk_idxs:{:?})",
            self.pk,
            self.sk.keys()
        )
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
