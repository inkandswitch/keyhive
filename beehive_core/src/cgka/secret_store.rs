/// * In normal case, each node has a single public key and an encrypted secret key.
///   That secret is encrypted by one child using the pk of its sibling for DH.
/// * In blank sibling case, the encrypting child encrypts the secret for each of the nodes
///   in its sibling's resolution (and stores that one in an entry in a map corresponding
///   to the node). This means a separate DH per node in that resolution.
/// * If the sibling has multiple public keys (because of a merge conflict), then the
///   encrypter must use the nested encryption method for encrypting the new secret key
///   for the parent (using it's secret key with each of the (sorted) public keys of its
///   sibling to create a nested encryption).
/// * * An encrypter will always have one public key because it overwrites conflicts on
///     its path as it ascends the tree.
/// * * A node with multiple public keys will also have multiple corresponding encrypted
///     secret keys. On decryption, any leaf with a conflict node on its path will need
///     all those secret keys to do the nested decryption of the conflict node's parent.
/// * * Encryption of a parent of a conflict node will always result in one public key
///     and one (nested) encrypted secret key for that parent.
/// * * Note that a node with multiple conflict keys will not have a single secret key. It
///     will have a secret key per public key. Unfortunately, those might be nested
///     encryptions too(?).
/// * * When starting a decryption, you pass in your map of public keys to decrypted
///     secret keys. If you hit new public keys on the way up, you add the decrypted
///     secret keys to that map. This map allows you to always look up secret keys for
///     nested decryptions.
/// * Problems
/// * * Only a child of a node can propose a secret key for that node.
/// * * On a merge, the merger might not have the conflict node on its path.
/// * *
///
/// * Invariants
/// * * I should always have the secret keys I need to decrypt my path, even when there
///     are conflicts along it. That's because I will have every update made at my leaf.
///


use std::{cmp::Ordering, collections::{BTreeMap, HashSet}, fmt::{self, Debug, Formatter}};

use serde::{Deserialize, Serialize};
use x25519_dalek::{x25519, StaticSecret};

use crate::crypto::{encrypted::{Encrypted, NestedEncrypted}, siv::Siv, symmetric_key::SymmetricKey};

use super::{beekem::{PublicKey, SecretKey}, error::CGKAError, treemath::TreeNodeIndex, CGKA};

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

fn pk_to_bytes(pk: &PublicKey) -> Vec<u8> {
    pk.to_bytes().into()
}


#[derive(Clone, Eq, PartialEq, Deserialize, Serialize)]
pub struct Multikey {
    /// Invariant: PublicKeys must be in lexicographic order
    pub keys: Vec<PublicKey>,
}

impl Multikey {
    pub fn from_iter(keys_iter: impl Iterator<Item = PublicKey>) -> Self {
        Self {
            keys: keys_iter.collect()
        }
    }

    pub fn len(&self) -> usize {
        self.keys.len()
    }

    pub fn has_conflict(&self) -> bool {
        self.keys.len() > 1
    }

    pub fn push(&mut self, key: PublicKey) {
        self.keys.push(key);
    }

    pub fn append(&mut self, other: &Multikey) {
        self.keys.append(&mut other.keys.clone());
    }

    pub fn contains(&self, pk: &PublicKey) -> bool {
        self.keys.contains(pk)
    }

    pub fn first_public_key(&self) -> PublicKey {
        debug_assert!(self.keys.len() > 0);
        self.keys[0]
    }

    pub fn keys(&self) -> impl Iterator<Item = &PublicKey> {
        self.keys.iter()
    }
}

impl Debug for Multikey {
  fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
    f.debug_struct("Multikey")
      .field("keys", &self.keys.iter().map(|pk| pk.to_bytes()))
      .finish()
  }
}

#[derive(Clone, Deserialize, Serialize)]
pub struct SecretStore {
    /// The PublicKeys corresponding to the versions.
    /// Every encrypted secret key (and hence version) corresponds to a single public key.
    // TODO: It's error prone to have to keep this in sync with the versions list.
    // But if we don't, we always have to calculate the multikey from the pks of the
    // versions when the multikey of a node is needed.
    multikey: Multikey,
    /// Invariant: there should always be at least one
    versions: Vec<SecretStoreVersion>,
}

impl SecretStore {
    // TODO: Constructor
    pub fn new(pk: PublicKey, encrypter_pk: PublicKey, encrypter_paired_pk: Option<Multikey>, sk: BTreeMap<TreeNodeIndex, NestedEncrypted<SecretKey>>) -> Self {
        let version = SecretStoreVersion {
            pk,
            sk,
            encrypter_pk,
            encrypter_paired_multikey: encrypter_paired_pk,
        };
        Self {
            multikey: Multikey { keys: vec![pk] },
            versions: vec![version],
        }
    }

    pub fn has_conflict(&self) -> bool {
        self.versions.len() > 1
    }

    pub fn multikey(&self) -> &Multikey {
        &self.multikey
    }

    // TODO: Handle multiple child pks
    pub fn decrypt_secret(&self, child_idx: TreeNodeIndex, child_multikey: &Multikey, child_sks: &mut SecretKeyMap) -> Result<SecretKey, CGKAError> {
        if self.has_conflict() {
            return Err(CGKAError::UnexpectedKeyConflict);
        }
        // TODO: Should we just use the map instead of returning a secret. And then we just
        // call the decrypt_undecrypted_secrets method here?
        self.versions[0].decrypt_secret(child_idx, child_multikey, child_sks)
    }

    pub fn decrypt_undecrypted_secrets(&self, child_idx: TreeNodeIndex, child_multikey: &Multikey, child_sks: &mut SecretKeyMap) -> Result<(), CGKAError> {
        debug_assert_eq!(self.multikey.len(), self.versions.len());
        for (pk, version) in self.multikey.keys().zip(&self.versions) {
            if !child_sks.contains_key(pk) {
                let secret = version.decrypt_secret(child_idx, child_multikey, child_sks)?;
                child_sks.insert(*pk, secret);
            }
        }
        Ok(())
    }

    pub fn single_pk(&self) -> Option<PublicKey> {
        debug_assert!(self.versions.len() >= 1);
        if self.has_conflict() {
            None
        } else {
            Some(self.multikey.first_public_key())
        }
    }

    // TODO: Is it possible we're bringing in duplicate keys here?
    pub fn merge(&mut self, other: Option<&SecretStore>, replaced: Option<&SecretStore>) -> Result<(), CGKAError> {
        if let Some(s) = replaced {
            self.remove_keys_from(s)?;
        }
        if let Some(o) = other {
            self.versions.append(&mut o.versions.clone());
            // This will overwrite self.multikey
            self.sort_keys();
        }
        Ok(())
    }

    // TODO: Make this more performant.
    fn remove_keys_from(&mut self, replaced: &SecretStore) -> Result<(), CGKAError> {
        let mut remove_idxs = HashSet::new();
        let keys_to_remove: HashSet<&PublicKey> = replaced.multikey.keys().collect();
        let mut new_keys = Vec::new();
        let mut new_versions = Vec::new();
        for (idx, key) in self.multikey.keys().enumerate() {
            if keys_to_remove.contains(key) {
                remove_idxs.insert(idx);
            } else {
                new_keys.push(*key);
                new_versions.push(self.versions[idx].clone());
            }
        }
        self.multikey = Multikey { keys: new_keys };
        self.versions = new_versions;
        Ok(())
    }

    fn sort_keys(&mut self) {
        self.versions.sort();
        self.multikey = Multikey::from_iter(self.versions.iter().map(|v| v.pk));
    }
}

#[derive(Clone, Deserialize, Serialize)]
pub struct SecretStoreVersion {
    /// Every encrypted secret key (and hence version) corresponds to a single public key.
    pub pk: PublicKey,
    /// This is a map in order to handle the case of blank siblings, when we must encrypt
    /// the same secret key separately for each public key in the sibling resolution.
    pub sk: BTreeMap<TreeNodeIndex, NestedEncrypted<SecretKey>>,
    /// The PublicKey of the child that encrypted this parent.
    pub encrypter_pk: PublicKey,
    /// If this is None, the sibling subtree was blank when encrypting this parent.
    /// Otherwise, it represents the first node in the sibling resolution, which the
    /// encrypter used for its own Diffie Hellman shared secret.
    /// Invariant: PublicKeys must be in lexicographic order
    pub encrypter_paired_multikey: Option<Multikey>,
}

impl SecretStoreVersion {
    // TODO: Handle multiple child pks
    pub fn decrypt_secret(&self, child_idx: TreeNodeIndex, child_multikey: &Multikey, child_sks: &SecretKeyMap) -> Result<SecretKey, CGKAError> {
        let is_encrypter = child_multikey.contains(&self.encrypter_pk);
        let encrypted = self.sk.get(&child_idx)
            .ok_or(CGKAError::EncryptedSecretNotFound)?;
        let decrypt_keys: Vec<SecretKey> = if is_encrypter {
            let secret_key = child_sks.get(&self.encrypter_pk)
                .ok_or(CGKAError::SecretKeyNotFound)?;
            if let Some(pair_keys) = &self.encrypter_paired_multikey {
                pair_keys
                    .keys
                    .iter()
                    // TODO: Should this be kep.encrypter_paried_pk?
                    .map(|pk| generate_shared_key(&pk, secret_key))
                    .collect()
            } else {
                vec![secret_key.clone()]
            }
        } else {
            encrypted
                .paired_pks
                .iter()
                .map(|pk| {
                    let secret_key_result = child_sks.get(&pk);
                    if let Some(secret_key) = secret_key_result {
                        Ok(generate_shared_key(&self.encrypter_pk, secret_key))
                    } else {
                        Err(CGKAError::SecretKeyNotFound)
                    }
                })
                .collect::<Result<Vec<StaticSecret>, CGKAError>>()?
        };
        decrypt_nested_secret(encrypted, decrypt_keys)
    }
}

impl PartialEq for SecretStoreVersion {
    fn eq(&self, other: &Self) -> bool {
        self.pk == other.pk && self.encrypter_pk == other.encrypter_pk &&
            self.encrypter_paired_multikey == other.encrypter_paired_multikey
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

fn decrypt_nested_secret(
    encrypted: &NestedEncrypted<SecretKey>,
    decrypt_keys: Vec<SecretKey>,
) -> Result<SecretKey, CGKAError> {
    debug_assert!(encrypted.nonces.len() > 0);
    debug_assert_eq!(encrypted.nonces.len(), decrypt_keys.len());
    let mut ciphertext = encrypted.ciphertext.clone();
    for idx in 0..(encrypted.nonces.len() - 1) {
        let decrypt_key = &decrypt_keys[idx];
        let nonce = encrypted.nonces[idx];
        ciphertext = decrypt_layer(&ciphertext, &nonce, &decrypt_key)?;
    }
    let decrypt_key = decrypt_keys.last().expect("Length should be greater than 0");
    let nonce = encrypted.nonces.last().expect("Length should be greater than 0");
    let decrypted_bytes: [u8; 32] = decrypt_layer(&ciphertext, nonce, decrypt_key)?.try_into()
        .map_err(|e| CGKAError::Decryption("Expected 32 bytes".to_string()))?;
    Ok(StaticSecret::from(decrypted_bytes))
}

fn decrypt_layer(
    ciphertext: &Vec<u8>,
    nonce: &Siv,
    decrypt_key: &SecretKey,
) -> Result<Vec<u8>, CGKAError> {
    SymmetricKey::from(decrypt_key.to_bytes())
        .decrypt(*nonce, &ciphertext)
        .map_err(|e| CGKAError::Decryption(e.to_string()))?
        .try_into()
        .map_err(|_e| CGKAError::Conversion)
}

fn generate_shared_key(their_public_key: &PublicKey, my_secret: &SecretKey) -> SecretKey {
    x25519(my_secret.to_bytes(), their_public_key.to_bytes()).into()
}

// #[derive(Clone, Eq, PartialEq, Deserialize, Serialize)]
// pub struct Multikey {
//     encrypting_children: (TreeNodeIndex, TreeNodeIndex),
//     keys: Vec<KeyWithEncryptingPair>,
// }

// impl Multikey {
//     pub fn add_key(&mut self, key: PublicKey, encrypting_pair: (PublicKey, PublicKey)) {
//         let k = KeyWithEncryptingPair { key, encrypting_pair };
//         if !keys.contains(k) {
//             keys.push(k);
//         }
//     }

//     pub fn derive_shared_secret(&self, child_idx: TreeNodeIndex, key_map: BTreeMap<PublicKey, SecretKey>) -> SecretKey {
//         for pk in self.keys {

//         }
//     }
// }

