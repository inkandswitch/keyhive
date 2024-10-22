use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::crypto::encrypted::Encrypted;

use super::{beekem::{PublicKey, SecretKey}, treemath::TreeNodeIndex};

#[derive(Clone, Eq, PartialEq, Deserialize, Serialize)]
pub struct KeyWithEncryptingPair {
    pub key: PublicKey,
    pub encrypter_pair_pk: PublicKey,
}

#[derive(Clone, Deserialize, Serialize)]
pub struct MultikeyEncryptedSecretStore {
    pub pk: Vec<KeyWithEncryptingPair>,
    /// This is a map in order to handle the case of blank siblings, when we must encrypt
    /// the same secret key separately for each public key in the sibling resolution.
    pub sk: BTreeMap<TreeNodeIndex, Encrypted<SecretKey>>,
    /// The PublicKey of the child that encrypted this parent.
    pub encrypter_pk: PublicKey,
    /// If this is None, the sibling subtree was blank when encrypting this parent.
    /// Otherwise, it represents the first node in the sibling resolution, which the
    /// encrypter used for its own Diffie Hellman shared secret.
    pub encrypter_paired_pk: Option<Vec<KeyWithEncryptingPair>>,
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

