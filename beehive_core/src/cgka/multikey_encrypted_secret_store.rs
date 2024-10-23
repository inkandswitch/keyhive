/// * In normal case, each node has a single public key and an encrypted secret key.
///   That secret is encrypted by one child using the pk of its sibling for DH.
/// * In blank sibling case, the encrypting child encrypts the secret for each of the nodes
///   in its sibling's resolution (and stores that one in an entry in a map corresponding
///   to the node). This means a separate DH per node in that resolution.
/// * In merge conflict case, the encrypter is not the child but the merger.
/// * * When merging a node, it generates a new random secret and a new external pk.
/// * * It then sorts all conflict public keys for that node.
/// * *
/// * *
/// * Problems
/// * * Only a child of a node can propose a secret key for that node.
/// * * On a merge, the merger might not have the conflict node on its path.
/// * *
///
///
///


use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use x25519_dalek::{x25519, StaticSecret};

use crate::crypto::{encrypted::{Encrypted, NestedEncrypted}, siv::Siv, symmetric_key::SymmetricKey};

use super::{beekem::{PublicKey, SecretKey}, error::CGKAError, treemath::TreeNodeIndex};

#[derive(Clone, Eq, PartialEq, Deserialize, Serialize)]
pub struct KeyWithEncryptingPair {
    pub key: PublicKey,
    pub encrypter_pair_pk: PublicKey,
}

#[derive(Clone, Deserialize, Serialize)]
pub struct MultikeySecretStore {
    /// Invariant: PublicKeys must be in lexicographic order
    pub pk: Vec<KeyWithEncryptingPair>,
    /// This is a map in order to handle the case of blank siblings, when we must encrypt
    /// the same secret key separately for each public key in the sibling resolution.
    pub sk: BTreeMap<TreeNodeIndex, NestedEncrypted<SecretKey>>,
    /// The PublicKey of the child that encrypted this parent.
    pub encrypter_pk: PublicKey,
    /// If this is None, the sibling subtree was blank when encrypting this parent.
    /// Otherwise, it represents the first node in the sibling resolution, which the
    /// encrypter used for its own Diffie Hellman shared secret.
    /// Invariant: PublicKeys must be in lexicographic order
    pub encrypter_paired_pk: Option<Vec<KeyWithEncryptingPair>>,
}

impl MultikeySecretStore {
    // pub fn derive_shared_secret(&self, child_pk: PublicKey, child_sks: BTreeMap<PublicKey, SecretKey>) -> SecretKey {
    //     let is_encrypter = child_pk == self.encrypter_pk;
    //     // TODO: Starting with the simplest case where there are no resolutions
    //     // Fix this.
    // }

    pub fn decrypt_secret(&self, child_idx: TreeNodeIndex, child_pk: PublicKey, child_sks: BTreeMap<Vec<u8>, SecretKey>) -> Result<SecretKey, CGKAError> {
        let is_encrypter = child_pk == self.encrypter_pk;
        let encrypted = self.sk.get(&child_idx)
            // FIXME: Pick a better error
            .ok_or(CGKAError::IdentifierNotFound)?;
        let decrypt_keys: Vec<SecretKey> = if is_encrypter {
            let child_pk_bytes: Vec<u8> = child_pk.to_bytes().into();
            let secret_key = child_sks.get(&child_pk_bytes)
                .ok_or(CGKAError::PublicKeyNotFound)?;
            if let Some(pair_keys) = &self.encrypter_paired_pk {
                pair_keys
                    .iter()
                    .map(|kep| generate_shared_key(&kep.encrypter_pair_pk, secret_key.clone()))
                    .collect()
            } else {
                vec![secret_key.clone()]
            }
        } else {
            // Since we're not the encrypter, there must be paired public keys.
            let Some(ref pair_keys) = self.encrypter_paired_pk else {
                return Err(CGKAError::PublicKeyNotFound);
            };
            pair_keys
                .iter()
                .map(|kep| {
                    let encrypter_pair_pk_bytes: Vec<u8> = kep.encrypter_pair_pk.to_bytes().into();
                    let secret_key_result = child_sks.get(&encrypter_pair_pk_bytes);
                    if let Some(secret_key) = secret_key_result {
                        Ok(generate_shared_key(&self.encrypter_pk, secret_key.clone()))
                    } else {
                        Err(CGKAError::PublicKeyNotFound)
                    }
                })
                .collect::<Result<Vec<StaticSecret>, CGKAError>>()?
        };
        decrypt_nested_secret(encrypted, decrypt_keys)
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
        .map_err(|e| CGKAError::Conversion)
}

fn generate_shared_key(their_public_key: &PublicKey, my_secret: SecretKey) -> SecretKey {
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

