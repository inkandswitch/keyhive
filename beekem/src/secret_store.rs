//! The secret store an update writes at an inner tree node.

use crate::{
    encrypted::EncryptedSecret,
    error::CgkaError,
    id::TreeId,
    keys::{HasShareKey, NodeKeys, ShareKeyMap},
    treemath::TreeNodeIndex,
};
use alloc::{collections::BTreeMap, string::ToString, vec::Vec};
use keyhive_codec::{
    error::DecodeError,
    traits::{decode_exact, Decode, Encode, StreamDecode},
};
use keyhive_crypto::share_key::{ShareKey, ShareSecretKey};

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[cfg_attr(any(test, feature = "arbitrary"), derive(arbitrary::Arbitrary))]
pub struct SecretStore {
    /// Every encrypted secret key corresponds to a single public key.
    pub pk: ShareKey,
    /// This is a map in order to handle the case of blank siblings, when we must encrypt
    /// the same secret key separately for each public key in the sibling resolution.
    pub sk: BTreeMap<TreeNodeIndex, EncryptedSecret<ShareSecretKey>>,
    /// The share key of the child that encrypted this parent.
    pub encrypter_pk: ShareKey,
}

/// What an update writes at one inner node of its path. This includes the
/// node's new key and its secret, encrypted for the resolution of the
/// non-encrypting child.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(any(test, feature = "arbitrary"), derive(arbitrary::Arbitrary))]
pub struct PathNode {
    /// The node's new key.
    pub pk: ShareKey,
    /// The node's secret, encrypted for each node in the resolution, by tree
    /// index.
    pub sk: BTreeMap<TreeNodeIndex, EncryptedSecret<ShareSecretKey>>,
}

/// `pk || sk`, with `sk` in ascending index order.
impl Encode for PathNode {
    fn encode_into(&self, out: &mut Vec<u8>) {
        self.pk.encode_into(out);
        self.sk.encode_into(out);
    }
}

impl Decode for PathNode {
    fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        decode_exact(bytes)
    }
}

impl StreamDecode for PathNode {
    fn decode_next(bytes: &[u8]) -> Result<(Self, &[u8]), DecodeError> {
        let (pk, rest) = ShareKey::decode_next(bytes)?;
        let (sk, rest) = BTreeMap::decode_next(rest)?;
        Ok((PathNode { pk, sk }, rest))
    }
}

impl HasShareKey for SecretStore {
    fn share_key(&self) -> ShareKey {
        self.pk
    }
}

impl SecretStore {
    /// Decrypt this node's secret with the secret of its child's sibling, found
    /// in `sks`. If the sibling was blank or in conflict, the key is from its
    /// resolution.
    ///
    /// Returns `None` if none of its encryptions is to a key in `sks`.
    pub(crate) fn decrypt_with_sibling_secret(
        &self,
        doc_id: TreeId,
        sks: &ShareKeyMap,
    ) -> Option<ShareSecretKey> {
        self.sk.values().find_map(|encrypted| {
            let plaintext = sks
                .try_decrypt_encryption(doc_id, self.encrypter_pk, encrypted)
                .ok()?;
            ShareSecretKey::try_from_slice(&plaintext)
        })
    }

    /// Decrypt this node's secret with `child_sk`, the secret of the child below
    /// it that encrypted it.
    ///
    /// Returns `None` if `child_sk` is not that child's secret.
    pub(crate) fn decrypt_with_child_secret(
        &self,
        doc_id: TreeId,
        child_sk: &ShareSecretKey,
    ) -> Option<ShareSecretKey> {
        self.sk
            .values()
            .find_map(|encrypted| encrypted.try_encrypter_decrypt(doc_id, child_sk).ok())
            .and_then(|plaintext| ShareSecretKey::try_from_slice(&plaintext))
    }

    pub fn decrypt_secret(
        &self,
        doc_id: TreeId,
        child_node_keys: &NodeKeys,
        child_sks: &mut ShareKeyMap,
        seen_idxs: &[TreeNodeIndex],
    ) -> Result<ShareSecretKey, CgkaError> {
        // The child's node keys may not include the encrypter's key. Check our own
        // secrets too.
        let is_encrypter = child_node_keys.contains_key(&self.encrypter_pk)
            || child_sks.contains_key(&self.encrypter_pk);
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

        let decrypted = if is_encrypter {
            let secret_key = child_sks
                .get(&self.encrypter_pk)
                .ok_or(CgkaError::SecretKeyNotFound)?;

            encrypted
                .try_encrypter_decrypt(doc_id, secret_key)
                .map_err(|e| CgkaError::Decryption(e.to_string()))?
        } else {
            child_sks.try_decrypt_encryption(doc_id, self.encrypter_pk, encrypted)?
        };

        ShareSecretKey::try_from_slice(&decrypted).ok_or(CgkaError::Conversion)
    }
}
