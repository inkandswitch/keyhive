// * Leaf nodes represent participants. Each participant has a fixed Identifier as well
//   as a public key that is rotated over time.
// * Each non-leaf node stores one or more public keys and a secret used
//   to decrypt the parent.
// * Secrets are randomly generated.
// * A node is encrypted via Diffie Hellman using the private key of one child
//   node and the public key of its sibling.
// * Fast lookup of leaf by identifier.
// * All operations start from leaf (?).
// * Must walk to each child on the copath. But concurrent merges we may need to go further down
// * Concurrent adds create conflicting leaf orders. How do we minimize restructuring
//   of the tree on merge?
// * * Do concurrent adds require us to go back to the nearest common causal ancestor
//     and then apply the adds fresh?
// * * The resulting tree would have to have blanks on the paths of all other moved
//     nodes since I can't update their paths. This means that on a merge, you must
//     update your own path (if any changes invalidated it, i.e. there are blanks).
// * Remove blanks the path of the removed node.
// * Blanks are skipped when determining effective children of a parent by taking
//   the resolution.
// * There should always be at least one leaf node.
// *
// * Brooke's innovation: for conflicting node updates off your path, you keep
//   all conflicting public key at those nodes when merging. At the node on your path
//   with a multi-key child, you perform a nested Diffie Hellman.
// * * Is it an invariant that there will only be at most one sibling with multiple
//     conflict public keys at the moment of updating the parent (because the updater
//     would replace the sibling on its path with a single public key)?
// *
// * Tree structure conflicts to consider (the auth graph crdt determines who wins in say add/remove conflicts):
// * * Concurrent key rotations
// * * Concurrent adds
// * * Concurrent removes
// * * Concurrent key rotations, adds, and removes
//
// * Rotations are probably much more common than adds
// * Adds are more common than removes
//
//
// Is it an invariant that the root will always have a secret? To guarantee this
// we need to
// * initialize with a root key on tree construction
// * recalculate the key when removing another leaf
// * recalculate key when doing any operation that blanks up to the root
// Should these invariants be managed at the CGKA level?
//

use std::collections::BTreeMap;

use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit},
    ChaCha20Poly1305, Nonce, XChaCha20Poly1305,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use treemath::{LeafNodeIndex, ParentNodeIndex, TreeNodeIndex, TreeSize};
use x25519_dalek::{self, x25519, SharedSecret, StaticSecret};

use crate::{
    crypto::{encrypted::Encrypted, hash::Hash, symmetric_key::SymmetricKey},
    principal::identifier::Identifier,
};

use super::{error::CGKAError, treemath, CGKA};
pub type PublicKey = x25519_dalek::PublicKey;
pub type SecretKey = x25519_dalek::StaticSecret;

#[derive(Clone, Deserialize, Serialize)]
pub(crate) struct BeeKEM {
    owner_leaf_idx: Option<LeafNodeIndex>,
    next_leaf_idx: LeafNodeIndex,
    leaves: Vec<Option<LeafNode>>,
    parents: Vec<Option<ParentNode>>,
    tree_size: TreeSize,
    id_to_leaf_idx: BTreeMap<Identifier, LeafNodeIndex>,
}

/// Constructors
impl BeeKEM {
    /// We assume participants are in causal order.
    pub(crate) fn new(
        participants: Vec<(Identifier, PublicKey)>,
        owner_id: Identifier,
        owner_pk: PublicKey,
        owner_sk: SecretKey,
    ) -> Result<Self, CGKAError> {
        let mut tree = Self {
            owner_leaf_idx: None,
            next_leaf_idx: LeafNodeIndex::new(0),
            leaves: Vec::new(),
            parents: Vec::new(),
            tree_size: TreeSize::from_leaf_count(participants.len() as u32),
            id_to_leaf_idx: BTreeMap::new(),
        };
        tree.grow_tree_to_size();
        for (idx, (id, pk)) in participants.iter().enumerate() {
            if *id == owner_id {
                tree.owner_leaf_idx = Some(LeafNodeIndex::new(idx as u32));
            }
            tree.push_leaf(*id, *pk)?;
        }
        if tree.owner_leaf_idx.is_none() {
            return Err(CGKAError::OwnerIdentifierNotFound);
        }
        tree.encrypt_owner_path(owner_sk)?;
        // tree.encrypt_path(owner_id, owner_pk, owner_sk)?;
        // TODO: Populate my path
        Ok(tree)
    }

    pub(crate) fn set_owner_id(&mut self, id: Identifier) -> Result<(), CGKAError> {
        let leaf_idx = *self
            .id_to_leaf_idx
            .get(&id)
            .ok_or(CGKAError::IdentifierNotFound)?;
        self.owner_leaf_idx = Some(leaf_idx);
        Ok(())
    }

    pub(crate) fn get_public_key(&self, idx: TreeNodeIndex) -> Result<&PublicKey, CGKAError> {
        Ok(match idx {
            TreeNodeIndex::Leaf(l_idx) => {
                if let Some(l) = self.get_leaf(l_idx)? {
                    &l.pk
                } else {
                    return Err(CGKAError::PublicKeyNotFound);
                }
            }
            TreeNodeIndex::Parent(p_idx) => {
                if let Some(p) = &self.get_parent(p_idx)? {
                    &p.pk
                } else {
                    return Err(CGKAError::PublicKeyNotFound);
                }
            }
        })
    }

    pub(crate) fn get_leaf(&self, idx: LeafNodeIndex) -> Result<&Option<LeafNode>, CGKAError> {
        self.leaves
            .get(idx.usize())
            .ok_or(CGKAError::TreeIndexOutOfBounds)
    }

    fn get_owner_leaf(&self) -> Result<&LeafNode, CGKAError> {
        let idx = self
            .owner_leaf_idx
            .ok_or(CGKAError::OwnerIdentifierNotFound)?;
        let leaf = self
            .leaves
            .get(idx.usize())
            .as_ref()
            .ok_or(CGKAError::TreeIndexOutOfBounds)?
            .as_ref()
            .ok_or(CGKAError::OwnerIdentifierNotFound)?;
        Ok(leaf)
    }

    pub(crate) fn get_parent(
        &self,
        idx: ParentNodeIndex,
    ) -> Result<&Option<ParentNode>, CGKAError> {
        self.parents
            .get(idx.usize())
            .ok_or(CGKAError::TreeIndexOutOfBounds)
    }

    pub(crate) fn insert_leaf_at(
        &mut self,
        idx: LeafNodeIndex,
        leaf: LeafNode,
    ) -> Result<(), CGKAError> {
        if idx.usize() >= self.leaves.len() {
            return Err(CGKAError::TreeIndexOutOfBounds);
        }
        self.leaves[idx.usize()] = Some(leaf);
        Ok(())
    }

    pub(crate) fn insert_parent_at(
        &mut self,
        idx: ParentNodeIndex,
        parent: ParentNode,
    ) -> Result<(), CGKAError> {
        if idx.usize() >= self.parents.len() {
            return Err(CGKAError::TreeIndexOutOfBounds);
        }
        self.parents[idx.usize()] = Some(parent);
        Ok(())
    }

    pub(crate) fn blank_leaf_and_path(&mut self, idx: LeafNodeIndex) -> Result<(), CGKAError> {
        if idx.usize() >= self.leaves.len() {
            return Err(CGKAError::TreeIndexOutOfBounds);
        }
        self.leaves[idx.usize()] = None;
        self.blank_path(treemath::parent(idx.into()))
    }

    pub(crate) fn push_leaf(&mut self, id: Identifier, pk: PublicKey) -> Result<(), CGKAError> {
        self.maybe_grow_tree(self.next_leaf_idx.u32());
        let l_idx = self.next_leaf_idx;
        // Increment next leaf idx
        self.next_leaf_idx = LeafNodeIndex::new(self.next_leaf_idx.u32() + 1);
        self.id_to_leaf_idx.insert(id, l_idx);
        self.insert_leaf_at(l_idx, LeafNode { id, pk })?;
        self.blank_path(treemath::parent(l_idx.into()))
    }

    pub(crate) fn remove_id(&mut self, id: Identifier) -> Result<(), CGKAError> {
        let l_idx = self
            .id_to_leaf_idx
            .get(&id)
            .ok_or(CGKAError::IdentifierNotFound)?;
        self.blank_leaf_and_path(*l_idx)?;
        self.id_to_leaf_idx.remove(&id);
        Ok(())
    }

    pub(crate) fn id_count(&self) -> u32 {
        self.id_to_leaf_idx.len() as u32
    }

    /// Starting from the owner's leaf, move up the tree toward the root (i.e. the leaf's
    /// path). As you look at each parent node along the way, if the node is not blank,
    /// look up your child idx in the parent's secret key map. Derive a Diffie Hellman
    /// shared key using the public key stored there and use that shared key to decrypt
    /// the secret key stored there.
    /// If the parent is blank, hold on to the child node's public and secret keys and
    /// move to the next parent.
    pub(crate) fn decrypt_tree_secret(
        &mut self,
        owner_sk: SecretKey,
    ) -> Result<SecretKey, CGKAError> {
        // TODO: Should we enforce an invariant that there will always be a root key?
        if self.no_root_key()? {
            let leaf = self.get_owner_leaf()?;
            self.encrypt_path(leaf.id, leaf.pk, owner_sk.clone())?;
            return Err(CGKAError::NoRootKey);
        }
        let leaf_idx = self
            .owner_leaf_idx
            .ok_or(CGKAError::OwnerIdentifierNotFound)?;
        if self.is_blank(leaf_idx.into())? {
            return Err(CGKAError::OwnerIdentifierNotFound);
        }
        let mut child_idx: TreeNodeIndex = leaf_idx.into();
        let mut last_non_blank_child_idx: TreeNodeIndex = child_idx;
        let mut parent_idx = treemath::parent(child_idx);
        let mut next_secret = owner_sk.clone();
        while !self.is_root(child_idx) {
            // TODO: Remove
            if self.is_blank(parent_idx.into())? {
                println!("--- while is_blank loop {:?}", child_idx);
            }
            while self.is_blank(parent_idx.into())? && !self.is_root(child_idx) {
                child_idx = parent_idx.into();
                parent_idx = treemath::parent(child_idx);
                println!("--- Skipped to {:?}", child_idx);
            }
            // TODO: This shouldn't be possible if there is a root key
            if self.is_root(child_idx) {
                println!("Child is root. This should be impossible.");
                break;
            }
            println!("Preparing to decrypt_parent_key for {:?}", parent_idx);
            next_secret =
                self.decrypt_parent_key(last_non_blank_child_idx, child_idx, next_secret.clone())?;
            println!("|||- Next secret is {:?}", next_secret.to_bytes());
            child_idx = parent_idx.into();
            last_non_blank_child_idx = child_idx;
            parent_idx = treemath::parent(child_idx);
        }
        Ok(next_secret)
    }

    /// Starting from the owner's leaf, move up the tree toward the root (i.e. the leaf's
    /// path). As you look at each parent node along the way, you need to populate it
    /// with a public key and a map from sibling subtree public keys to a newly generated
    /// secret key encrypted pairwise with each node in the sibling resolution (in the
    /// ideal case, this will just be the sibling node itself, but if the sibling is
    /// blank it can be many nodes).
    /// If the sibling node's resolution is empty, then you will generate the new key
    /// pair but encrypt the secret with your last secret (instead of using Diffie Hellman
    /// with a sibling). The secret key map for that parent will then only have an entry for
    /// you.
    /// TODO: Should we only allow this for the owner path?
    pub(crate) fn encrypt_path(
        &mut self,
        id: Identifier,
        pk: PublicKey,
        sk: SecretKey,
    ) -> Result<(), CGKAError> {
        let leaf_idx = *self
            .id_to_leaf_idx
            .get(&id)
            .ok_or(CGKAError::IdentifierNotFound)?;
        if self.is_blank(leaf_idx.into())? {
            return Err(CGKAError::IdentifierNotFound);
        }
        self.insert_leaf_at(leaf_idx, LeafNode { id, pk })?;
        let mut child_idx: TreeNodeIndex = leaf_idx.into();
        let mut child_pk = pk;
        let mut child_secret = sk.clone();
        let mut parent_idx = treemath::parent(child_idx);
        while !self.is_root(child_idx) {
            child_secret =
                self.encrypt_key_for_parent(child_idx, child_pk, child_secret.clone())?;
            child_idx = parent_idx.into();
            child_pk = *self.get_public_key(child_idx)?;
            parent_idx = treemath::parent(child_idx);
        }
        Ok(())
    }

    pub(crate) fn encrypt_owner_path(&mut self, owner_sk: SecretKey) -> Result<(), CGKAError> {
        let owner_leaf = self.get_owner_leaf()?;
        self.encrypt_path(owner_leaf.id, owner_leaf.pk, owner_sk)
    }

    pub(crate) fn no_root_key(&self) -> Result<bool, CGKAError> {
        let root_idx = treemath::root(self.tree_size);
        println!("Root idx: {:?}, tree_size: {:?}", root_idx, self.tree_size);
        let TreeNodeIndex::Parent(p_idx) = root_idx else {
            return Err(CGKAError::TreeIndexOutOfBounds);
        };
        Ok(self.get_parent(p_idx)?.is_none())
    }

    fn decrypt_parent_key(
        &self,
        non_blank_child_idx: TreeNodeIndex,
        child_idx: TreeNodeIndex,
        child_secret: SecretKey,
    ) -> Result<SecretKey, CGKAError> {
        debug_assert!(!self.is_root(child_idx));
        let parent_idx = treemath::parent(child_idx);
        debug_assert!(!self.is_blank(parent_idx.into())?);
        println!(
            "||| Looking for {:?}, tree size: {:?}",
            parent_idx, self.tree_size
        );
        let parent = self
            .get_parent(parent_idx)?
            .as_ref()
            .ok_or(CGKAError::TreeIndexOutOfBounds)?;
        println!("||| Found {:?}", parent_idx);
        let (pk, encrypted) = parent
            .sk
            .get(&non_blank_child_idx)
            // FIXME: Pick a better error
            .ok_or(CGKAError::IdentifierNotFound)?;

        let sibling_idx = treemath::sibling(child_idx);
        let mut sibling_resolution = Vec::new();
        self.append_resolution(sibling_idx, &mut sibling_resolution)?;
        let decrypt_key = if sibling_resolution.is_empty() {
            // Normally you use a DH shared key to encrypt/decrypt the next node up,
            // but if there's a blank sibling subtree, then you use your secret key
            // directly instead.
            println!("||||-- using child secret");
            child_secret
        } else {
            println!("||||-- generating shared key");
            generate_shared_key(pk, child_secret)
        };

        decrypt_secret(encrypted, decrypt_key)
    }

    fn encrypt_key_for_parent(
        &mut self,
        child_idx: TreeNodeIndex,
        child_pk: PublicKey,
        child_secret: SecretKey,
    ) -> Result<SecretKey, CGKAError> {
        debug_assert!(!self.is_root(child_idx));
        let parent_idx = treemath::parent(child_idx);
        println!("Preparing to encrypt {:?}", parent_idx);
        let (new_public_key, new_secret, new_secret_map) =
            self.generate_and_encrypt_new_key_pair_for_parent(child_idx, child_pk, child_secret)?;
        // println!("My pk: {:?}", child_pk);
        // print_key_map(&new_secret_map);
        let node = ParentNode {
            pk: new_public_key,
            sk: new_secret_map,
        };
        println!("Inserting parent at {:?}", parent_idx);
        self.insert_parent_at(parent_idx, node)?;
        Ok(new_secret)
    }

    fn generate_and_encrypt_new_key_pair_for_parent(
        &self,
        child_idx: TreeNodeIndex,
        child_pk: PublicKey,
        child_secret: SecretKey,
    ) -> Result<
        (
            PublicKey,
            SecretKey,
            BTreeMap<TreeNodeIndex, (PublicKey, Encrypted<SecretKey>)>,
        ),
        CGKAError,
    > {
        debug_assert!(!self.is_root(child_idx));
        let sibling_idx = treemath::sibling(child_idx);
        let mut secret_map = BTreeMap::new();
        let (new_pk, new_sk) = generate_new_key_pair();
        let mut sibling_resolution = Vec::new();
        self.append_resolution(sibling_idx, &mut sibling_resolution)?;
        if sibling_resolution.is_empty() {
            // Normally you use a DH shared key to encrypt/decrypt the next node up,
            // but if there's a blank sibling subtree, then you use your secret key
            // directly instead.
            let encrypted_sk = encrypt_secret(new_sk.clone(), child_secret.clone())?;
            secret_map.insert(child_idx, (child_pk, encrypted_sk));
        } else {
            // Encrypt the secret for every node in the sibling resolution, using
            // a new DH shared secret to do the encryption for each node.
            let mut first = true;
            for idx in sibling_resolution {
                let sibling_pk = self.get_public_key(idx)?;
                let shared_key = generate_shared_key(sibling_pk, child_secret.clone());
                let encrypted_sk = encrypt_secret(new_sk.clone(), shared_key.clone())?;
                if first {
                    secret_map.insert(child_idx, (*sibling_pk, encrypted_sk.clone()));
                    first = false;
                }
                secret_map.insert(idx, (child_pk, encrypted_sk));
            }
        }
        Ok((new_pk, new_sk, secret_map))
    }

    fn is_blank(&self, idx: TreeNodeIndex) -> Result<bool, CGKAError> {
        Ok(match idx {
            TreeNodeIndex::Leaf(l_idx) => self.get_leaf(l_idx)?.is_none(),
            TreeNodeIndex::Parent(p_idx) => self.get_parent(p_idx)?.is_none(),
        })
    }

    fn blank_path(&mut self, idx: ParentNodeIndex) -> Result<(), CGKAError> {
        self.blank_parent(idx)?;
        if self.is_root(idx.into()) {
            return Ok(());
        }
        self.blank_path(treemath::parent(idx.into()))
    }

    fn blank_parent(&mut self, idx: ParentNodeIndex) -> Result<(), CGKAError> {
        println!("Blanking parent at {:?}", idx);
        // FIXME: This write can panic
        self.parents[idx.usize()] = None;
        Ok(())
    }

    /// Growing the tree will add a new root and a new subtree, all blank.
    fn maybe_grow_tree(&mut self, new_count: u32) {
        if self.tree_size >= TreeSize::from_leaf_count(new_count) {
            return;
        }
        self.tree_size.inc();
        self.grow_tree_to_size();
    }

    fn grow_tree_to_size(&mut self) {
        self.leaves
            .resize(self.tree_size.leaf_count() as usize, None);
        self.parents
            .resize(self.tree_size.parent_count() as usize, None);
    }

    fn is_root(&self, idx: TreeNodeIndex) -> bool {
        idx == treemath::root(self.tree_size)
    }

    /// This is the size of the tree including any blank leaves
    pub(crate) fn tree_size(&self) -> u32 {
        self.tree_size.u32()
    }

    /// Contains id.
    fn contains_id(&self, id: Identifier) -> bool {
        self.id_to_leaf_idx.contains_key(&id)
    }

    /// Highest non-blank descendents of a node
    fn append_resolution(
        &self,
        idx: TreeNodeIndex,
        acc: &mut Vec<TreeNodeIndex>,
    ) -> Result<(), CGKAError> {
        match idx {
            TreeNodeIndex::Leaf(l_idx) => {
                if let Some(_) = self.get_leaf(l_idx)? {
                    acc.push(l_idx.into());
                }
                Ok(())
            }
            TreeNodeIndex::Parent(p_idx) => {
                if let Some(_) = self.get_parent(p_idx)? {
                    acc.push(p_idx.into());
                    Ok(())
                } else {
                    let left_idx = treemath::left(p_idx);
                    self.append_resolution(left_idx, acc)?;
                    let right_idx = treemath::right(p_idx);
                    self.append_resolution(right_idx, acc)
                }
            }
        }
    }
}

// FIXME: Remove
fn print_key_map(km: &BTreeMap<TreeNodeIndex, (PublicKey, Encrypted<SecretKey>)>) {
    let mut count = 0;
    println!("-----------------------------------------------------------------------");
    for k in km.keys() {
        if let Some((pk, encs)) = km.get(k) {
            println!(
                "{count} -- K: {:?}, V: [ pk: {:?}, encsk: {:?}",
                k, pk, encs.ciphertext
            );
        }
        count += 1;
        println!("|||||||||||||||||");
    }
    println!("-----------------------------------------------------------------------");
}

//////////////////////////////////////////////////////////////////
// FIXME: Replace this section with using beehive crypto capabilities
// directly
//////////////////////////////////////////////////////////////////
fn generate_new_key_pair() -> (PublicKey, SecretKey) {
    let sk = StaticSecret::random_from_rng(&mut rand::thread_rng());
    let pk = PublicKey::from(&sk);
    (pk, sk)
}

fn generate_shared_key(their_public_key: &PublicKey, my_secret: SecretKey) -> SecretKey {
    let shared: SecretKey = x25519(my_secret.to_bytes(), their_public_key.to_bytes()).into();
    println!("-----------------------------------------------------------------------");
    println!("______their_public_key = {:?}", their_public_key);
    println!("______my_secret_key = {:?}", my_secret.to_bytes());
    println!("______shared_key = {:?}", shared.to_bytes());
    println!("-----------------------------------------------------------------------");
    shared
}

fn encrypt_secret(
    secret: SecretKey,
    encrypt_key: SecretKey,
) -> Result<Encrypted<SecretKey>, CGKAError> {
    println!("Encrypting secret with {:?}", encrypt_key.to_bytes());
    println!("__secret I'm encrypting: {:?}", secret.to_bytes());
    let mut nonce = [0u8; 24];
    rand::thread_rng().fill_bytes(&mut nonce);
    let symmetric_key = SymmetricKey::from(encrypt_key.to_bytes());
    let encrypted_secret_bytes = symmetric_key
        .encrypt(nonce.into(), secret.as_bytes())
        .map_err(CGKAError::Encryption)?;
    let encrypted_secret: Encrypted<SecretKey> =
        Encrypted::new(nonce.into(), encrypted_secret_bytes);
    Ok(encrypted_secret)
}

fn decrypt_secret(
    encrypted: &Encrypted<SecretKey>,
    decrypt_key: SecretKey,
) -> Result<SecretKey, CGKAError> {
    println!("Decrypting secret with {:?}", decrypt_key.to_bytes());
    println!("||| decrypt_secret");
    let symmetric_key = SymmetricKey::from(decrypt_key.to_bytes());
    let decrypted_bytes: [u8; 32] = symmetric_key
        .decrypt(encrypted.nonce, &encrypted.ciphertext)
        .map_err(|e| CGKAError::Decryption(e.to_string()))?
        .try_into()
        .map_err(|e| CGKAError::Conversion)?;
    Ok(StaticSecret::from(decrypted_bytes))
}
//////////////////////////////////////////////////////////////////

#[derive(Clone, Deserialize, Serialize)]
pub(crate) struct LeafNode {
    pub id: Identifier,
    pub pk: PublicKey,
}

#[derive(Clone, Deserialize, Serialize)]
pub(crate) struct ParentNode {
    // TODO: Handle multiple public keys for BeeKEM conflict resolution
    pub pk: PublicKey,
    /// This is kept as a map in order to handle blanks, where we must encrypt the same
    /// secret key for multiple distinct public keys (corresponding to distinct
    /// TreeNodeIndex values).
    /// Map from node idx to the public key that was its diffie hellman partner
    /// and the secret key encrypted that way.
    pub sk: BTreeMap<TreeNodeIndex, (PublicKey, Encrypted<SecretKey>)>,
}

// #[cfg(test)]
// mod tests {
//     use x25519_dalek::StaticSecret;

//     use super::*;

//     fn setup_participant() -> (Identifier, PublicKey) {
//         let id = Identifier::new(
//             ed25519_dalek::SigningKey::generate(&mut rand::thread_rng()).verifying_key(),
//         );
//         let secret = StaticSecret::random_from_rng(&mut rand::thread_rng());
//         let pk = PublicKey::from(&secret);
//         (id, pk)
//     }

//     // FIXME: These are basically duplicate tests from CGKA. Focus only on tree-specific
//     // functionality, like tree size changes.
//     #[test]
//     fn test_simple_add() -> Result<(), CGKAError> {
//         let me = setup_participant();
//         let mut participants = vec![me];
//         participants.push(setup_participant());
//         let participant_count = participants.len() as u32;
//         let tree = BeeKEM::new(participants, me.0)?;
//         assert_eq!(
//             tree.tree_size(),
//             TreeSize::from_leaf_count(participant_count).u32()
//         );
//         assert_eq!(tree.id_count(), participant_count);
//         Ok(())
//     }

//     #[test]
//     fn test_simple_add_and_remove() -> Result<(), CGKAError> {
//         let me = setup_participant();
//         let p1 = setup_participant();
//         let participants = vec![me, p1];
//         let initial_participant_count = participants.len() as u32;
//         let mut tree = BeeKEM::new(participants, me.0)?;
//         tree.remove_id(p1.0)?;
//         assert_eq!(
//             tree.tree_size(),
//             TreeSize::from_leaf_count(initial_participant_count).u32()
//         );
//         assert_eq!(tree.id_count(), initial_participant_count - 1);
//         Ok(())
//     }
// }
