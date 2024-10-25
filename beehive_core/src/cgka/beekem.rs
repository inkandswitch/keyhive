// * Leaf nodes represent members. Each member has a fixed Identifier as well
//   as a public key that is rotated over time.
// * Each non-leaf node stores one or more public keys and a secret used
//   for deriving a shared key for decrypting the parent.
// * Secrets are randomly generated.
// * In the simple case, a node is encrypted via Diffie Hellman using the private key of
//   one child node and the public key of its sibling. If the sibling subtree is blank,
//   the child will use its own secret key to encrypt directly. If the sibling is blank
//   but has non-blank descendents, the child node will do Diffie Hellman with each of
//   those descendents to encrypt the parent secret (storing these in a map).
// * All operations start from a leaf.
// * Concurrent adds create conflicting leaf orders. How do we minimize restructuring
//   of the tree on merge?
// * * Current proposal: keep the longest of the two conflicting sets of adds and append
//   the non-redundant adds from the shorter set to the right in lexicographic Identifier
//   order.
// * Remove blanks the path of the removed node.
// * Blanks are skipped when determining effective children of a parent by taking
//   the resolution.
// * There should always be at least one leaf node.
// *
// * Brooke's innovation: for conflicting node updates off your path, you keep
//   all conflicting public keys at those nodes when merging. At the node on your path
//   with a multi-key child, you perform a nested Diffie Hellman.
// * * There will be at most one sibling with multiple conflict public keys at the
//     moment of updating the parent (because the updater would replace the other sibling
//     on its path with a single public key)?
// *
// * Tree structure conflicts to consider (the auth graph crdt determines who wins in say add/remove conflicts):
// * * Concurrent key rotations
// * * Concurrent adds
// * * Concurrent removes
// * * Concurrent key rotations, adds, and removes
//
// * Rotations are probably much more common than adds
// * Adds are more common than removes
// * We hypothesize that earlier members (who tend to be further left in the leaves
//   vector) will be less likely to be removed. Removals on the left are more expensive
//   to "garbage collect" since filling in those blanks (i.e. implicit tombstones)
//   requires moving more leaves to the left.
//
// Is it an invariant that the root will always have a secret? To guarantee this
// we need to
// * initialize a root key on tree construction
// * recalculate the root key when removing another leaf
// * recalculate the root key when doing any operation that blanks up to the root
// Should these invariants be managed at the CGKA or BeeKEM tree level?

use std::{
    collections::BTreeMap,
    fmt::{self, Debug, Formatter},
};

use rand::RngCore;
use serde::{Deserialize, Serialize};
use treemath::{LeafNodeIndex, ParentNodeIndex, TreeNodeIndex, TreeSize};
use x25519_dalek::{self, x25519, StaticSecret};

use crate::{
    crypto::{
        encrypted::{Encrypted, NestedEncrypted},
        siv::Siv,
        symmetric_key::SymmetricKey,
    },
    principal::identifier::Identifier,
};

use super::{
    error::CGKAError,
    secret_store::{Multikey, SecretKeyMap, SecretStore},
    treemath, CGKA,
};
pub type PublicKey = x25519_dalek::PublicKey;
pub type SecretKey = x25519_dalek::StaticSecret;

#[derive(Clone, Deserialize, Serialize)]
pub struct TreeChange {
    /// The new path that was applied.
    pub new_path: TreePath,
    /// The path that is being replaced.
    /// In order to rewind, we need the specific public keys along the path, which could
    /// potentially only be reconstructed by replaying from the beginning otherwise.
    pub undo: TreePath,
}

#[derive(Clone, Deserialize, Serialize)]
pub struct TreePath {
    pub leaf_id: Identifier,
    pub leaf_idx: u32,
    pub leaf_pk: PublicKey,
    pub path: Vec<(u32, Option<ParentNode>)>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct BeeKEM {
    next_leaf_idx: LeafNodeIndex,
    leaves: Vec<Option<LeafNode>>,
    parents: Vec<Option<ParentNode>>,
    tree_size: TreeSize,
    id_to_leaf_idx: BTreeMap<Identifier, LeafNodeIndex>,
}

impl BeeKEM {
    /// We can assume members are in causal order (a property guaranteed by
    /// Beehive as a whole).
    pub(crate) fn new(members: Vec<(Identifier, PublicKey)>) -> Result<Self, CGKAError> {
        let mut tree = Self {
            next_leaf_idx: LeafNodeIndex::new(0),
            leaves: Vec::new(),
            parents: Vec::new(),
            tree_size: TreeSize::from_leaf_count(members.len() as u32),
            id_to_leaf_idx: BTreeMap::new(),
        };
        tree.grow_tree_to_size();
        for (id, pk) in members {
            tree.push_leaf(id, pk)?;
        }
        Ok(tree)
    }

    // /// Hash of the tree
    // pub fn hash(&self) -> Hash<BeeKEM> {
    //     Hash::hash(self.clone())
    // }

    pub(crate) fn multikey_for_index(&self, idx: TreeNodeIndex) -> Result<&Multikey, CGKAError> {
        Ok(match idx {
            TreeNodeIndex::Leaf(l_idx) => {
                &self
                    .leaf(l_idx)?
                    .as_ref()
                    .ok_or(CGKAError::PublicKeyNotFound)?
                    .pk
            }
            TreeNodeIndex::Parent(p_idx) => &self
                .parent(p_idx)?
                .as_ref()
                .ok_or(CGKAError::PublicKeyNotFound)?
                .multikey(),
        })
    }

    pub(crate) fn multikey_for_id(&self, id: Identifier) -> Result<&Multikey, CGKAError> {
        let idx = self.leaf_index_for_id(id)?;
        self.multikey_for_index((*idx).into())
    }

    pub(crate) fn leaf(&self, idx: LeafNodeIndex) -> Result<&Option<LeafNode>, CGKAError> {
        self.leaves
            .get(idx.usize())
            .ok_or(CGKAError::TreeIndexOutOfBounds)
    }

    fn leaf_index_for_id(&self, id: Identifier) -> Result<&LeafNodeIndex, CGKAError> {
        self.id_to_leaf_idx
            .get(&id)
            .ok_or(CGKAError::IdentifierNotFound)
    }

    fn id_for_leaf(&self, idx: LeafNodeIndex) -> Result<Identifier, CGKAError> {
        Ok(self
            .leaf(idx)?
            .as_ref()
            .ok_or(CGKAError::IdentifierNotFound)?
            .id)
    }

    // TODO: Rename since it can be read to mean "parent_of" but is "get_parent_node_at_idx"
    pub(crate) fn parent(&self, idx: ParentNodeIndex) -> Result<&Option<ParentNode>, CGKAError> {
        self.parents
            .get(idx.usize())
            .ok_or(CGKAError::TreeIndexOutOfBounds)
    }

    pub(crate) fn insert_leaf_at(
        &mut self,
        idx: LeafNodeIndex,
        id: Identifier,
        pk: PublicKey,
    ) -> Result<(), CGKAError> {
        if idx.usize() >= self.leaves.len() {
            return Err(CGKAError::TreeIndexOutOfBounds);
        }
        let multikey = Multikey { keys: vec![pk] };
        let leaf = LeafNode { id, pk: multikey };
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

    pub(crate) fn push_leaf(&mut self, id: Identifier, pk: PublicKey) -> Result<u32, CGKAError> {
        self.maybe_grow_tree(self.next_leaf_idx.u32());
        let l_idx = self.next_leaf_idx;
        // Increment next leaf idx
        self.next_leaf_idx += 1;
        self.id_to_leaf_idx.insert(id, l_idx);
        self.insert_leaf_at(l_idx, id, pk)?;
        self.blank_path(treemath::parent(l_idx.into()))?;
        Ok(l_idx.u32())
    }

    pub(crate) fn remove_id(&mut self, id: Identifier) -> Result<u32, CGKAError> {
        if self.member_count() == 1 {
            return Err(CGKAError::RemoveLastMember);
        }
        let l_idx = self.leaf_index_for_id(id)?;
        let l_idx_u32 = l_idx.u32();
        self.blank_leaf_and_path(*l_idx)?;
        self.id_to_leaf_idx.remove(&id);
        // "Collect" any contiguous tombstones at the end of the leaves Vec
        while self.leaf(self.next_leaf_idx - 1)?.is_none() {
            self.next_leaf_idx -= 1;
        }
        Ok(l_idx_u32)
    }

    pub(crate) fn member_count(&self) -> u32 {
        self.id_to_leaf_idx.len() as u32
    }

    /// Starting from the owner's leaf, move up the tree toward the root (i.e. along the
    /// leaf's path). As you look at each parent node along the way, if the node is not
    /// blank, look up your child idx in the parent's secret key map. Derive a Diffie Hellman
    /// shared key using the public key stored in the secret map and use that shared key to
    /// decrypt the secret key stored there.
    ///
    /// If the parent is blank, hold on to the last non-blank child node's index and secret
    /// key and move to the next parent.
    pub(crate) fn decrypt_tree_secret(
        &self,
        owner_id: Identifier,
        owner_sks: &mut SecretKeyMap,
    ) -> Result<SecretKey, CGKAError> {
        let leaf_idx = *self.leaf_index_for_id(owner_id)?;
        let leaf = self
            .leaf(leaf_idx)?
            .as_ref()
            .ok_or(CGKAError::OwnerIdentifierNotFound)?;
        if !self.has_root_key()? {
            return Err(CGKAError::NoRootKey);
        }
        if self.is_blank(leaf_idx.into())? {
            return Err(CGKAError::OwnerIdentifierNotFound);
        }
        let mut child_idx: TreeNodeIndex = leaf_idx.into();
        let mut last_non_blank_child_idx: TreeNodeIndex = child_idx;
        // let mut child_sk = owner_sks;
        let mut last_secret = None;
        let mut child_pk = &leaf.pk;
        println!("|My pk: {:?}|", child_pk);
        let mut parent_idx: TreeNodeIndex = treemath::parent(child_idx).into();
        while !self.is_root(child_idx) {
            // Find the next non-blank parent
            while self.is_blank(parent_idx)? {
                child_idx = parent_idx.into();
                parent_idx = treemath::parent(child_idx).into();
            }
            debug_assert!(!self.is_root(child_idx));
            last_secret =
                self.decrypt_parent_key(last_non_blank_child_idx, child_idx, child_pk, owner_sks)?;
            child_pk = self.multikey_for_index(parent_idx)?;
            child_idx = parent_idx;
            last_non_blank_child_idx = child_idx;
            parent_idx = treemath::parent(child_idx).into();
        }
        last_secret.ok_or(CGKAError::NoRootKey)
    }

    /// Starting from the owner's leaf, move up the tree toward the root (i.e. along the
    /// leaf's path). As you look at each parent node along the way, you need to populate
    /// it with a public key and a map from sibling subtree public keys to a newly generated
    /// secret key encrypted pairwise with each node in the sibling resolution (in the
    /// ideal case, this will just be the sibling node itself, but if the sibling is
    /// blank it can be many nodes).
    ///
    /// If the sibling node's resolution is empty, then you will generate the new key
    /// pair but encrypt the secret with your last secret (instead of using Diffie Hellman
    /// with a sibling). The secret key map for that parent will then only have an entry
    /// for you.
    ///
    /// TODO: Currently returns (new path, old path) but we should use better types
    /// to clarify intention
    pub(crate) fn encrypt_path(
        &mut self,
        id: Identifier,
        pk: PublicKey,
        sks: &mut SecretKeyMap,
    ) -> Result<TreeChange, CGKAError> {
        let leaf_idx = *self.leaf_index_for_id(id)?;
        let mut new_path = TreePath {
            leaf_id: id,
            leaf_idx: leaf_idx.u32(),
            // TODO: Does this need to be a multikey?
            leaf_pk: pk,
            path: Vec::new(),
        };
        let mut undo_path = TreePath {
            leaf_id: id,
            leaf_idx: leaf_idx.u32(),
            // TODO: What should this be?
            leaf_pk: self.multikey_for_id(id)?.first_public_key(),
            path: Vec::new(),
        };
        if self.id_for_leaf(leaf_idx)? != id {
            return Err(CGKAError::IdentifierNotFound);
        }
        self.insert_leaf_at(leaf_idx, id, pk)?;
        let mut child_idx: TreeNodeIndex = leaf_idx.into();
        let mut child_pk = pk;
        let mut child_sk = sks.get(&pk).ok_or(CGKAError::SecretKeyNotFound)?.clone();
        let mut parent_idx = treemath::parent(child_idx);
        while !self.is_root(child_idx) {
            undo_path
                .path
                .push((parent_idx.u32(), self.parent(parent_idx)?.clone()));
            let (new_parent_pk, new_parent_sk) = generate_new_key_pair();
            // let child_sk = sks.get(&child_pk)
            //     .ok_or(CGKAError::SecretKeyNotFound)?;
            self.encrypt_key_for_parent(
                child_idx,
                child_pk,
                &child_sk,
                new_parent_pk,
                &new_parent_sk,
            )?;
            sks.insert(new_parent_pk, new_parent_sk.clone());
            new_path
                .path
                .push((parent_idx.u32(), self.parent(parent_idx)?.clone()));
            child_idx = parent_idx.into();
            child_pk = new_parent_pk;
            child_sk = new_parent_sk;
            parent_idx = treemath::parent(child_idx);
        }
        Ok(TreeChange {
            new_path,
            undo: undo_path,
        })
    }

    fn validate_change(&self, leaf_id: Identifier, change: &TreeChange) -> Result<(), CGKAError> {
        // TODO: Should we verify that the path is the same as the direct path
        // from the leaf?
        if change.new_path.path.len()
            != self.path_length_for(LeafNodeIndex::new(change.new_path.leaf_idx))
        {
            return Err(CGKAError::InvalidPathLength);
        }
        if leaf_id != change.new_path.leaf_id {
            return Err(CGKAError::IdentifierNotFound);
        }
        Ok(())
    }

    // pub(crate) fn overwrite_path(&mut self, change: TreeChange) -> Result<(), CGKAError> {
    //     let leaf_idx = LeafNodeIndex::new(change.new_path.leaf_idx);
    //     let leaf_id = self
    //         .leaf(leaf_idx)?
    //         .as_ref()
    //         .ok_or(CGKAError::IdentifierNotFound)?
    //         .id;
    //     self.validate_change(leaf_id, &change)?;
    //     self.insert_leaf_at(leaf_idx, leaf_id, change.new_path.leaf_pk)?;
    //     for (idx, node) in change.new_path.path {
    //         let p_idx = ParentNodeIndex::new(idx);
    //         if let Some(p_node) = node {
    //             self.insert_parent_at(p_idx, p_node)?;
    //         } else {
    //             self.blank_parent(p_idx)?;
    //         }
    //     }
    //     Ok(())
    // }

    pub(crate) fn apply_path(&mut self, change: TreeChange) -> Result<(), CGKAError> {
        println!("\n\n apply_path(): ");
        println!("- leaf: {:?}", change.new_path.leaf_idx);
        println!(
            "- new_path: {:?}",
            change
                .new_path
                .path
                .iter()
                .map(|(idx, _)| ParentNodeIndex::new(*idx))
                .collect::<Vec<ParentNodeIndex>>()
        );
        println!(
            "- undo_path: {:?}",
            change
                .undo
                .path
                .iter()
                .map(|(idx, _)| ParentNodeIndex::new(*idx))
                .collect::<Vec<ParentNodeIndex>>()
        );
        debug_assert_eq!(change.new_path.path.len(), change.undo.path.len());
        let leaf_idx = LeafNodeIndex::new(change.new_path.leaf_idx);
        let leaf_id = self
            .leaf(leaf_idx)?
            .as_ref()
            .ok_or(CGKAError::IdentifierNotFound)?
            .id;
        // TODO: Handle conflicting keys
        self.insert_leaf_at(leaf_idx, leaf_id, change.new_path.leaf_pk)?;
        self.validate_change(leaf_id, &change)?;
        for ((idx, node), (undo_idx, undo_node)) in
            change.new_path.path.iter().zip(change.undo.path)
        {
            debug_assert_eq!(*idx, undo_idx);
            println!("-- Next merging node: {:?}", ParentNodeIndex::new(*idx));
            let p_idx = ParentNodeIndex::new(*idx);
            let current_p_node = self.parent(p_idx)?;
            let new_p_node = if let Some(current) = current_p_node {
                // TODO: borrow mutably here and then we don't need to clone and insert
                let mut p_node = current.clone();
                println!("_______");
                println!("Merging in {:?}", p_idx);
                p_node.merge(
                    node.as_ref().map(|p| &p.secret_store),
                    undo_node.as_ref().map(|p| &p.secret_store),
                )?;
                Some(p_node)
            } else {
                println!("-- My node was blank, so just overwriting!");
                node.clone()
            };
            if let Some(parent) = new_p_node {
                self.insert_parent_at(p_idx, parent)?;
            } else {
                self.blank_parent(p_idx)?;
            }
        }
        Ok(())
    }

    pub(crate) fn has_root_key(&self) -> Result<bool, CGKAError> {
        let root_idx: TreeNodeIndex = treemath::root(self.tree_size);
        let TreeNodeIndex::Parent(p_idx) = root_idx else {
            return Err(CGKAError::TreeIndexOutOfBounds);
        };
        Ok(if let Some(r) = self.parent(p_idx)? {
            // A root with a public key conflict does not have a decryption secret
            !r.has_conflict()
        } else {
            false
        })
    }

    fn decrypt_parent_key(
        &self,
        non_blank_child_idx: TreeNodeIndex,
        child_idx: TreeNodeIndex,
        child_multikey: &Multikey,
        mut child_sks: &mut SecretKeyMap,
    ) -> Result<Option<SecretKey>, CGKAError> {
        debug_assert!(!self.is_root(child_idx));
        let parent_idx = treemath::parent(child_idx);
        println!("__________");
        println!("Decrypting {:?}", parent_idx);
        debug_assert!(!self.is_blank(parent_idx.into())?);
        let parent = self
            .parent(parent_idx)?
            .as_ref()
            .ok_or(CGKAError::TreeIndexOutOfBounds)?;

        let maybe_secret = if let Some(parent_pk) = parent.single_pk() {
            println!("--Single secret");
            // TODO: Check if we have already decrypted this secret.
            let secret =
                parent.decrypt_secret(non_blank_child_idx, child_multikey, &mut child_sks)?;
            println!(
                "--Inserting decrypted secret from {:?} for pk {:?}",
                parent_idx, parent_pk
            );
            child_sks.insert(parent_pk, secret.clone());
            Some(secret)
        } else {
            println!("--Multiple secrets");
            // If we haven't decrypted all secrets for a conflict node, we need to do
            // that before continuing.
            parent.decrypt_undecrypted_secrets(
                non_blank_child_idx,
                child_multikey,
                &mut child_sks,
            )?;
            None
        };
        Ok(maybe_secret)
    }

    fn encrypt_key_for_parent(
        &mut self,
        child_idx: TreeNodeIndex,
        child_pk: PublicKey,
        child_sk: &SecretKey,
        new_parent_pk: PublicKey,
        new_parent_sk: &SecretKey,
    ) -> Result<(), CGKAError> {
        debug_assert!(!self.is_root(child_idx));
        let parent_idx = treemath::parent(child_idx);
        let (encrypter_paired_pk, new_secret_map) =
            self.encrypt_new_secret_for_parent(child_idx, child_pk, child_sk, new_parent_sk)?;
        let secret_store =
            SecretStore::new(new_parent_pk, child_pk, encrypter_paired_pk, new_secret_map);
        let node = ParentNode::new(secret_store);
        self.insert_parent_at(parent_idx, node)?;
        Ok(())
    }

    fn encrypt_new_secret_for_parent(
        &self,
        child_idx: TreeNodeIndex,
        child_pk: PublicKey,
        child_sk: &SecretKey,
        new_parent_sk: &SecretKey,
    ) -> Result<
        (
            Option<Multikey>,
            BTreeMap<TreeNodeIndex, NestedEncrypted<SecretKey>>,
        ),
        CGKAError,
    > {
        debug_assert!(!self.is_root(child_idx));
        let sibling_idx = treemath::sibling(child_idx);
        let mut secret_map = BTreeMap::new();
        let mut sibling_resolution = Vec::new();
        self.append_resolution(sibling_idx, &mut sibling_resolution)?;
        let encrypter_paired_pk = if sibling_resolution.is_empty() {
            // Normally you use a DH shared key to encrypt/decrypt the next node up,
            // but if there's a blank sibling subtree, then you use your secret key
            // directly instead.
            let encrypted_sk =
                encrypt_nested_secret(new_parent_sk, vec![(child_pk, child_sk.clone())])?;
            secret_map.insert(child_idx, encrypted_sk);
            None
        } else {
            // Encrypt the secret for every node in the sibling resolution, using
            // a new DH shared secret to do the encryption for each node.
            let mut paired_pk = None;
            for idx in sibling_resolution {
                let sibling_multikey = self.multikey_for_index(idx)?;
                let shared_keys = sibling_multikey
                    .keys()
                    .map(|sibling_pk| (*sibling_pk, generate_shared_key(sibling_pk, child_sk)))
                    .collect();
                let encrypted_sk = encrypt_nested_secret(new_parent_sk, shared_keys)?;
                if paired_pk.is_none() {
                    secret_map.insert(child_idx, encrypted_sk.clone());
                    paired_pk = Some(sibling_multikey.clone());
                }
                secret_map.insert(idx, encrypted_sk);
            }
            paired_pk
        };
        Ok((encrypter_paired_pk, secret_map))
    }

    fn is_blank(&self, idx: TreeNodeIndex) -> Result<bool, CGKAError> {
        Ok(match idx {
            TreeNodeIndex::Leaf(l_idx) => self.leaf(l_idx)?.is_none(),
            TreeNodeIndex::Parent(p_idx) => self.parent(p_idx)?.is_none(),
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
        if idx.usize() >= self.parents.len() {
            return Err(CGKAError::TreeIndexOutOfBounds);
        }
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

    fn path_length_for(&self, idx: LeafNodeIndex) -> usize {
        treemath::direct_path(idx, self.tree_size).len()
    }

    /// Highest non-blank descendents of a node
    fn append_resolution(
        &self,
        idx: TreeNodeIndex,
        acc: &mut Vec<TreeNodeIndex>,
    ) -> Result<(), CGKAError> {
        match idx {
            TreeNodeIndex::Leaf(l_idx) => {
                if self.leaf(l_idx)?.is_some() {
                    acc.push(l_idx.into());
                }
            }
            TreeNodeIndex::Parent(p_idx) => {
                if self.parent(p_idx)?.is_some() {
                    acc.push(p_idx.into());
                } else {
                    let left_idx = treemath::left(p_idx);
                    self.append_resolution(left_idx, acc)?;
                    let right_idx = treemath::right(p_idx);
                    self.append_resolution(right_idx, acc)?;
                }
            }
        }
        Ok(())
    }
}

// TODO: This is currently just a stopgap for tree hashing. How do we actually want
// to derive the tree hash?
impl From<BeeKEM> for Vec<u8> {
    fn from(tree: BeeKEM) -> Self {
        bincode::serialize(&tree).expect("Serialization failed")
    }
}

#[derive(Clone, Deserialize, Serialize)]
pub(crate) struct LeafNode {
    pub id: Identifier,
    pub pk: Multikey,
}

impl Debug for LeafNode {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("LeafNode")
            .field("id", &self.id)
            // FIXME
            //   .field("pk", &self.pk.to_bytes())
            .finish()
    }
}

#[derive(Clone, Deserialize, Serialize)]
pub struct ParentNode {
    pub secret_store: SecretStore,
    // /// Invariant: PublicKeys must be in lexicographic order
    // pub pk: Multikey,
    // /// TODO: Document
    // pub secret_store: SecretStore,
}

impl ParentNode {
    pub fn new(secret_store: SecretStore) -> Self {
        Self { secret_store }
    }

    pub fn has_conflict(&self) -> bool {
        self.secret_store.has_conflict()
    }

    pub fn single_pk(&self) -> Option<PublicKey> {
        self.secret_store.single_pk()
    }

    pub fn multikey(&self) -> &Multikey {
        self.secret_store.multikey()
    }

    pub fn decrypt_secret(
        &self,
        non_blank_child_idx: TreeNodeIndex,
        child_multikey: &Multikey,
        child_sks: &mut SecretKeyMap,
    ) -> Result<SecretKey, CGKAError> {
        self.secret_store
            .decrypt_secret(non_blank_child_idx, child_multikey, child_sks)
    }

    pub fn decrypt_undecrypted_secrets(
        &self,
        child_idx: TreeNodeIndex,
        child_multikey: &Multikey,
        child_sks: &mut SecretKeyMap,
    ) -> Result<(), CGKAError> {
        self.secret_store
            .decrypt_undecrypted_secrets(child_idx, child_multikey, child_sks)
    }

    pub fn merge(
        &mut self,
        other: Option<&SecretStore>,
        replaced: Option<&SecretStore>,
    ) -> Result<(), CGKAError> {
        self.secret_store.merge(other, replaced)
    }

    // pub fn encrypter_pk(&self) -> PublicKey {
    //     self.secret_store.encrypter_pk
    // }

    // pub fn encrypter_paired_pk(&self) -> &Option<Multikey> {
    //     &self.secret_store.encrypter_paired_pk
    // }
}

impl Debug for ParentNode {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("ParentNode")
            // FIXME
            //   .field("pk", &self.pk.to_bytes())
            //   .field("encrypter_pk", &self.encrypter_pk.to_bytes())
            //   .field("encrypter_paired_pk", &self.encrypter_paired_pk.map(|pk| pk.to_bytes()))
            .finish()
    }
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

fn generate_shared_key(their_public_key: &PublicKey, my_secret: &SecretKey) -> SecretKey {
    x25519(my_secret.to_bytes(), their_public_key.to_bytes()).into()
}

fn encrypt_bytes(bytes: &[u8], encrypt_key: &SecretKey) -> Result<(Siv, Vec<u8>), CGKAError> {
    let mut nonce = [0u8; 24];
    rand::thread_rng().fill_bytes(&mut nonce);
    let symmetric_key = SymmetricKey::from(encrypt_key.to_bytes());
    let encrypted_secret = symmetric_key
        .encrypt(nonce.into(), bytes)
        .map_err(CGKAError::Encryption)?;
    Ok((nonce.into(), encrypted_secret))
}

fn encrypt_nested_secret(
    secret: &SecretKey,
    encrypt_keys: Vec<(PublicKey, SecretKey)>,
) -> Result<NestedEncrypted<SecretKey>, CGKAError> {
    debug_assert!(encrypt_keys.len() >= 1);
    let paired_pks = encrypt_keys.iter().map(|(pk, _)| *pk).collect();
    let mut nonces: Vec<Siv> = Vec::new();
    let (mut nonce, mut encrypted_secret_bytes): (Siv, Vec<u8>) =
        encrypt_bytes(&secret.to_bytes(), &encrypt_keys[0].1)?;
    nonces.push(nonce);
    for (_, encrypt_key) in encrypt_keys.iter().skip(1) {
        (nonce, encrypted_secret_bytes) = encrypt_bytes(&secret.to_bytes(), encrypt_key)?;
        nonces.push(nonce);
    }
    let encrypted_secret: NestedEncrypted<SecretKey> =
        NestedEncrypted::new(nonces, paired_pks, encrypted_secret_bytes);
    Ok(encrypted_secret)
}
//////////////////////////////////////////////////////////////////
