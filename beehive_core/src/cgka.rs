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

pub mod treemath;

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use treemath::{LeafNodeIndex, ParentNodeIndex, TreeNodeIndex, TreeSize};
use x25519_dalek;

use crate::{crypto::{encrypted::Encrypted, hash::Hash}, principal::identifier::Identifier};
type PublicKey = x25519_dalek::PublicKey;
type SecretKey = x25519_dalek::StaticSecret;

#[derive(Clone, Deserialize, Serialize)]
pub struct CGKA {
    pub my_leaf_idx: Option<LeafNodeIndex>,
    next_leaf_idx: LeafNodeIndex,
    leaves: Vec<Option<LeafNode>>,
    parents: Vec<Option<ParentNode>>,
    id_to_leaf_idx: BTreeMap<Identifier, LeafNodeIndex>,
    tree_size: TreeSize,
    // FIXME: One option is to use the treemath approach from OpenMLS.
    // tree: ...,
    // /// Ops: Add, Remove, Rotate
    // ops: ...,
}

/// Constructors
impl CGKA {
    /// We assume participants are in causal order.
    pub fn new(participants: Vec<(Identifier, PublicKey)>, my_id: Identifier) -> Result<Self, CGKAError> {
        let mut cgka = Self {
            my_leaf_idx: None,
            next_leaf_idx: LeafNodeIndex::new(participants.len() as u32),
            leaves: Vec::new(),
            parents: Vec::new(),
            id_to_leaf_idx: BTreeMap::new(),
            tree_size: TreeSize::from_leaf_count(participants.len() as u32),
        };
        for (idx, (id, pk)) in participants.iter().enumerate() {
            if *id == my_id {
                cgka.my_leaf_idx = Some(LeafNodeIndex::new(idx as u32));
            }
            cgka.add(*id, *pk)?;
        }
        // TODO: Populate my path
        Ok(cgka)
    }
}

/// Tree
impl CGKA {
    fn get_leaf(&self, idx: LeafNodeIndex) -> Result<&Option<LeafNode>, CGKAError> {
        self.leaves.get(idx.usize()).ok_or(CGKAError::IndexOutOfBounds)
    }

    fn get_parent(&self, idx: ParentNodeIndex) -> Result<&Option<ParentNode>, CGKAError> {
        self.parents.get(idx.usize()).ok_or(CGKAError::IndexOutOfBounds)
    }

    fn insert_leaf_at(&mut self, idx: LeafNodeIndex, leaf: LeafNode) -> Result<(), CGKAError> {
        if idx.usize() >= self.leaves.len() { return Err(CGKAError::IndexOutOfBounds); }
        self.leaves[idx.usize()] = Some(leaf);
        Ok(())
    }

    fn insert_parent_at(&mut self, idx: ParentNodeIndex, parent: ParentNode) -> Result<(), CGKAError> {
        if idx.usize() >= self.parents.len() { return Err(CGKAError::IndexOutOfBounds); }
        self.parents[idx.usize()] = Some(parent);
        Ok(())
    }

    fn blank_leaf_and_path(&mut self, idx: LeafNodeIndex) -> Result<(), CGKAError> {
        if idx.usize() >= self.leaves.len() { return Err(CGKAError::IndexOutOfBounds); }
        self.leaves[idx.usize()] = None;
        self.blank_path(treemath::parent(idx.into()))
    }

    fn blank_path(&mut self, idx: ParentNodeIndex) -> Result<(), CGKAError> {
        self.blank_parent(idx)?;
        if self.is_root(idx.into()) { return Ok(()); }
        self.blank_path(treemath::parent(idx.into()))
    }

    fn blank_parent(&mut self, idx: ParentNodeIndex) -> Result<(), CGKAError> {
        // FIXME: This write can panic
        self.parents[idx.usize()] = None;
        Ok(())
    }

    fn push_leaf(&mut self, id: Identifier, pk: PublicKey) -> Result<(), CGKAError> {
        self.maybe_grow_tree(self.leaves.len() as u32 + 1);
        let l_idx = self.next_leaf_idx;
        // Increment next leaf idx
        self.next_leaf_idx = LeafNodeIndex::new(self.next_leaf_idx.u32() + 1);
        self.id_to_leaf_idx.insert(id, l_idx);
        self.insert_leaf_at(l_idx, LeafNode { id, pk })?;
        self.blank_path(treemath::parent(l_idx.into()))
    }

    /// Growing the tree will add a new root and a new subtree, all blank.
    fn maybe_grow_tree(&mut self, new_count: u32) {
        if self.tree_size >= TreeSize::from_leaf_count(new_count) { return; }
        self.tree_size.inc();
        // FIXME: Panics if MAX overflow
        self.leaves.reserve(self.tree_size.leaf_count() as usize);
        // FIXME: Does this effectively call reserve first under the hood?
        self.leaves.resize(self.tree_size.leaf_count() as usize, None);
        // FIXME: Panics if MAX overflow
        self.parents.reserve(self.tree_size.parent_count() as usize);
        // FIXME: Does this effectively call reserve first under the hood?
        self.parents.resize(self.tree_size.parent_count() as usize, None);
    }

    fn is_root(&self, idx: TreeNodeIndex) -> bool {
        idx == treemath::root(self.tree_size)
    }

    /// This is the size of the tree including any blank leaves
    fn tree_size(&self) -> u32 {
        self.tree_size.u32()
    }

    /// Contains id.
    fn contains_id(&self, id: Identifier) -> bool {
        self.id_to_leaf_idx.contains_key(&id)
    }
}

/// Public CGKA operations
impl CGKA {
    /// Get secret for decryption/encryption.
    pub fn get_secret(&self, sk: SecretKey) -> SecretKey {
        // Work from my leaf index up
        todo!()
    }

    /// Add participant.
    pub fn add(&mut self, id: Identifier, pk: PublicKey) -> Result<(), CGKAError> {
        self.push_leaf(id, pk)
    }

    /// Remove participant.
    pub fn remove(&mut self, id: Identifier) -> Result<(), CGKAError> {
        let l_idx = self.id_to_leaf_idx.get(&id).ok_or(CGKAError::IdentifierNotFound)?;
        self.blank_leaf_and_path(*l_idx)
    }

    /// Rotate key.
    pub fn update(&mut self, id: Identifier, old_pk: PublicKey, new_pk: PublicKey, new_sk: SecretKey) {
        todo!()
    }

    /// Merge
    // pub fn merge(&mut self, ops: ...) {
    //     todo!()
    // }

    /// Hash of the tree
    pub fn hash(&self) -> Hash<CGKA> {
        todo!()
    }
}

// #[derive(Clone, Deserialize, Serialize)]
// pub enum TreeNode {
//     Leaf(LeafNode),
//     Parent(ParentNode),
// }

// impl From<LeafNode> for TreeNode {
//     fn from(leaf: LeafNode) -> TreeNode {
//         TreeNode::Leaf(leaf)
//     }
// }

// impl From<ParentNode> for TreeNode {
//     fn from(node: ParentNode) -> TreeNode {
//         TreeNode::Parent(node)
//     }
// }

#[derive(Clone, Deserialize, Serialize)]
pub struct LeafNode {
    pub id: Identifier,
    pub pk: PublicKey,
}

#[derive(Clone, Deserialize, Serialize)]
pub struct ParentNode {
    pub pks: Vec<PublicKey>,
    pub sk: Encrypted<SecretKey>,
}

/// Highest non-blank descendents of a node
fn append_resolution<'a>(cgka: &'a CGKA, idx: TreeNodeIndex, leaves_acc: &mut Vec<&'a LeafNode>, parents_acc: &mut Vec<&'a ParentNode>) -> Result<(), CGKAError> {
    match idx {
        TreeNodeIndex::Leaf(l_idx) => {
            if let Some(leaf_node) = cgka.get_leaf(l_idx)? {
                leaves_acc.push(leaf_node);
            }
            Ok(())
        },
        TreeNodeIndex::Parent(p_idx) => {
            if let Some(parent_node) = cgka.get_parent(p_idx)? {
                parents_acc.push(parent_node);
                Ok(())
            } else {
                let left_idx = treemath::left(p_idx);
                append_resolution(cgka, left_idx, leaves_acc, parents_acc)?;
                let right_idx = treemath::right(p_idx);
                append_resolution(cgka, right_idx, leaves_acc, parents_acc)
            }
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum CGKAError {
    #[error("Index out of bounds")]
    IndexOutOfBounds,

    #[error("Identifier not found")]
    IdentifierNotFound,
}

//////////////////////////////////
//////////////////////////////////

// Derive key pair
fn dkp(x: &[u8]) -> (PublicKey, SecretKey) {
    todo!()
}

// Key derivation function
// Second input is used to prevent collisions (e.g. "path" or "node")
// fn kdf(&[u8], &[u8]) -> ???
