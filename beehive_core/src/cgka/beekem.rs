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

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use treemath::{LeafNodeIndex, ParentNodeIndex, TreeNodeIndex, TreeSize};
use x25519_dalek;

use crate::{crypto::{encrypted::Encrypted, hash::Hash}, principal::identifier::Identifier};

use super::{error::CGKAError, treemath};
type PublicKey = x25519_dalek::PublicKey;
type SecretKey = x25519_dalek::StaticSecret;

#[derive(Clone, Deserialize, Serialize)]
pub(crate) struct BeeKEM {
    my_leaf_idx: Option<LeafNodeIndex>,
    next_leaf_idx: LeafNodeIndex,
    leaves: Vec<Option<LeafNode>>,
    parents: Vec<Option<ParentNode>>,
    tree_size: TreeSize,
    id_to_leaf_idx: BTreeMap<Identifier, LeafNodeIndex>,
}

/// Constructors
impl BeeKEM {
    /// We assume participants are in causal order.
    pub(crate) fn new(participants: Vec<(Identifier, PublicKey)>, my_id: Identifier) -> Result<Self, CGKAError> {
        let mut tree = Self {
            my_leaf_idx: None,
            next_leaf_idx: LeafNodeIndex::new(0),
            leaves: Vec::new(),
            parents: Vec::new(),
            tree_size: TreeSize::from_leaf_count(participants.len() as u32),
            id_to_leaf_idx: BTreeMap::new(),
        };
        tree.grow_tree_to_size();
        for (idx, (id, pk)) in participants.iter().enumerate() {
            if *id == my_id {
                tree.my_leaf_idx = Some(LeafNodeIndex::new(idx as u32));
            }
            tree.push_leaf(*id, *pk)?;
        }
        // TODO: Populate my path
        Ok(tree)
    }

    pub(crate) fn get_leaf(&self, idx: LeafNodeIndex) -> Result<&Option<LeafNode>, CGKAError> {
        self.leaves.get(idx.usize()).ok_or(CGKAError::TreeIndexOutOfBounds)
    }

    pub(crate) fn get_parent(&self, idx: ParentNodeIndex) -> Result<&Option<ParentNode>, CGKAError> {
        self.parents.get(idx.usize()).ok_or(CGKAError::TreeIndexOutOfBounds)
    }

    pub(crate) fn insert_leaf_at(&mut self, idx: LeafNodeIndex, leaf: LeafNode) -> Result<(), CGKAError> {
        println!("idxusize: {} >= leaves len {}", idx.usize(), self.leaves.len());
        if idx.usize() >= self.leaves.len() { return Err(CGKAError::TreeIndexOutOfBounds); }
        println!("inserting at {:?}", idx);
        self.leaves[idx.usize()] = Some(leaf);
        Ok(())
    }

    pub(crate) fn insert_parent_at(&mut self, idx: ParentNodeIndex, parent: ParentNode) -> Result<(), CGKAError> {
        if idx.usize() >= self.parents.len() { return Err(CGKAError::TreeIndexOutOfBounds); }
        self.parents[idx.usize()] = Some(parent);
        Ok(())
    }

    pub(crate) fn blank_leaf_and_path(&mut self, idx: LeafNodeIndex) -> Result<(), CGKAError> {
        println!("blank_leaf {:?}", idx);
        if idx.usize() >= self.leaves.len() { return Err(CGKAError::TreeIndexOutOfBounds); }
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
        let l_idx = self.id_to_leaf_idx.get(&id).ok_or(CGKAError::IdentifierNotFound)?;
        self.blank_leaf_and_path(*l_idx)?;
        self.id_to_leaf_idx.remove(&id);
        Ok(())
    }

    pub(crate) fn id_count(&self) -> u32 {
        self.id_to_leaf_idx.len() as u32
    }

    fn is_blank_leaf(&self, idx: LeafNodeIndex) -> Result<bool, CGKAError> {
        Ok(self.get_leaf(idx)?.is_none())
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

    /// Growing the tree will add a new root and a new subtree, all blank.
    fn maybe_grow_tree(&mut self, new_count: u32) {
        println!("maybe_grow_tree: size {:?}, new_count: {new_count}, new_size {:?}", self.tree_size, TreeSize::from_leaf_count(new_count));
        if self.tree_size >= TreeSize::from_leaf_count(new_count) { return; }
        self.tree_size.inc();
        self.grow_tree_to_size();
    }

    fn grow_tree_to_size(&mut self) {
        // FIXME: Panics if MAX overflow
        self.leaves.reserve(self.tree_size.leaf_count() as usize);
        // FIXME: Does this (effectively) call reserve first under the hood?
        self.leaves.resize(self.tree_size.leaf_count() as usize, None);
        // FIXME: Panics if MAX overflow
        self.parents.reserve(self.tree_size.parent_count() as usize);
        // FIXME: Does this (effectively) call reserve first under the hood?
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
fn append_resolution<'a>(tree: &'a BeeKEM, idx: TreeNodeIndex, leaves_acc: &mut Vec<&'a LeafNode>, parents_acc: &mut Vec<&'a ParentNode>) -> Result<(), CGKAError> {
    match idx {
        TreeNodeIndex::Leaf(l_idx) => {
            if let Some(leaf_node) = tree.get_leaf(l_idx)? {
                leaves_acc.push(leaf_node);
            }
            Ok(())
        },
        TreeNodeIndex::Parent(p_idx) => {
            if let Some(parent_node) = tree.get_parent(p_idx)? {
                parents_acc.push(parent_node);
                Ok(())
            } else {
                let left_idx = treemath::left(p_idx);
                append_resolution(tree, left_idx, leaves_acc, parents_acc)?;
                let right_idx = treemath::right(p_idx);
                append_resolution(tree, right_idx, leaves_acc, parents_acc)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use x25519_dalek::StaticSecret;

    use super::*;

    fn setup_participant() -> (Identifier, PublicKey) {
        let id = Identifier::new(ed25519_dalek::SigningKey::generate(&mut rand::thread_rng())
            .verifying_key());
        let secret = StaticSecret::random_from_rng(&mut rand::thread_rng());
        let pk = PublicKey::from(&secret);
        (id, pk)
    }

    // FIXME: These are basically duplicate tests from CGKA. Focus only on tree-specific
    // functionality, like tree size changes.
    #[test]
    fn test_simple_add() -> Result<(), CGKAError> {
        let me = setup_participant();
        let mut participants = vec![me];
        participants.push(setup_participant());
        let participant_count = participants.len() as u32;
        let tree = BeeKEM::new(participants, me.0)?;
        assert_eq!(tree.tree_size(), TreeSize::from_leaf_count(participant_count).u32());
        assert_eq!(tree.id_count(), participant_count);
        Ok(())
    }

    #[test]
    fn test_simple_add_and_remove() -> Result<(), CGKAError> {
        let me = setup_participant();
        let p1 = setup_participant();
        let participants = vec![me, p1];
        let initial_participant_count = participants.len() as u32;
        let mut tree = BeeKEM::new(participants, me.0)?;
        tree.remove_id(p1.0)?;
        assert_eq!(tree.tree_size(), TreeSize::from_leaf_count(initial_participant_count).u32());
        assert_eq!(tree.id_count(), initial_participant_count - 1);
        Ok(())
    }
}
