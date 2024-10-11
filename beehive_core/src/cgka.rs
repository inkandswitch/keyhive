// * Leaf nodes represent participants. Each participant has a fixed Identifier as well
//   as a public key that is rotated over time.
// * Each non-leaf node stores one or more public keys and a secret used
//   to decrypt the parent.
// * Secrets are randomly generated.
// * A node is encrypted via Diffie Hellman using the private key of one child
//   node and the public key of its sibling.
// * Fast lookup of leaf by identifier.
// * All operations start from leaf (?).
// * Must walk to each child on the copath.
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
// *
// *

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use x25519_dalek;

use crate::{crypto::encrypted::Encrypted, principal::identifier::Identifier};
type PublicKey = x25519_dalek::PublicKey;
type SecretKey = x25519_dalek::StaticSecret;

#[derive(Clone, Deserialize, Serialize)]
pub struct LeafIdx(usize);
#[derive(Clone, Deserialize, Serialize)]
pub struct ParentIdx(usize);

#[derive(Clone, Deserialize, Serialize)]
pub struct CausalTreeKEM {
    my_leaf_idx: LeafIdx,
    leaves: Vec<Option<LeafNode>>,
    parents: Vec<Option<ParentNode>>,
    id_to_leaf_idx: BTreeMap<Identifier, LeafIdx>,
    // FIXME: One option is to use the treemath approach from OpenMLS.
    // tree: ...,
}

impl CausalTreeKEM {
    pub fn new(pks: Vec<PublicKey>) -> Self {
        todo!()
        // FIXME: Build left-balanced binary tree with pks as leaves.
    }
}

/// Public interface
// TODO: Can we assume causal broadcast?
impl CausalTreeKEM {
    /// Get secret for decryption/encryption.
    pub fn get_secret(&self, pk: PublicKey, sk: SecretKey) -> SecretKey {
        todo!()
    }

    /// Add key.
    pub fn add(&mut self, id: Identifier, pk: PublicKey) {
        todo!()
    }

    /// Contains id.
    pub fn contains_id(&self, id: Identifier) -> bool {
        self.id_to_leaf_idx.contains_key(&id)
    }

    // /// Contains key.
    // pub fn contains_key(&self, pk: PublicKey) -> bool {
    //     self.id_for_pk(pk).is_some()
    // }

    // /// Get Identifier for key.
    // pub fn id_for_pk(&self, pk: PublicKey) -> Option<Identifier> {
    //     todo!()
    // }

    /// Remove participant.
    pub fn remove(&mut self, id: Identifier) {
        todo!()
    }

    /// Rotate key.
    pub fn update(&mut self, id: Identifier, old_pk: PublicKey, new_pk: PublicKey, new_sk: SecretKey) {
        todo!()
    }

    /// Merge
    pub fn merge(&mut self, tree: &CausalTreeKEM) {
        todo!()
    }
}

/// Private methods
impl CausalTreeKEM {
    // fn is_root(&self, node: TreeIdx) -> bool {
    //     todo!()
    // }
}

#[derive(Clone, Deserialize, Serialize)]
pub enum TreeNode {
    Leaf(LeafNode),
    Parent(ParentNode),
}

impl TreeNode {
    fn resolution(&self) -> Vec<TreeNode> {
        match self {
            TreeNode::Leaf(l) => l.resolution(),
            TreeNode::Parent(p) => p.resolution(),
        }
    }
}

impl From<LeafNode> for TreeNode {
    fn from(leaf: LeafNode) -> TreeNode {
        TreeNode::Leaf(leaf)
    }
}

impl From<ParentNode> for TreeNode {
    fn from(node: ParentNode) -> TreeNode {
        TreeNode::Parent(node)
    }
}

#[derive(Clone, Deserialize, Serialize)]
pub struct LeafNode {
    pub id: Identifier,
    pub pk: PublicKey,
}

impl LeafNode {
    /// Highest non-blank descendents of a node
    fn resolution(&self) -> Vec<TreeNode> {
        vec![self.clone().into()]
    }
}

#[derive(Clone, Deserialize, Serialize)]
pub struct ParentNode {
    pub pks: Vec<PublicKey>,
    pub sk: Encrypted<SecretKey>,
}

impl ParentNode {
    /// Highest non-blank descendents of a node
    fn resolution(&self) -> Vec<TreeNode> {
        todo!()
    }
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

/// Requires the following properties:
///   1: If (x, X) and (y, Y) are valid key pairs, then so is (x, X) * (y, Y) = (x *pub y, X *priv Y).
///   2: * is associative and commutative (ensuring order of concurrent updates doesn't matter).
///   3: *pub is cancellative: if x *pub z = y *pub z for some z, then x = y.
fn star(pk: PublicKey, sk: SecretKey) -> (PublicKey, SecretKey) {
    (star_pub(pk), star_priv(sk))
}

fn star_pub(pk: PublicKey) -> PublicKey {
    todo!()
}

fn star_priv(sk: SecretKey) -> SecretKey {
    todo!()
}



