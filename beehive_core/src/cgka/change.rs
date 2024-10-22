use crate::principal::identifier::Identifier;

use super::beekem::{ParentNode, PublicKey};

pub struct CGKAChange {
    /// The id of the one who initiated the change.
    pub changer_id: Identifier,
    /// The new operation we're applying
    pub op: CGKAOperation,
    /// The path that is being replaced.
    /// In order to rewind, we need the specific public keys along the path, which could
    /// potentially only be reconstructed by replaying from the beginning otherwise.
    pub undo: TreePath,
}

pub struct TreePath {
    pub leaf_idx: u32,
    pub leaf_pk: PublicKey,
    pub path: Vec<(u32, Option<ParentNode>)>,
}

pub enum CGKAOperation {
    Add { id: Identifier, pk: PublicKey, leaf_index: u32, owner_path: TreePath },
    Merge,
    Remove { id: Identifier, leaf_index: u32, owner_path: TreePath },
    Update { id: Identifier, new_path: TreePath },
}
