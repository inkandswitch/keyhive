use crate::principal::identifier::Identifier;

use super::beekem::{ParentNode, PublicKey};

pub struct TreePath {
    pub leaf_idx: u32,
    pub leaf_pk: PublicKey,
    pub path: Vec<(u32, Option<ParentNode>)>,
}

pub enum CGKAMessage {
    Add { id: Identifier, pk: PublicKey, leaf_index: u32, owner_path: TreePath },
    Merge,
    Remove { id: Identifier, leaf_index: u32, owner_path: TreePath },
    Update { id: Identifier, new_path: TreePath },
}
