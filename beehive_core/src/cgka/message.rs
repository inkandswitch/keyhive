use crate::principal::identifier::Identifier;

use super::beekem::PublicKey;

pub type TreePath = Vec<(u32, PublicKey)>;

pub enum CGKAMessage {
    Add { id: Identifier, pk: PublicKey, leaf_index: u32, owner_path: TreePath },
    Merge,
    Remove { id: Identifier, leaf_index: u32, owner_path: TreePath },
    Update { id: Identifier, new_path: TreePath },
}
