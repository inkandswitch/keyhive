use super::beekem::PathChange;
use crate::{crypto::share_key::ShareKey, principal::identifier::Identifier};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub enum CgkaOperation {
    Add {
        id: Identifier,
        pk: ShareKey,
        leaf_index: u32,
    },
    Remove {
        id: Identifier,
        removed_keys: Vec<ShareKey>,
    },
    Update {
        id: Identifier,
        new_path: PathChange,
    },
}
