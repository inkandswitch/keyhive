use serde::{Deserialize, Serialize};

use crate::principal::identifier::Identifier;

use super::{beekem::PathChange, keys::PublicKey};

#[derive(Clone, Deserialize, Serialize)]
pub enum CgkaOperation {
    Add {
        id: Identifier,
        pk: PublicKey,
        leaf_index: u32,
    },
    Remove {
        id: Identifier,
        removed_keys: Vec<PublicKey>,
    },
    Update {
        id: Identifier,
        new_path: PathChange,
    },
}
