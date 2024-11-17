use super::beekem::PathChange;
use crate::{crypto::share_key::ShareKey, principal::individual::id::IndividualId};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub enum CgkaOperation {
    Add {
        id: IndividualId,
        pk: ShareKey,
        leaf_index: u32,
    },
    Remove {
        id: IndividualId,
        removed_keys: Vec<ShareKey>,
    },
    Update {
        id: IndividualId,
        new_path: PathChange,
    },
}
