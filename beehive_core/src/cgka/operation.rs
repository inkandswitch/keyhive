use std::{collections::HashSet, rc::Rc};

use super::beekem::PathChange;
use crate::{
    content::reference::ContentRef,
    crypto::{digest::Digest, share_key::ShareKey, signed::Signed},
    principal::{
        group::operation::{delegation::Delegation, revocation::Revocation},
        individual::id::IndividualId,
    },
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Hash, Eq, PartialEq, Deserialize, Serialize)]
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

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CgkaOperationPredecessors<T: ContentRef> {
    pub update_preds: HashSet<Digest<CgkaOperation>>,
    pub delegation_preds: HashSet<Rc<Signed<Delegation<T>>>>,
    pub revocation_preds: HashSet<Rc<Signed<Revocation<T>>>>,
}

impl<T: ContentRef> CgkaOperationPredecessors<T> {
    pub fn new() -> Self {
        Self {
            update_preds: Default::default(),
            delegation_preds: Default::default(),
            revocation_preds: Default::default(),
        }
    }

    pub fn depends_on_membership_ops(&self) -> bool {
        !(self.delegation_preds.is_empty() && self.revocation_preds.is_empty())
    }
}

impl<T: ContentRef> Default for CgkaOperationPredecessors<T> {
    fn default() -> Self {
        CgkaOperationPredecessors::new()
    }
}
