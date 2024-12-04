use std::{collections::{HashMap, HashSet}, rc::Rc};

use super::beekem::PathChange;
use crate::{
    content::reference::ContentRef,
    crypto::{digest::Digest, share_key::ShareKey, signed::Signed},
    principal::{
        group::operation::{delegation::Delegation, revocation::Revocation, Operation},
        individual::id::IndividualId,
    }, util::content_addressed_map::CaMap,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
pub struct CgkaOperationWithPreds {
    pub op: CgkaOperation,
    pub preds: HashSet<Digest<CgkaOperation>>,
}

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
pub struct CgkaOperationGraph<T: ContentRef> {
    // FIXME
    pub cgka_ops: CaMap<CgkaOperation>,
    // FIXME
    pub cgka_ops_predecessors: HashMap<Digest<CgkaOperation>, CgkaOperationPredecessors<T>>,
    pub cgka_op_heads: HashSet<Digest<CgkaOperation>>,
    pub membership_op_to_cgka_op: HashMap<Digest<Operation<T>>, Digest<CgkaOperation>>,
}

impl<T: ContentRef> CgkaOperationGraph<T> {
    pub fn new() -> Self {
        Self {
            cgka_ops: Default::default(),
            cgka_ops_predecessors: Default::default(),
            cgka_op_heads: Default::default(),
            membership_op_to_cgka_op: Default::default(),
        }
    }

    // FIXME: We need to account for heads
    pub fn add_op(&mut self, op: &CgkaOperation) {
        let op_hash = Digest::hash(op);
        self.cgka_ops_predecessors.insert(op_hash, Default::default());
        self.cgka_ops.insert(op.clone().into());
        // FIXME: Figure out heads
        self.cgka_op_heads.insert(op_hash);
    }

    // FIXME: We need to account for heads
    pub fn add_membership_op(&mut self, membership_op: Operation<T>, cgka_op: &CgkaOperation) {
        let cgka_op_hash = Digest::hash(cgka_op);
        let membership_op_hash = Digest::hash(&membership_op);
        self.membership_op_to_cgka_op
            .insert(membership_op_hash, cgka_op_hash);
        self.cgka_ops.insert(cgka_op.clone().into());
        self.membership_op_to_cgka_op.insert(membership_op_hash, cgka_op_hash);
    }

    pub fn predecessors_for(&self, op_hash: &Digest<CgkaOperation>) -> Option<&CgkaOperationPredecessors<T>> {
        self.cgka_ops_predecessors.get(op_hash)
    }

    pub fn get_cgka_op(&self, op_hash: &Digest<CgkaOperation>) -> Option<&Rc<CgkaOperation>> {
        self.cgka_ops.get(op_hash)
    }

    pub fn get_cgka_op_for_membership_op(&self, membership_op: &Digest<Operation<T>>) -> Option<&Digest<CgkaOperation>> {
        self.membership_op_to_cgka_op.get(membership_op)
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CgkaOperationPredecessors<T: ContentRef> {
    pub update_preds: HashSet<Digest<CgkaOperation>>,
    pub delegation_preds: HashSet<Digest<Signed<Delegation<T>>>>,
    pub revocation_preds: HashSet<Digest<Signed<Revocation<T>>>>,
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
