use std::{
    collections::{HashMap, HashSet},
    rc::Rc,
};

use super::beekem::PathChange;
use crate::{
    crypto::{digest::Digest, share_key::ShareKey},
    principal::individual::id::IndividualId,
    util::content_addressed_map::CaMap,
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
        added_id: IndividualId,
        pk: ShareKey,
        leaf_index: u32,
        predecessors: Vec<Digest<CgkaOperation>>,
    },
    Remove {
        id: IndividualId,
        removed_keys: Vec<ShareKey>,
        predecessors: Vec<Digest<CgkaOperation>>,
    },
    Update {
        id: IndividualId,
        new_path: PathChange,
        predecessors: Vec<Digest<CgkaOperation>>,
    },
}

impl CgkaOperation {
    pub fn predecessors(&self) -> HashSet<Digest<CgkaOperation>> {
        match self {
            CgkaOperation::Add { predecessors, .. } => {
                HashSet::from_iter(predecessors.iter().cloned())
            }
            CgkaOperation::Remove { predecessors, .. } => {
                HashSet::from_iter(predecessors.iter().cloned())
            }
            CgkaOperation::Update { predecessors, .. } => {
                HashSet::from_iter(predecessors.iter().cloned())
            }
        }
    }
}

// FIXME: Docs
/// Notes on predecessors: For update operations, we keep track of all immediate
/// causal predecessors. For membership operations, we only keep track of immediate
/// causal predecessors if they are other membership operations.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CgkaOperationGraph {
    pub cgka_ops: CaMap<CgkaOperation>,
    pub cgka_ops_predecessors: HashMap<Digest<CgkaOperation>, CgkaOperationPredecessors>,
    pub cgka_op_heads: HashSet<Digest<CgkaOperation>>,
    // FIXME
    // pub membership_op_to_cgka_op: HashMap<Operation<T>, Digest<CgkaOperation>>,
    // pub cgka_op_to_membership_op: HashMap<Digest<CgkaOperation>, Operation<T>>,
}

impl CgkaOperationGraph {
    pub fn new() -> Self {
        Self {
            cgka_ops: Default::default(),
            cgka_ops_predecessors: Default::default(),
            cgka_op_heads: Default::default(),
            // FIXME
            // membership_op_to_cgka_op: Default::default(),
            // cgka_op_to_membership_op: Default::default(),
        }
    }

    // FIXME: We need to account for heads
    pub fn add_local_op(&mut self, op: &CgkaOperation) {
        self.add_op_and_update_heads(op, None);
    }

    // FIXME: We need to account for heads
    pub fn add_op(&mut self, op: &CgkaOperation, heads: &HashSet<Digest<CgkaOperation>>) {
        self.add_op_and_update_heads(op, Some(heads));
    }

    fn add_op_and_update_heads(
        &mut self,
        op: &CgkaOperation,
        external_heads: Option<&HashSet<Digest<CgkaOperation>>>,
    ) {
        let op_hash = Digest::hash(op);
        let mut op_predecessors = CgkaOperationPredecessors::new();
        self.cgka_ops.insert(op.clone().into());
        if let Some(heads) = external_heads {
            for h in heads {
                op_predecessors.update_preds.insert(*h);
                self.cgka_op_heads.remove(&h);
            }
        } else {
            for h in &self.cgka_op_heads {
                op_predecessors.update_preds.insert(*h);
            }
            self.cgka_op_heads.clear();
        };
        self.cgka_op_heads.insert(op_hash);
        self.cgka_ops_predecessors.insert(op_hash, op_predecessors);
    }

    pub fn contains_current_heads(&self, heads: &HashSet<Digest<CgkaOperation>>) -> bool {
        self.cgka_op_heads.is_subset(heads)
    }

    // FIXME
    // pub fn add_local_membership_op(&mut self, membership_op: Operation<T>, cgka_op: &CgkaOperation) {
    //     self.add_membership_op_and_update_heads(membership_op, cgka_op, None);
    // }

    // pub fn add_membership_op(&mut self, membership_op: Operation<T>, cgka_op: &CgkaOperation, external_heads: &HashSet<Operation<T>>) {
    //     self.add_membership_op_and_update_heads(membership_op, cgka_op, Some(external_heads));
    // }

    // // FIXME: We need to account for heads
    // fn add_membership_op_and_update_heads(&mut self, membership_op: Operation<T>, cgka_op: &CgkaOperation, external_heads: Option<&HashSet<Operation<T>>>) {
    //     let cgka_op_hash = Digest::hash(cgka_op);
    //     self.membership_op_to_cgka_op
    //         .insert(membership_op.clone(), cgka_op_hash);
    //     self.cgka_ops.insert(cgka_op.clone().into());
    //     self.membership_op_to_cgka_op.insert(membership_op.clone(), cgka_op_hash);
    //     self.cgka_op_to_membership_op.insert(cgka_op_hash, membership_op.clone().into());
    //     let mut op_predecessors = CgkaOperationPredecessors::new();
    //     if let Some(heads) = external_heads {
    //         for h in heads {
    //             op_predecessors.preds.insert(*self.membership_op_to_cgka_op.get(h).expect("predecessor hash to be present"));
    //             self.cgka_op_heads.remove(self.membership_op_to_cgka_op.get(&membership_op).expect("predecessors to be present"));
    //         }
    //     } else {
    //         for h in &self.cgka_op_heads {
    //             op_predecessors.preds.insert(*h);
    //         }
    //         self.cgka_op_heads.clear();
    //     };
    //     self.cgka_op_heads.insert(cgka_op_hash);
    //     self.cgka_ops_predecessors.insert(cgka_op_hash, op_predecessors);
    // }

    pub fn predecessors_for(
        &self,
        op_hash: &Digest<CgkaOperation>,
    ) -> Option<&CgkaOperationPredecessors> {
        self.cgka_ops_predecessors.get(op_hash)
    }

    pub fn get_cgka_op(&self, op_hash: &Digest<CgkaOperation>) -> Option<&Rc<CgkaOperation>> {
        self.cgka_ops.get(op_hash)
    }

    // FIXME
    // pub fn get_cgka_op_for_membership_op(&self, membership_op: &Operation<T>) -> Option<&Digest<CgkaOperation>> {
    //     self.membership_op_to_cgka_op.get(membership_op)
    // }
    // pub fn get_membership_op_for_cgka_op(&self, cgka_op: &Digest<CgkaOperation>) -> Option<&Operation<T>> {
    //     self.cgka_op_to_membership_op.get(cgka_op)
    // }
}

impl Default for CgkaOperationGraph {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CgkaOperationPredecessors {
    pub update_preds: HashSet<Digest<CgkaOperation>>,
    pub membership_preds: HashSet<Digest<CgkaOperation>>,
    // FIXME: Get rid of these and possibly this whole struct. We'll look up
    // the membership op hashes using the CgkaOperation hashes.
    // pub delegation_preds: HashSet<Digest<Signed<Delegation<T>>>>,
    // pub revocation_preds: HashSet<Digest<Signed<Revocation<T>>>>,
}

impl CgkaOperationPredecessors {
    pub fn new() -> Self {
        Self {
            update_preds: Default::default(),
            membership_preds: Default::default(),
            // delegation_preds: Default::default(),
            // revocation_preds: Default::default(),
        }
    }
}

impl Default for CgkaOperationPredecessors {
    fn default() -> Self {
        CgkaOperationPredecessors::new()
    }
}
