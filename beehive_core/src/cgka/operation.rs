use std::{
    borrow::Borrow,
    collections::{HashMap, HashSet},
    rc::Rc,
};
use super::{beekem::PathChange, tombstone::CgkaTombstoneId};
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
        tombstone_id: CgkaTombstoneId,
    },
    Remove {
        id: IndividualId,
        removed_keys: Vec<ShareKey>,
        predecessors: Vec<Digest<CgkaOperation>>,
        tombstone_id: CgkaTombstoneId,
    },
    Update {
        id: IndividualId,
        new_path: PathChange,
        predecessors: Vec<Digest<CgkaOperation>>,
        tombstone_id: CgkaTombstoneId,
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
}

impl CgkaOperationGraph {
    pub fn new() -> Self {
        Self {
            cgka_ops: Default::default(),
            cgka_ops_predecessors: Default::default(),
            cgka_op_heads: Default::default(),
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
        println!("\nInserting head: {:?}", op_hash);
        self.cgka_op_heads.insert(op_hash);
        println!("--- CURRENT HEADS: {:?}", self.cgka_op_heads);
        self.cgka_ops_predecessors.insert(op_hash, op_predecessors);
    }

    pub fn heads_contained_in(&self, heads: &HashSet<Digest<CgkaOperation>>) -> bool {
        println!("\nheads_contained_in");
        println!("local heads: {:?}", self.cgka_op_heads);
        println!("other heads: {:?}\n", heads);

        let mut local_add_heads = self.cgka_op_heads.clone();
        local_add_heads.retain(|h| self.is_add_op(h));
        local_add_heads.is_subset(&heads)
    }

    fn is_add_op(&self, hash: &Digest<CgkaOperation>) -> bool {
        let op = self.cgka_ops.get(&hash).expect("op to be in history");
        matches!(op.borrow(), &CgkaOperation::Add { .. })
    }

    pub fn predecessors_for(
        &self,
        op_hash: &Digest<CgkaOperation>,
    ) -> Option<&CgkaOperationPredecessors> {
        self.cgka_ops_predecessors.get(op_hash)
    }

    pub fn get_cgka_op(&self, op_hash: &Digest<CgkaOperation>) -> Option<&Rc<CgkaOperation>> {
        self.cgka_ops.get(op_hash)
    }
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
}

impl CgkaOperationPredecessors {
    pub fn new() -> Self {
        Self {
            update_preds: Default::default(),
            membership_preds: Default::default(),
        }
    }
}

impl Default for CgkaOperationPredecessors {
    fn default() -> Self {
        CgkaOperationPredecessors::new()
    }
}
