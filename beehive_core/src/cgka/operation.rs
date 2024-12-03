use super::{beekem::PathChange, error::CgkaError};
use crate::{
    crypto::{digest::Digest, share_key::ShareKey},
    principal::individual::id::IndividualId,
    util::content_addressed_map::CaMap,
};
use nonempty::NonEmpty;
use serde::{Deserialize, Serialize};
use std::{
    borrow::Borrow,
    collections::{HashMap, HashSet, VecDeque},
    rc::Rc,
};
use topological_sort::TopologicalSort;

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
        add_predecessors: Vec<Digest<CgkaOperation>>,
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

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CgkaOperationGraph {
    pub cgka_ops: CaMap<CgkaOperation>,
    pub cgka_ops_predecessors: HashMap<Digest<CgkaOperation>, HashSet<Digest<CgkaOperation>>>,
    pub cgka_op_heads: HashSet<Digest<CgkaOperation>>,
    pub add_heads: HashSet<Digest<CgkaOperation>>,
}

impl CgkaOperationGraph {
    pub fn new() -> Self {
        Self {
            cgka_ops: Default::default(),
            cgka_ops_predecessors: Default::default(),
            cgka_op_heads: Default::default(),
            add_heads: Default::default(),
        }
    }

    pub fn contains_op_hash(&self, op_hash: &Digest<CgkaOperation>) -> bool {
        self.cgka_ops.contains_key(op_hash)
    }

    pub fn has_single_head(&self) -> bool {
        self.cgka_op_heads.len() == 1
    }

    pub fn add_local_op(&mut self, op: &CgkaOperation) {
        self.add_op_and_update_heads(op, None);
    }

    pub fn add_op(&mut self, op: &CgkaOperation, heads: &HashSet<Digest<CgkaOperation>>) {
        self.add_op_and_update_heads(op, Some(heads));
    }

    fn add_op_and_update_heads(
        &mut self,
        op: &CgkaOperation,
        external_heads: Option<&HashSet<Digest<CgkaOperation>>>,
    ) {
        let op_hash = Digest::hash(op);
        let mut op_predecessors = HashSet::new();
        self.cgka_ops.insert(op.clone().into());
        let is_add = self.is_add_op(&op_hash);
        if let Some(heads) = external_heads {
            for h in heads {
                op_predecessors.insert(*h);
                self.cgka_op_heads.remove(h);
            }
            if let CgkaOperation::Add {
                add_predecessors, ..
            } = op
            {
                for h in add_predecessors {
                    self.add_heads.remove(h);
                }
            }
        } else {
            for h in &self.cgka_op_heads {
                op_predecessors.insert(*h);
            }
            self.cgka_op_heads.clear();
            if is_add {
                self.add_heads.clear();
            }
        };
        self.cgka_op_heads.insert(op_hash);
        if self.is_add_op(&op_hash) {
            self.add_heads.insert(op_hash);
        }
        self.cgka_ops_predecessors.insert(op_hash, op_predecessors);
    }

    pub fn heads_contained_in(&self, heads: &HashSet<Digest<CgkaOperation>>) -> bool {
        self.cgka_op_heads.is_subset(heads)
    }

    pub fn add_heads_contained_in(&self, heads: &HashSet<Digest<CgkaOperation>>) -> bool {
        self.add_heads.is_subset(heads)
    }

    fn is_add_op(&self, hash: &Digest<CgkaOperation>) -> bool {
        let op = self.cgka_ops.get(hash).expect("op to be in history");
        matches!(op.borrow(), &CgkaOperation::Add { .. })
    }

    pub fn predecessors_for(
        &self,
        op_hash: &Digest<CgkaOperation>,
    ) -> Option<&HashSet<Digest<CgkaOperation>>> {
        self.cgka_ops_predecessors.get(op_hash)
    }

    pub fn get_cgka_op(&self, op_hash: &Digest<CgkaOperation>) -> Option<&Rc<CgkaOperation>> {
        self.cgka_ops.get(op_hash)
    }

    pub fn topsort_graph(&self) -> Result<NonEmpty<Rc<CgkaOperation>>, CgkaError> {
        self.topsort_for_heads(&self.cgka_op_heads)
    }

    pub fn topsort_for_heads(
        &self,
        heads: &HashSet<Digest<CgkaOperation>>,
    ) -> Result<NonEmpty<Rc<CgkaOperation>>, CgkaError> {
        debug_assert!(heads.iter().all(|head| self.cgka_ops.contains_key(head)));
        let mut op_hashes = Vec::new();
        let mut dependencies = TopologicalSort::<Digest<CgkaOperation>>::new();
        let mut frontier = VecDeque::new();
        let mut seen = HashSet::new();
        for head in heads {
            frontier.push_back(*head);
            seen.insert(head);
        }
        while let Some(op_hash) = frontier.pop_front() {
            let preds = self
                .predecessors_for(&op_hash)
                .ok_or(CgkaError::OperationNotFound)?;
            for update_pred in preds {
                dependencies.add_dependency(*update_pred, op_hash);
                if seen.contains(update_pred) {
                    continue;
                }
                seen.insert(update_pred);
                frontier.push_back(*update_pred);
            }
        }
        while !dependencies.is_empty() {
            let mut next_set = dependencies.pop_all();
            next_set.sort();
            for hash in next_set {
                op_hashes.push(
                    self.cgka_ops
                        .get(&hash)
                        .ok_or(CgkaError::OperationNotFound)?
                        .clone(),
                );
            }
        }
        if op_hashes.is_empty() {
            op_hashes.extend(
                heads
                    .iter()
                    .map(|hash| {
                        self.cgka_ops
                            .get(hash)
                            .ok_or(CgkaError::OperationNotFound)
                            .expect("head to be present")
                            .clone()
                    })
                    .collect::<Vec<_>>(),
            );
        }
        Ok(NonEmpty::from_vec(op_hashes).expect("to have at least one op hash"))
    }
}

impl Default for CgkaOperationGraph {
    fn default() -> Self {
        Self::new()
    }
}
