use super::{beekem::PathChange, error::CgkaError};
use crate::{
    crypto::{digest::Digest, share_key::ShareKey, signed::Signed},
    principal::{document::id::DocumentId, individual::id::IndividualId},
    transact::{fork::Fork, merge::Merge},
    util::content_addressed_map::CaMap,
};
use derivative::Derivative;
use nonempty::NonEmpty;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque},
    hash::{Hash, Hasher},
    mem,
    ops::Deref,
    sync::Arc,
};
use topological_sort::TopologicalSort;

/// An ordered [`NonEmpty`] of concurrent [`CgkaOperation`]s.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CgkaEpoch(NonEmpty<Arc<Signed<CgkaOperation>>>);

impl From<NonEmpty<Arc<Signed<CgkaOperation>>>> for CgkaEpoch {
    fn from(item: NonEmpty<Arc<Signed<CgkaOperation>>>) -> Self {
        CgkaEpoch(item)
    }
}

impl Deref for CgkaEpoch {
    type Target = NonEmpty<Arc<Signed<CgkaOperation>>>;

    fn deref(&self) -> &NonEmpty<Arc<Signed<CgkaOperation>>> {
        &self.0
    }
}

impl IntoIterator for CgkaEpoch {
    type Item = Arc<Signed<CgkaOperation>>;
    type IntoIter = <NonEmpty<Arc<Signed<CgkaOperation>>> as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

#[derive(Debug, Clone, Hash, Eq, PartialEq, Deserialize, Serialize)]
#[cfg_attr(any(test, feature = "arbitrary"), derive(arbitrary::Arbitrary))]
pub enum CgkaOperation {
    Add {
        added_id: IndividualId,
        pk: ShareKey,
        leaf_index: u32,
        predecessors: Vec<Digest<Signed<CgkaOperation>>>,
        add_predecessors: Vec<Digest<Signed<CgkaOperation>>>,
        doc_id: DocumentId,
    },
    Remove {
        id: IndividualId,
        leaf_idx: u32,
        removed_keys: Vec<ShareKey>,
        predecessors: Vec<Digest<Signed<CgkaOperation>>>,
        doc_id: DocumentId,
    },
    Update {
        id: IndividualId,
        new_path: Box<PathChange>,
        predecessors: Vec<Digest<Signed<CgkaOperation>>>,
        doc_id: DocumentId,
    },
}

impl CgkaOperation {
    pub(crate) fn init_add(doc_id: DocumentId, added_id: IndividualId, pk: ShareKey) -> Self {
        Self::Add {
            added_id,
            pk,
            leaf_index: 0,
            predecessors: Vec::new(),
            add_predecessors: Vec::new(),
            doc_id,
        }
    }

    /// The zero or more immediate causal predecessors of this operation.
    pub(crate) fn predecessors(&self) -> HashSet<Digest<Signed<CgkaOperation>>> {
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

    /// Document id
    pub fn doc_id(&self) -> &DocumentId {
        match self {
            CgkaOperation::Add { doc_id, .. } => doc_id,
            CgkaOperation::Remove { doc_id, .. } => doc_id,
            CgkaOperation::Update { doc_id, .. } => doc_id,
        }
    }
}

/// Causal graph of [`CgkaOperation`]s.
#[derive(Debug, Clone, Default, Eq, PartialEq, Serialize, Deserialize, Derivative)]
#[derivative(Hash)]
pub(crate) struct CgkaOperationGraph {
    pub(crate) cgka_ops: CaMap<Signed<CgkaOperation>>,

    #[derivative(Hash(hash_with = "hash_cgka_ops_preds"))]
    pub(crate) cgka_ops_predecessors:
        HashMap<Digest<Signed<CgkaOperation>>, HashSet<Digest<Signed<CgkaOperation>>>>,

    #[derivative(Hash(hash_with = "crate::util::hasher::hash_set"))]
    pub(crate) cgka_op_heads: HashSet<Digest<Signed<CgkaOperation>>>,

    #[derivative(Hash(hash_with = "crate::util::hasher::hash_set"))]
    pub(crate) add_heads: HashSet<Digest<Signed<CgkaOperation>>>,
}

impl Fork for CgkaOperationGraph {
    type Forked = Self;

    fn fork(&self) -> Self::Forked {
        self.clone()
    }
}

impl Merge for CgkaOperationGraph {
    fn merge(&mut self, fork: Self::Forked) {
        self.cgka_ops.merge(fork.cgka_ops);
        self.cgka_ops_predecessors
            .extend(fork.cgka_ops_predecessors);
        self.cgka_op_heads.extend(fork.cgka_op_heads);
        self.add_heads.extend(fork.add_heads); // TODO reduce heads
    }
}

fn hash_cgka_ops_preds<H: Hasher>(
    hmap: &HashMap<Digest<Signed<CgkaOperation>>, HashSet<Digest<Signed<CgkaOperation>>>>,
    state: &mut H,
) {
    hmap.iter()
        .map(|(k, v)| (k, v.iter().collect::<BTreeSet<_>>()))
        .collect::<BTreeMap<_, _>>()
        .hash(state)
}

impl CgkaOperationGraph {
    pub(crate) fn new() -> Self {
        Self {
            cgka_ops: CaMap::new(),
            cgka_ops_predecessors: HashMap::new(),
            cgka_op_heads: HashSet::new(),
            add_heads: HashSet::new(),
        }
    }

    pub(crate) fn contains_op_hash(&self, op_hash: &Digest<Signed<CgkaOperation>>) -> bool {
        self.cgka_ops.contains_key(op_hash)
    }

    pub(crate) fn contains_predecessors(
        &self,
        preds: &HashSet<Digest<Signed<CgkaOperation>>>,
    ) -> bool {
        preds.iter().all(|hash| self.cgka_ops.contains_key(hash))
    }

    /// Whether the causal graph has a single head. More than one head indicates
    /// unresolved merges of concurrent operations.
    pub(crate) fn has_single_head(&self) -> bool {
        self.cgka_op_heads.len() == 1
    }

    /// Add an operation that was created locally to the graph.
    pub(crate) fn add_local_op(&mut self, op: &Signed<CgkaOperation>) {
        self.add_op_and_update_heads(op, None);
    }

    /// Add an operation to the graph.
    pub(crate) fn add_op(
        &mut self,
        op: &Signed<CgkaOperation>,
        heads: &HashSet<Digest<Signed<CgkaOperation>>>,
    ) {
        self.add_op_and_update_heads(op, Some(heads));
    }

    /// Add an operation to the graph, add new heads, and remove any heads that
    /// were replaced by causal successors.
    fn add_op_and_update_heads(
        &mut self,
        op: &Signed<CgkaOperation>,
        external_heads: Option<&HashSet<Digest<Signed<CgkaOperation>>>>,
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
            } = &op.payload
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

    pub(crate) fn heads_contained_in(
        &self,
        heads: &HashSet<Digest<Signed<CgkaOperation>>>,
    ) -> bool {
        self.cgka_op_heads.is_subset(heads)
    }

    fn is_add_op(&self, hash: &Digest<Signed<CgkaOperation>>) -> bool {
        let op = self.cgka_ops.get(hash).expect("op to be in history");
        matches!(&op.payload, &CgkaOperation::Add { .. })
    }

    pub(crate) fn predecessors_for(
        &self,
        op_hash: &Digest<Signed<CgkaOperation>>,
    ) -> Option<&HashSet<Digest<Signed<CgkaOperation>>>> {
        self.cgka_ops_predecessors.get(op_hash)
    }

    /// Topsort all operation in the graph.
    pub(crate) fn topsort_graph(&self) -> Result<NonEmpty<CgkaEpoch>, CgkaError> {
        self.topsort_for_heads(&self.cgka_op_heads)
    }

    /// Topsort all ancestor operations for the provided heads. These are grouped by
    /// "epoch", which in this context means sets of ops that were concurrent. Each
    /// epoch set is then ordered and placed into a distinct [`CgkaEpoch`].
    pub(crate) fn topsort_for_heads(
        &self,
        heads: &HashSet<Digest<Signed<CgkaOperation>>>,
    ) -> Result<NonEmpty<CgkaEpoch>, CgkaError> {
        debug_assert!(heads.iter().all(|head| self.cgka_ops.contains_key(head)));
        let mut op_hashes = Vec::new();
        let mut dependencies = TopologicalSort::<Digest<Signed<CgkaOperation>>>::new();
        let mut successors: HashMap<
            Digest<Signed<CgkaOperation>>,
            HashSet<Digest<Signed<CgkaOperation>>>,
        > = HashMap::new();
        let mut frontier = VecDeque::new();
        let mut seen = HashSet::new();
        for head in heads {
            frontier.push_back(*head);
            seen.insert(head);
            successors.insert(*head, HashSet::new());
        }
        // Populate dependencies and successors with all ancestors of the initial heads.
        while let Some(op_hash) = frontier.pop_front() {
            let preds = self
                .predecessors_for(&op_hash)
                .ok_or(CgkaError::OperationNotFound)?;
            for update_pred in preds {
                dependencies.add_dependency(*update_pred, op_hash);
                successors.entry(*update_pred).or_default().insert(op_hash);
                if seen.contains(update_pred) {
                    continue;
                }
                seen.insert(update_pred);
                frontier.push_back(*update_pred);
            }
        }

        if dependencies.is_empty() {
            let single_epoch = heads
                .iter()
                .map(|hash| {
                    self.cgka_ops
                        .get(hash)
                        .ok_or(CgkaError::OperationNotFound)
                        .expect("head to be present")
                        .clone()
                })
                .collect::<Vec<_>>();
            op_hashes.push(
                NonEmpty::from_vec(single_epoch)
                    .expect("to have at least one op hash")
                    .into(),
            );
            return Ok(NonEmpty::from_vec(op_hashes).expect("to have at least one op hash"));
        }

        // Partition heads into ordered epochs representing ordered sets of
        // concurrent operations.
        let mut epoch_heads = HashSet::new();
        let mut next_epoch: Vec<Arc<Signed<CgkaOperation>>> = Vec::new();
        while !dependencies.is_empty() {
            let mut next_set = dependencies.pop_all();
            next_set.sort();
            for hash in &next_set {
                epoch_heads.insert(*hash);
                if successors.get(hash).expect("hash to be present").is_empty() {
                    // For terminal hashes, we insert the hash itself as its successor.
                    // Terminal hashes will all be included in the final epoch.
                    successors
                        .get_mut(hash)
                        .expect("hash to be present")
                        .insert(*hash);
                }
            }
            for hash in &next_set {
                for h in &epoch_heads {
                    if hash == h {
                        continue;
                    }
                    successors.get_mut(h).expect("head to exist").remove(hash);
                }
            }
            // If all of the successors of a head H have been added as heads, then
            // H can be removed.
            epoch_heads = epoch_heads
                .iter()
                .filter(|h| !successors.get_mut(h).expect("head to exist").is_empty())
                .copied()
                .collect::<HashSet<_>>();
            let should_end_epoch = epoch_heads.len() <= 1;
            if should_end_epoch {
                let mut next = Vec::new();
                mem::swap(&mut next_epoch, &mut next);
                if !next.is_empty() {
                    op_hashes.push(
                        NonEmpty::from_vec(next)
                            .expect("there to be at least one hash")
                            .into(),
                    );
                }
            }
            for hash in next_set {
                next_epoch.push(
                    self.cgka_ops
                        .get(&hash)
                        .ok_or(CgkaError::OperationNotFound)?
                        .clone(),
                );
            }
            if should_end_epoch {
                let mut next = Vec::new();
                mem::swap(&mut next_epoch, &mut next);
                if !next.is_empty() {
                    op_hashes.push(
                        NonEmpty::from_vec(next)
                            .expect("there to be at least one hash")
                            .into(),
                    );
                }
            }
        }

        if !next_epoch.is_empty() {
            // The final epoch consists of all terminal hashes. If there is only one member,
            // it will be added as the last epoch above. If there is more than one member,
            // it will be added here.
            op_hashes.push(
                NonEmpty::from_vec(next_epoch.clone())
                    .expect("there to be at least one hash")
                    .into(),
            );
        }

        Ok(NonEmpty::from_vec(op_hashes).expect("to have at least one op hash"))
    }
}
