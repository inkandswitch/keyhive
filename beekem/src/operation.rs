//! CGKA operations and their causal graph.

use crate::{
    collections::{Map, Set},
    content_addressed_map::CaMap,
    error::CgkaError,
    id::{MemberId, TreeId},
    topsort::TopologicalSort,
    transact::{Fork, Merge},
    tree::PathChange,
};
use alloc::{
    collections::{BTreeMap, BTreeSet, BinaryHeap},
    sync::Arc,
    vec::Vec,
};
use core::{
    hash::{Hash, Hasher},
    mem,
    ops::Deref,
};
use keyhive_crypto::{digest::Digest, share_key::ShareKey, signed::Signed};
use nonempty::NonEmpty;
use serde::{Deserialize, Serialize};

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
        added_id: MemberId,
        pk: ShareKey,
        leaf_index: u32,
        predecessors: Vec<Digest<Signed<CgkaOperation>>>,
        doc_id: TreeId,
    },
    Remove {
        id: MemberId,
        leaf_idx: u32,
        removed_keys: Vec<ShareKey>,
        predecessors: Vec<Digest<Signed<CgkaOperation>>>,
        doc_id: TreeId,
    },
    Update {
        id: MemberId,
        new_path: alloc::boxed::Box<PathChange>,
        predecessors: Vec<Digest<Signed<CgkaOperation>>>,
        doc_id: TreeId,
    },
}

impl CgkaOperation {
    /// The zero or more immediate causal predecessors of this operation.
    pub fn predecessors(&self) -> Set<Digest<Signed<CgkaOperation>>> {
        match self {
            CgkaOperation::Add { predecessors, .. } => Set::from_iter(predecessors.iter().cloned()),
            CgkaOperation::Remove { predecessors, .. } => {
                Set::from_iter(predecessors.iter().cloned())
            }
            CgkaOperation::Update { predecessors, .. } => {
                Set::from_iter(predecessors.iter().cloned())
            }
        }
    }

    /// Document/tree id.
    pub fn doc_id(&self) -> &TreeId {
        match self {
            CgkaOperation::Add { doc_id, .. } => doc_id,
            CgkaOperation::Remove { doc_id, .. } => doc_id,
            CgkaOperation::Update { doc_id, .. } => doc_id,
        }
    }
}

/// Causal graph of [`CgkaOperation`]s.
///
/// Manual `Hash` impl replaces `derivative`, sorting collection keys
/// for deterministic hashing.
#[derive(Debug, Clone, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct CgkaOperationGraph {
    pub cgka_ops: CaMap<Signed<CgkaOperation>>,

    pub cgka_ops_predecessors:
        Map<Digest<Signed<CgkaOperation>>, Set<Digest<Signed<CgkaOperation>>>>,

    pub cgka_op_heads: Set<Digest<Signed<CgkaOperation>>>,

    /// The length of the longest causal chain from the initial operation to each
    /// operation.
    depths: Map<Digest<Signed<CgkaOperation>>, u64>,
}

impl Hash for CgkaOperationGraph {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.cgka_ops.hash(state);

        // Hash predecessors deterministically
        self.cgka_ops_predecessors
            .iter()
            .map(|(k, v)| (k, v.iter().collect::<BTreeSet<_>>()))
            .collect::<BTreeMap<_, _>>()
            .hash(state);

        // Hash heads deterministically
        self.cgka_op_heads
            .iter()
            .collect::<BTreeSet<_>>()
            .hash(state);
    }
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
        self.depths.extend(fork.depths);
    }
}

impl CgkaOperationGraph {
    pub fn new() -> Self {
        Self {
            cgka_ops: CaMap::new(),
            cgka_ops_predecessors: Map::new(),
            cgka_op_heads: Set::new(),
            depths: Map::new(),
        }
    }

    pub fn contains_op_hash(&self, op_hash: &Digest<Signed<CgkaOperation>>) -> bool {
        self.cgka_ops.contains_key(op_hash)
    }

    pub fn contains_predecessors(&self, preds: &Set<Digest<Signed<CgkaOperation>>>) -> bool {
        preds.iter().all(|hash| self.cgka_ops.contains_key(hash))
    }

    /// Whether the causal graph has a single head.
    pub fn has_single_head(&self) -> bool {
        self.cgka_op_heads.len() == 1
    }

    /// Add an operation that was created locally to the graph.
    pub fn add_local_op(&mut self, op: &Signed<CgkaOperation>) {
        self.add_op_and_update_heads(op, None);
    }

    /// Add an operation to the graph.
    pub fn add_op(
        &mut self,
        op: &Signed<CgkaOperation>,
        heads: &Set<Digest<Signed<CgkaOperation>>>,
    ) {
        self.add_op_and_update_heads(op, Some(heads));
    }

    fn add_op_and_update_heads(
        &mut self,
        op: &Signed<CgkaOperation>,
        external_heads: Option<&Set<Digest<Signed<CgkaOperation>>>>,
    ) {
        let op_hash = Digest::hash(op);
        let mut op_predecessors = Set::new();
        self.cgka_ops.insert(op.clone().into());
        if let Some(heads) = external_heads {
            for h in heads {
                op_predecessors.insert(*h);
                self.cgka_op_heads.remove(h);
            }
        } else {
            for h in self.cgka_op_heads.iter() {
                op_predecessors.insert(*h);
            }
            self.cgka_op_heads.clear();
        };
        self.cgka_op_heads.insert(op_hash);
        let depth = op_predecessors
            .iter()
            .filter_map(|p| self.depths.get(p))
            .max()
            .map_or(0, |d| d + 1);
        self.depths.insert(op_hash, depth);
        self.cgka_ops_predecessors.insert(op_hash, op_predecessors);
    }

    /// Whether a replay would put an operation with these `predecessors` in the
    /// same epoch as an add or remove.
    ///
    /// An epoch begins at the nearest operation that every other operation
    /// either happened-before or happened-after. This traverses back from the heads
    /// and from `predecessors` in order of decreasing depth until it finds one such
    /// operation.
    pub fn epoch_has_membership_change(
        &self,
        predecessors: &Set<Digest<Signed<CgkaOperation>>>,
    ) -> bool {
        let mut seen = Set::new();
        let mut queue = BinaryHeap::new();
        for hash in predecessors.iter().chain(self.cgka_op_heads.iter()) {
            if seen.insert(*hash) {
                queue.push((self.depths.get(hash).copied().unwrap_or(0), *hash));
            }
        }
        while queue.len() > 1 {
            let Some((_, hash)) = queue.pop() else { break };
            let is_membership_change = self.cgka_ops.get(&hash).is_some_and(|op| {
                matches!(
                    op.payload,
                    CgkaOperation::Add { .. } | CgkaOperation::Remove { .. }
                )
            });
            if is_membership_change {
                return true;
            }
            for pred in self.predecessors_for(&hash).into_iter().flatten() {
                if seen.insert(*pred) {
                    queue.push((self.depths.get(pred).copied().unwrap_or(0), *pred));
                }
            }
        }
        false
    }

    pub fn heads_contained_in(&self, heads: &Set<Digest<Signed<CgkaOperation>>>) -> bool {
        self.cgka_op_heads.iter().all(|h| heads.contains(h))
    }

    pub fn predecessors_for(
        &self,
        op_hash: &Digest<Signed<CgkaOperation>>,
    ) -> Option<&Set<Digest<Signed<CgkaOperation>>>> {
        self.cgka_ops_predecessors.get(op_hash)
    }

    /// Topsort all operations in the graph.
    pub fn topsort_graph(&self) -> Result<NonEmpty<CgkaEpoch>, CgkaError> {
        self.topsort_for_heads(&self.cgka_op_heads)
    }

    /// Topsort all ancestor operations for the provided heads.
    pub fn topsort_for_heads(
        &self,
        heads: &Set<Digest<Signed<CgkaOperation>>>,
    ) -> Result<NonEmpty<CgkaEpoch>, CgkaError> {
        debug_assert!(heads.iter().all(|head| self.cgka_ops.contains_key(head)));
        let mut op_hashes = Vec::new();
        let mut dependencies = TopologicalSort::<Digest<Signed<CgkaOperation>>>::new();
        let mut successors: Map<Digest<Signed<CgkaOperation>>, Set<Digest<Signed<CgkaOperation>>>> =
            Map::new();
        let mut frontier = alloc::collections::VecDeque::new();
        let mut seen = Set::new();
        for head in heads {
            // A head with no predecessors has no dependency edges. It must
            // be added on its own or the sort would leave it out.
            dependencies.insert(*head);
            frontier.push_back(*head);
            seen.insert(*head);
            successors.insert(*head, Set::new());
        }
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
                seen.insert(*update_pred);
                frontier.push_back(*update_pred);
            }
        }

        let mut epoch_heads = Set::new();
        let mut next_epoch: Vec<Arc<Signed<CgkaOperation>>> = Vec::new();
        while !dependencies.is_empty() {
            let mut next_set = dependencies.pop_all();
            next_set.sort();
            for hash in &next_set {
                epoch_heads.insert(*hash);
                if successors.get(hash).expect("hash to be present").is_empty() {
                    successors
                        .get_mut(hash)
                        .expect("hash to be present")
                        .insert(*hash);
                }
            }
            for hash in &next_set {
                for h in epoch_heads.iter().cloned().collect::<Vec<_>>() {
                    if *hash == h {
                        continue;
                    }
                    successors.get_mut(&h).expect("head to exist").remove(hash);
                }
            }
            epoch_heads = epoch_heads
                .iter()
                .filter(|h| !successors.get_mut(h).expect("head to exist").is_empty())
                .copied()
                .collect::<Set<_>>();
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
            op_hashes.push(
                NonEmpty::from_vec(next_epoch.clone())
                    .expect("there to be at least one hash")
                    .into(),
            );
        }

        Ok(NonEmpty::from_vec(op_hashes).expect("to have at least one op hash"))
    }
}

#[cfg(test)]
mod causal_graph_tests {
    use super::*;
    use keyhive_crypto::{
        share_key::ShareSecretKey,
        signer::{async_signer, memory::MemorySigner},
        verifiable::Verifiable,
    };

    async fn add_op(
        signer: &MemorySigner,
        doc_id: TreeId,
        leaf_index: u32,
    ) -> Signed<CgkaOperation> {
        let op = CgkaOperation::Add {
            added_id: MemberId(MemorySigner::generate(&mut rand::thread_rng()).verifying_key()),
            pk: ShareSecretKey::generate(&mut rand::thread_rng()).share_key(),
            leaf_index,
            predecessors: Vec::new(),
            doc_id,
        };
        async_signer::try_sign_async::<future_form::Local, _, _>(signer, op)
            .await
            .expect("signing succeeds")
    }

    fn hash_of(graph: &CgkaOperationGraph) -> u64 {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        graph.hash(&mut hasher);
        hasher.finish()
    }

    #[tokio::test]
    async fn merging_a_fork_keeps_the_operations_it_added() {
        let signer = MemorySigner::generate(&mut rand::thread_rng());
        let doc_id = TreeId::from(signer.verifying_key());
        let mut trunk = CgkaOperationGraph::new();
        let root = add_op(&signer, doc_id, 0).await;
        trunk.add_local_op(&root);

        let mut forked = trunk.fork();
        let on_fork = add_op(&signer, doc_id, 1).await;
        let on_fork_hash = Digest::hash(&on_fork);
        forked.add_op(&on_fork, &Set::from_iter([Digest::hash(&root)]));

        trunk.merge(forked);

        assert!(
            trunk.contains_op_hash(&on_fork_hash),
            "an operation added on the fork is missing after the merge"
        );
        assert_eq!(
            trunk.predecessors_for(&on_fork_hash),
            Some(&Set::from_iter([Digest::hash(&root)])),
            "the merged operation lost its predecessors"
        );
        assert!(
            trunk.cgka_op_heads.contains(&on_fork_hash),
            "the merged operation is not a head"
        );
    }

    #[tokio::test]
    async fn topsort_keeps_a_root_that_nothing_depends_on_yet() {
        // Two concurrent roots. One already has a successor. The other is still
        // a head on its own with no dependency edges.
        let signer = MemorySigner::generate(&mut rand::thread_rng());
        let doc_id = TreeId::from(signer.verifying_key());
        let mut graph = CgkaOperationGraph::new();
        let root = add_op(&signer, doc_id, 0).await;
        graph.add_local_op(&root);
        let after_root = add_op(&signer, doc_id, 1).await;
        graph.add_op(&after_root, &Set::from_iter([Digest::hash(&root)]));
        let lone_root = add_op(&signer, doc_id, 0).await;
        graph.add_op(&lone_root, &Set::new());

        let sorted: Set<_> = graph
            .topsort_graph()
            .expect("the graph sorts")
            .iter()
            .flat_map(|epoch| epoch.iter().map(|op| Digest::hash(&**op)))
            .collect();

        assert_eq!(
            sorted,
            Set::from_iter([
                Digest::hash(&root),
                Digest::hash(&after_root),
                Digest::hash(&lone_root)
            ]),
            "every operation in the graph should be in its topsort"
        );
    }

    #[tokio::test]
    async fn graphs_holding_different_operations_hash_differently() {
        let signer = MemorySigner::generate(&mut rand::thread_rng());
        let doc_id = TreeId::from(signer.verifying_key());
        let mut one = CgkaOperationGraph::new();
        let root = add_op(&signer, doc_id, 0).await;
        one.add_local_op(&root);
        let mut two = one.fork();

        assert_eq!(hash_of(&one), hash_of(&two), "equal graphs should agree");

        two.add_op(
            &add_op(&signer, doc_id, 1).await,
            &Set::from_iter([Digest::hash(&root)]),
        );

        assert_ne!(
            hash_of(&one),
            hash_of(&two),
            "a graph with an extra operation hashed the same as one without it"
        );
    }
}
