//! CGKA operations and their causal graph.

use crate::{
    collections::{Map, Set},
    content_addressed_map::CaMap,
    error::CgkaError,
    id::{MemberId, TreeId},
    transact::{Fork, Merge},
    tree::PathChange,
};
use alloc::{collections::BTreeSet, sync::Arc, vec::Vec};
use core::{
    hash::{Hash, Hasher},
    mem,
    ops::Deref,
};
use keyhive_crypto::{digest::Digest, share_key::ShareKey, signed::Signed};
use nonempty::NonEmpty;
use serde::{Deserialize, Serialize};

/// The membership operation authorizing a [`CgkaOperation`].
#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq, Deserialize, Serialize)]
#[cfg_attr(any(test, feature = "arbitrary"), derive(arbitrary::Arbitrary))]
pub enum CgkaAuthorization {
    /// The digest of the delegation that generated an add.
    Delegation([u8; 32]),

    /// The digest of the revocation that generated a remove.
    Revocation([u8; 32]),
}

/// An ordered [`NonEmpty`] of [`CgkaOperation`]s that a replay applies
/// together.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CgkaBatch(NonEmpty<Arc<Signed<CgkaOperation>>>);

impl From<NonEmpty<Arc<Signed<CgkaOperation>>>> for CgkaBatch {
    fn from(item: NonEmpty<Arc<Signed<CgkaOperation>>>) -> Self {
        CgkaBatch(item)
    }
}

impl Deref for CgkaBatch {
    type Target = NonEmpty<Arc<Signed<CgkaOperation>>>;

    fn deref(&self) -> &NonEmpty<Arc<Signed<CgkaOperation>>> {
        &self.0
    }
}

impl IntoIterator for CgkaBatch {
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
        authorization: CgkaAuthorization,
    },
    Remove {
        id: MemberId,
        leaf_idx: u32,
        removed_keys: Vec<ShareKey>,
        predecessors: Vec<Digest<Signed<CgkaOperation>>>,
        doc_id: TreeId,
        authorization: CgkaAuthorization,
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
        Set::from_iter(self.predecessor_list().iter().copied())
    }

    fn predecessor_list(&self) -> &[Digest<Signed<CgkaOperation>>] {
        match self {
            CgkaOperation::Add { predecessors, .. }
            | CgkaOperation::Remove { predecessors, .. }
            | CgkaOperation::Update { predecessors, .. } => predecessors,
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

    pub cgka_op_heads: Set<Digest<Signed<CgkaOperation>>>,

    /// The length of the longest chain of predecessors before each operation.
    /// An operation with no predecessors has depth 0.
    depths: Map<Digest<Signed<CgkaOperation>>, u64>,
}

impl Hash for CgkaOperationGraph {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.cgka_ops.hash(state);

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
        self.cgka_op_heads.extend(fork.cgka_op_heads);
        let ops = &self.cgka_ops;
        self.cgka_op_heads.retain(|head| {
            !ops.values()
                .any(|op| op.payload.predecessor_list().contains(head))
        });
        self.depths.extend(fork.depths);
    }
}

impl CgkaOperationGraph {
    pub fn new() -> Self {
        Self {
            cgka_ops: CaMap::new(),
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

    /// Add an operation to the graph.
    ///
    /// Does nothing if the operation is already in the graph. Returns
    /// [`CgkaError::OutOfOrderOperation`] and leaves the graph unchanged if one
    /// of its predecessors is not in the graph.
    pub fn add_op(&mut self, op: &Signed<CgkaOperation>) -> Result<(), CgkaError> {
        let op_hash = Digest::hash(op);
        if self.cgka_ops.contains_key(&op_hash) {
            return Ok(());
        }
        let op_predecessors = op.payload.predecessor_list();
        let mut depth = 0;
        for pred in op_predecessors {
            let pred_depth = self
                .depths
                .get(pred)
                .ok_or(CgkaError::OutOfOrderOperation)?;
            depth = depth.max(pred_depth + 1);
        }
        self.cgka_ops.insert(op.clone().into());
        for pred in op_predecessors {
            self.cgka_op_heads.remove(pred);
        }
        self.cgka_op_heads.insert(op_hash);
        self.depths.insert(op_hash, depth);
        Ok(())
    }

    pub fn heads_contained_in(&self, heads: &Set<Digest<Signed<CgkaOperation>>>) -> bool {
        self.cgka_op_heads.iter().all(|h| heads.contains(h))
    }

    pub fn predecessors_for(
        &self,
        op_hash: &Digest<Signed<CgkaOperation>>,
    ) -> Option<&[Digest<Signed<CgkaOperation>>]> {
        self.cgka_ops
            .get(op_hash)
            .map(|op| op.payload.predecessor_list())
    }

    /// Sort all operations in the graph into batches.
    pub fn batches(&self) -> Result<NonEmpty<CgkaBatch>, CgkaError> {
        self.batches_for_heads(&self.cgka_op_heads)
    }

    /// Sort `heads` and all their ancestors into batches.
    ///
    /// Operations are ordered by depth (and by digest if depth is equal). This
    /// is a causal order since an operation is always deeper than each of its
    /// predecessors.
    ///
    /// A batch is formed in two cases:
    /// 1. Boundary (singleton) batch: a single operation `x` is the only operation at
    ///    its depth, every shallower operation is its ancestor, and none of those
    ///    ancestors has a descendant deeper than `x` through a chain that excludes `x`.
    /// 2. Concurrency batch: all operations between consecutive boundary batches, before
    ///    the first, or after the last (or all operations, if there is no boundary batch).
    ///
    /// A batch contains every operation concurrent with any operation in it (though
    /// two operations in one batch may be causally ordered).
    ///
    /// Returns [`CgkaError::OperationNotFound`] if one of `heads` or their
    /// ancestors is not in the graph. Returns [`CgkaError::NotInitialized`]
    /// if `heads` is empty.
    pub fn batches_for_heads(
        &self,
        heads: &Set<Digest<Signed<CgkaOperation>>>,
    ) -> Result<NonEmpty<CgkaBatch>, CgkaError> {
        let mut deepest_child: Map<Digest<Signed<CgkaOperation>>, u64> = Map::new();
        let mut seen = heads.clone();
        let mut frontier = Vec::from_iter(heads.iter().copied());
        let mut ordered = Vec::with_capacity(heads.len());
        // Traverse back from heads, recording each operation's depth and the depth
        // of its deepest child.
        while let Some(op_hash) = frontier.pop() {
            let depth = self.depth(&op_hash)?;
            ordered.push((depth, op_hash));
            let preds = self
                .predecessors_for(&op_hash)
                .ok_or(CgkaError::OperationNotFound)?;
            for pred in preds {
                let deepest = deepest_child.entry(*pred).or_insert(depth);
                *deepest = (*deepest).max(depth);
                if seen.insert(*pred) {
                    frontier.push(*pred);
                }
            }
        }
        ordered.sort_unstable();

        let mut batches: Vec<CgkaBatch> = Vec::new();
        let mut batch = Vec::new();
        // The shallowest depth at which the next boundary batch could occur. This is the
        // greatest depth of any child of an operation in a shallower layer.
        let mut earliest_next_boundary = 0;
        // A layer is all the operations at one depth. They are concurrent with each
        // other since an operation is deeper than each of its ancestors.
        for layer in ordered.chunk_by(|a, b| a.0 == b.0) {
            let depth = layer[0].0;
            // A chain of operations that starts no deeper than a putative boundary operation
            // `x`, doesn't include `x`, and can't be extended further either
            //   1. ends at a shallower depth than `x` (its last operation is a head, which we
            //      treat as having a child of depth `u64::MAX`),
            //   2. includes an operation at the same depth as `x`, or
            //   3. contains an operation whose child skips past `x`.
            // In any of these cases, `x` is not a boundary operation. In case 2,
            // `layer.len() > 1`. In cases 1 and 3, `earliest_next_boundary > depth`.
            let is_boundary = layer.len() == 1 && earliest_next_boundary <= depth;
            if is_boundary {
                batches.extend(NonEmpty::from_vec(mem::take(&mut batch)).map(Into::into));
            }
            for (_, op_hash) in layer {
                batch.push(
                    self.cgka_ops
                        .get(op_hash)
                        .ok_or(CgkaError::OperationNotFound)?
                        .clone(),
                );
                let deepest = match deepest_child.get(op_hash) {
                    Some(depth) => *depth,
                    // This must be a head (it has no children among the sorted operations),
                    // which means every deeper operation is concurrent with it and can't be
                    // a boundary.
                    None => u64::MAX,
                };
                earliest_next_boundary = earliest_next_boundary.max(deepest);
            }
            if is_boundary {
                batches.extend(NonEmpty::from_vec(mem::take(&mut batch)).map(Into::into));
            }
        }
        batches.extend(NonEmpty::from_vec(batch).map(Into::into));

        NonEmpty::from_vec(batches).ok_or(CgkaError::NotInitialized)
    }

    fn depth(&self, op_hash: &Digest<Signed<CgkaOperation>>) -> Result<u64, CgkaError> {
        self.depths
            .get(op_hash)
            .copied()
            .ok_or(CgkaError::OperationNotFound)
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
            authorization: CgkaAuthorization::Delegation([0; 32]),
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
        assert_eq!(
            trunk.cgka_op_heads,
            Set::from_iter([on_fork_hash]),
            "the merged operation should be the only head"
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
