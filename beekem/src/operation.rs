//! CGKA operations and their causal graph.

use crate::{
    collections::{Map, Set},
    content_addressed_map::CaMap,
    error::CgkaError,
    id::{MemberId, TreeId},
    transact::{Fork, Merge},
    tree::PathChange,
};
use alloc::{
    collections::{BTreeSet, BinaryHeap},
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

    /// Whether this is an add or a remove.
    pub(crate) fn is_membership_change(&self) -> bool {
        matches!(self, Self::Add { .. } | Self::Remove { .. })
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

    /// Check that `op` can be added to the graph.
    ///
    /// Returns [`CgkaError::InvalidOperation`] if `op` has no
    /// predecessors and is not an add, and [`CgkaError::OutOfOrderOperation`] if
    /// one of its predecessors is not in the graph.
    pub(crate) fn check_can_add(&self, op: &CgkaOperation) -> Result<(), CgkaError> {
        let predecessors = op.predecessors();
        if predecessors.is_empty() && !matches!(op, CgkaOperation::Add { .. }) {
            return Err(CgkaError::InvalidOperation);
        }
        if !self.contains_predecessors(&predecessors) {
            return Err(CgkaError::OutOfOrderOperation);
        }
        Ok(())
    }

    /// Add an operation to the graph.
    ///
    /// Does nothing if the operation is already in the graph. Returns an
    /// error if it cannot be added or a predecessor has no recorded depth.
    pub fn add_op(&mut self, op: &Signed<CgkaOperation>) -> Result<(), CgkaError> {
        let op_hash = Digest::hash(op);
        if self.cgka_ops.contains_key(&op_hash) {
            return Ok(());
        }
        self.check_can_add(&op.payload)?;
        let op_predecessors = op.payload.predecessor_list();
        let mut depth = 0;
        for pred in op_predecessors {
            depth = depth.max(self.depth(pred)? + 1);
        }
        self.cgka_ops.insert(op.clone().into());
        for pred in op_predecessors {
            self.cgka_op_heads.remove(pred);
        }
        self.cgka_op_heads.insert(op_hash);
        self.depths.insert(op_hash, depth);
        Ok(())
    }

    /// Whether a replay would put an operation with `predecessors` in the same
    /// batch as an add or remove. `predecessors` must all be in the graph.
    ///
    /// Returns [`CgkaError::OperationNotFound`] if an operation it reaches is not
    /// in the graph, and [`CgkaError::DepthNotFound`] if one has no recorded depth.
    pub(crate) fn batch_has_membership_change(
        &self,
        predecessors: &Set<Digest<Signed<CgkaOperation>>>,
    ) -> Result<bool, CgkaError> {
        if predecessors.is_empty() {
            // A root must itself be an add.
            return Ok(true);
        }
        if self.heads_contained_in(predecessors) {
            // Every operation in the graph is a head or an ancestor of one. A
            // successor of every head is deeper than all of them and would be
            // in its own batch.
            return Ok(false);
        }
        let mut seen = Set::new();
        let mut frontier = BinaryHeap::new();
        for hash in predecessors.iter().chain(&self.cgka_op_heads) {
            if seen.insert(*hash) {
                frontier.push((self.depth(hash)?, *hash));
            }
        }
        while let Some((_, hash)) = frontier.pop() {
            if frontier.is_empty() {
                break;
            }
            let op = self
                .cgka_ops
                .get(&hash)
                .ok_or(CgkaError::OperationNotFound)?;
            if op.payload.is_membership_change() {
                return Ok(true);
            }
            for pred in op.payload.predecessor_list() {
                if seen.insert(*pred) {
                    frontier.push((self.depth(pred)?, *pred));
                }
            }
        }
        Ok(false)
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
        match self.depths.get(op_hash) {
            Some(depth) => Ok(*depth),
            None if self.cgka_ops.contains_key(op_hash) => Err(CgkaError::DepthNotFound),
            None => Err(CgkaError::OperationNotFound),
        }
    }
}

#[cfg(test)]
mod causal_graph_tests {
    use super::*;
    use alloc::{collections::BTreeMap, vec};
    use keyhive_crypto::{
        share_key::ShareSecretKey,
        signer::{async_signer, memory::MemorySigner},
        verifiable::Verifiable,
    };

    async fn signed_add(
        signer: &MemorySigner,
        doc_id: TreeId,
        leaf_index: u32,
        predecessors: &[&Signed<CgkaOperation>],
    ) -> Signed<CgkaOperation> {
        let op = CgkaOperation::Add {
            added_id: MemberId(MemorySigner::generate(&mut rand::thread_rng()).verifying_key()),
            pk: ShareSecretKey::generate(&mut rand::thread_rng()).share_key(),
            leaf_index,
            predecessors: predecessors.iter().map(|op| Digest::hash(*op)).collect(),
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
        let root = signed_add(&signer, doc_id, 0, &[]).await;
        trunk.add_op(&root).expect("a root has no predecessors");

        let mut forked = trunk.fork();
        let on_fork = signed_add(&signer, doc_id, 1, &[&root]).await;
        let on_fork_hash = Digest::hash(&on_fork);
        forked
            .add_op(&on_fork)
            .expect("the predecessor is in the graph");

        trunk.merge(forked);

        assert!(
            trunk.contains_op_hash(&on_fork_hash),
            "an operation added on the fork is missing after the merge"
        );
        assert_eq!(
            trunk.predecessors_for(&on_fork_hash),
            Some(&[Digest::hash(&root)][..]),
            "the merged operation lost its predecessors"
        );
        assert_eq!(
            trunk.cgka_op_heads,
            Set::from_iter([on_fork_hash]),
            "the merged operation should be the only head"
        );
        trunk
            .add_op(&signed_add(&signer, doc_id, 2, &[&on_fork]).await)
            .expect("the merged operation's depth is in the graph");
    }

    #[tokio::test]
    async fn a_root_nothing_depends_on_shares_the_first_batch() {
        // root  lone_root
        //  |
        // after_root
        let ops: &[(&str, &[&str])] =
            &[("root", &[]), ("after_root", &["root"]), ("lone_root", &[])];
        assert_eq!(
            batches_of(ops).await,
            vec![BTreeSet::from(["root", "after_root", "lone_root"])]
        );
    }

    #[tokio::test]
    async fn graphs_holding_different_operations_hash_differently() {
        let signer = MemorySigner::generate(&mut rand::thread_rng());
        let doc_id = TreeId::from(signer.verifying_key());
        let mut one = CgkaOperationGraph::new();
        let root = signed_add(&signer, doc_id, 0, &[]).await;
        one.add_op(&root).expect("a root has no predecessors");
        let mut two = one.fork();

        assert_eq!(hash_of(&one), hash_of(&two), "equal graphs should agree");

        two.add_op(&signed_add(&signer, doc_id, 1, &[&root]).await)
            .expect("the predecessor is in the graph");

        assert_ne!(
            hash_of(&one),
            hash_of(&two),
            "a graph with an extra operation hashed the same as one without it"
        );
    }

    /// Builds a graph from `(name, predecessors)` pairs listed in causal
    /// order and returns its batches as sets of names.
    async fn batches_of(ops: &[(&'static str, &[&str])]) -> Vec<BTreeSet<&'static str>> {
        let signer = MemorySigner::generate(&mut rand::thread_rng());
        let doc_id = TreeId::from(signer.verifying_key());
        let mut graph = CgkaOperationGraph::new();
        let mut signed = BTreeMap::new();
        for (leaf_index, (name, preds)) in (0..).zip(ops) {
            let preds: Vec<_> = preds.iter().map(|pred| &signed[pred]).collect();
            let op = signed_add(&signer, doc_id, leaf_index, &preds).await;
            graph.add_op(&op).expect("predecessors are listed first");
            signed.insert(*name, op);
        }
        let names: BTreeMap<_, _> = signed
            .into_iter()
            .map(|(name, op)| (Digest::hash(&op), name))
            .collect();
        graph
            .batches()
            .expect("the graph sorts")
            .iter()
            .map(|batch| batch.iter().map(|op| names[&Digest::hash(&**op)]).collect())
            .collect()
    }

    #[tokio::test]
    async fn each_operation_in_a_chain_is_its_own_batch() {
        // a
        // |
        // b
        // |
        // c
        assert_eq!(
            batches_of(&[("a", &[]), ("b", &["a"]), ("c", &["b"])]).await,
            vec![
                BTreeSet::from(["a"]),
                BTreeSet::from(["b"]),
                BTreeSet::from(["c"])
            ]
        );
    }

    #[tokio::test]
    async fn concurrent_branches_share_a_batch_until_they_rejoin() {
        //   a
        //  / \
        // b   c
        //  \ /
        //   d
        let ops: &[(&str, &[&str])] =
            &[("a", &[]), ("b", &["a"]), ("c", &["a"]), ("d", &["b", "c"])];
        assert_eq!(
            batches_of(ops).await,
            vec![
                BTreeSet::from(["a"]),
                BTreeSet::from(["b", "c"]),
                BTreeSet::from(["d"])
            ]
        );
    }

    #[tokio::test]
    async fn a_shorter_concurrent_branch_shares_a_batch_with_the_longer_one() {
        //   a
        //  / \
        // b   |
        // |   e
        // c   |
        //  \ /
        //   d
        let ops: &[(&str, &[&str])] = &[
            ("a", &[]),
            ("b", &["a"]),
            ("e", &["a"]),
            ("c", &["b"]),
            ("d", &["c", "e"]),
        ];
        assert_eq!(
            batches_of(ops).await,
            vec![
                BTreeSet::from(["a"]),
                BTreeSet::from(["b", "e", "c"]),
                BTreeSet::from(["d"])
            ]
        );
    }

    #[tokio::test]
    async fn an_unmerged_branch_keeps_later_operations_in_its_batch() {
        //       root
        //      /    \
        //   update  remove
        //     |
        // later_update
        let ops: &[(&str, &[&str])] = &[
            ("root", &[]),
            ("update", &["root"]),
            ("remove", &["root"]),
            ("later_update", &["update"]),
        ];
        assert_eq!(
            batches_of(ops).await,
            vec![
                BTreeSet::from(["root"]),
                BTreeSet::from(["update", "remove", "later_update"])
            ]
        );
    }

    #[tokio::test]
    async fn adding_an_op_again_leaves_the_graph_unchanged() {
        let signer = MemorySigner::generate(&mut rand::thread_rng());
        let doc_id = TreeId::from(signer.verifying_key());
        let mut graph = CgkaOperationGraph::new();
        let root = signed_add(&signer, doc_id, 0, &[]).await;
        let child = signed_add(&signer, doc_id, 1, &[&root]).await;
        let grandchild = signed_add(&signer, doc_id, 2, &[&child]).await;
        for op in [&root, &child, &grandchild] {
            graph.add_op(op).expect("predecessors are added first");
        }
        let before = graph.clone();

        graph
            .add_op(&child)
            .expect("re-adding an operation succeeds");

        assert_eq!(graph, before, "re-adding an operation changed the graph");
    }

    #[tokio::test]
    async fn adding_an_op_before_its_predecessor_leaves_the_graph_unchanged() {
        let signer = MemorySigner::generate(&mut rand::thread_rng());
        let doc_id = TreeId::from(signer.verifying_key());
        let mut graph = CgkaOperationGraph::new();
        let root = signed_add(&signer, doc_id, 0, &[]).await;
        graph.add_op(&root).expect("a root has no predecessors");
        let unknown = signed_add(&signer, doc_id, 1, &[]).await;
        let before = graph.clone();

        let result = graph.add_op(&signed_add(&signer, doc_id, 2, &[&root, &unknown]).await);

        assert!(
            matches!(result, Err(CgkaError::OutOfOrderOperation)),
            "an operation with a predecessor missing from the graph was accepted"
        );
        assert!(
            result.is_err_and(|e| e.is_missing_dependency()),
            "an operation whose predecessor may still arrive would not be retried"
        );
        assert_eq!(graph, before, "a rejected operation changed the graph");
    }

    async fn signed_update(
        signer: &MemorySigner,
        doc_id: TreeId,
        predecessors: &[&Signed<CgkaOperation>],
    ) -> Signed<CgkaOperation> {
        let new_path =
            arbitrary::Arbitrary::arbitrary(&mut arbitrary::Unstructured::new(&[0; 4096]))
                .expect("4096 bytes are enough for a path");
        let op = CgkaOperation::Update {
            id: MemberId(signer.verifying_key()),
            new_path,
            predecessors: predecessors.iter().map(|op| Digest::hash(*op)).collect(),
            doc_id,
        };
        async_signer::try_sign_async::<future_form::Local, _, _>(signer, op)
            .await
            .expect("signing succeeds")
    }

    #[tokio::test]
    async fn an_operation_with_no_predecessors_shares_a_batch_with_the_first_add() {
        let signer = MemorySigner::generate(&mut rand::thread_rng());
        let doc_id = TreeId::from(signer.verifying_key());
        let mut graph = CgkaOperationGraph::new();
        graph
            .add_op(&signed_add(&signer, doc_id, 0, &[]).await)
            .expect("a root has no predecessors");

        assert!(
            graph
                .batch_has_membership_change(&Set::new())
                .expect("a valid graph"),
            "a second root was not put in the batch of the first add"
        );
    }

    #[tokio::test]
    async fn a_second_root_puts_later_operations_in_its_batch() {
        // first_add
        //    |       second_add
        //  update
        let signer = MemorySigner::generate(&mut rand::thread_rng());
        let doc_id = TreeId::from(signer.verifying_key());
        let mut graph = CgkaOperationGraph::new();
        let first_add = signed_add(&signer, doc_id, 0, &[]).await;
        let update = signed_update(&signer, doc_id, &[&first_add]).await;
        let second_add = signed_add(&signer, doc_id, 1, &[]).await;
        for op in [&first_add, &update, &second_add] {
            graph.add_op(op).expect("predecessors are added first");
        }

        assert!(
            graph
                .batch_has_membership_change(&Set::from_iter([Digest::hash(&update)]))
                .expect("a valid graph"),
            "an operation after the update was not put in a batch with the second root"
        );
    }

    #[tokio::test]
    async fn a_missing_depth_is_an_error() {
        //       root
        //      /    \
        // update  other_update
        let signer = MemorySigner::generate(&mut rand::thread_rng());
        let doc_id = TreeId::from(signer.verifying_key());
        let mut graph = CgkaOperationGraph::new();
        let root = signed_add(&signer, doc_id, 0, &[]).await;
        let update = signed_update(&signer, doc_id, &[&root]).await;
        let other_signer = MemorySigner::generate(&mut rand::thread_rng());
        let other_update = signed_update(&other_signer, doc_id, &[&root]).await;
        for op in [&root, &update, &other_update] {
            graph.add_op(op).expect("predecessors are added first");
        }

        graph.depths.clear();
        assert!(
            matches!(
                graph.batch_has_membership_change(&Set::from_iter([Digest::hash(&update)])),
                Err(CgkaError::DepthNotFound)
            ),
            "a graph missing a depth was not reported"
        );
    }

    #[tokio::test]
    async fn a_head_missing_from_the_graph_is_an_error() {
        let signer = MemorySigner::generate(&mut rand::thread_rng());
        let doc_id = TreeId::from(signer.verifying_key());
        let graph = CgkaOperationGraph::new();
        let unknown = signed_add(&signer, doc_id, 0, &[]).await;

        assert!(
            matches!(
                graph.batches_for_heads(&Set::from_iter([Digest::hash(&unknown)])),
                Err(CgkaError::OperationNotFound)
            ),
            "a head missing from the graph was not reported as missing"
        );
    }

    #[tokio::test]
    async fn an_operation_after_every_head_starts_a_new_batch() {
        // first_root  second_root
        let signer = MemorySigner::generate(&mut rand::thread_rng());
        let doc_id = TreeId::from(signer.verifying_key());
        let mut graph = CgkaOperationGraph::new();
        let first_root = signed_add(&signer, doc_id, 0, &[]).await;
        let second_root = signed_add(&signer, doc_id, 1, &[]).await;
        for op in [&first_root, &second_root] {
            graph.add_op(op).expect("a root has no predecessors");
        }

        assert!(
            !graph
                .batch_has_membership_change(&graph.cgka_op_heads)
                .expect("a valid graph"),
            "an operation after every head was put in a batch with an add"
        );
    }

    #[tokio::test]
    async fn adding_a_root_that_is_not_an_add_leaves_the_graph_unchanged() {
        let signer = MemorySigner::generate(&mut rand::thread_rng());
        let doc_id = TreeId::from(signer.verifying_key());
        let mut graph = CgkaOperationGraph::new();
        graph
            .add_op(&signed_add(&signer, doc_id, 0, &[]).await)
            .expect("a root add is accepted");
        let before = graph.clone();

        let result = graph.add_op(&signed_update(&signer, doc_id, &[]).await);

        assert!(
            matches!(result, Err(CgkaError::InvalidOperation)),
            "a root that is not an add was accepted"
        );
        assert!(
            result.is_err_and(|e| !e.is_missing_dependency()),
            "a root that is not an add would be retried"
        );
        assert_eq!(graph, before, "a rejected operation changed the graph");
    }
}
