//! CGKA operations and their causal graph.

use crate::{
    collections::{Map, Set},
    content_addressed_map::CaMap,
    encrypted::EncryptedSecret,
    error::CgkaError,
    id::{MemberId, TreeId},
    pcs_key::PcsKey,
    topsort::TopologicalSort,
    transact::{Fork, Merge},
    tree::PathChange,
};
use alloc::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
    vec::Vec,
};
use core::{
    hash::{Hash, Hasher},
    mem,
    ops::Deref,
};
use keyhive_crypto::{
    digest::Digest,
    share_key::{ShareKey, ShareSecretKey},
    signed::Signed,
};
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

/// When a member is initially added, it has no access to the root secret until
/// the next PCS update. An invitation gives them a way to decrypt content
/// immediately by wrapping the latest key used for encrypting content and enough
/// information to associate that key with that content.
#[derive(Debug, Clone, Hash, Eq, PartialEq, Deserialize, Serialize)]
#[cfg_attr(any(test, feature = "arbitrary"), derive(arbitrary::Arbitrary))]
pub struct Invitation {
    /// The invited member.
    pub invitee_id: MemberId,

    /// The prekey the invited member was added under.
    pub invitee_pk: ShareKey,

    /// The root secret, encrypted to [`Self::invitee_pk`].
    pub root_secret: EncryptedSecret<ShareSecretKey>,

    /// The inviter's share key corresponding to the secret key it used
    /// to encrypt [`Self::root_secret`] via Diffie-Hellman.
    pub inviter_pk: ShareKey,

    /// Which root secret this is. Used to identify encrypted content associated
    /// with that secret.
    pub pcs_key_hash: Digest<PcsKey>,

    /// The update operation that originally produced the root secret. Used to derive
    /// an application secret from the root secret for decrypting content associated
    /// with that secret.
    pub pcs_update_op_hash: Digest<Signed<CgkaOperation>>,
}

#[derive(Debug, Clone, Hash, Eq, PartialEq, Deserialize, Serialize)]
#[cfg_attr(any(test, feature = "arbitrary"), derive(arbitrary::Arbitrary))]
pub enum CgkaOperation {
    Add {
        added_id: MemberId,
        pk: ShareKey,
        leaf_index: u32,
        predecessors: Vec<Digest<Signed<CgkaOperation>>>,
        add_predecessors: Vec<Digest<Signed<CgkaOperation>>>,
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
    /// Wraps an [`Invitation`] for a new member, allowing them to read content
    /// before the next PCS update. The only [`CgkaOperation`] that does not
    /// modify the tree.
    Invite {
        invitation: alloc::boxed::Box<Invitation>,
        predecessors: Vec<Digest<Signed<CgkaOperation>>>,
        doc_id: TreeId,
    },
}

impl CgkaOperation {
    pub fn init_add(doc_id: TreeId, added_id: MemberId, pk: ShareKey) -> Self {
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
    pub fn predecessors(&self) -> Set<Digest<Signed<CgkaOperation>>> {
        match self {
            CgkaOperation::Add { predecessors, .. }
            | CgkaOperation::Remove { predecessors, .. }
            | CgkaOperation::Update { predecessors, .. }
            | CgkaOperation::Invite { predecessors, .. } => {
                Set::from_iter(predecessors.iter().cloned())
            }
        }
    }

    /// Document/tree id.
    pub fn doc_id(&self) -> &TreeId {
        match self {
            CgkaOperation::Add { doc_id, .. }
            | CgkaOperation::Remove { doc_id, .. }
            | CgkaOperation::Update { doc_id, .. }
            | CgkaOperation::Invite { doc_id, .. } => doc_id,
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

    pub add_heads: Set<Digest<Signed<CgkaOperation>>>,

    /// A Lamport timestamp for each op. An op will always have a larger timestamp
    /// than its ancestors.
    cgka_op_lamport_timestamps: Map<Digest<Signed<CgkaOperation>>, u32>,
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

        self.add_heads.iter().collect::<BTreeSet<_>>().hash(state);

        self.cgka_op_lamport_timestamps
            .iter()
            .collect::<BTreeMap<_, _>>()
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
        self.add_heads.extend(fork.add_heads);
        self.cgka_op_lamport_timestamps
            .extend(fork.cgka_op_lamport_timestamps);
    }
}

impl CgkaOperationGraph {
    pub fn new() -> Self {
        Self {
            cgka_ops: CaMap::new(),
            cgka_ops_predecessors: Map::new(),
            cgka_op_heads: Set::new(),
            add_heads: Set::new(),
            cgka_op_lamport_timestamps: Map::new(),
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
            for h in self.cgka_op_heads.iter() {
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
        // Causal delivery should guarantee ops are ordered correctly
        debug_assert!(
            op_predecessors
                .iter()
                .all(|p| self.cgka_op_lamport_timestamps.contains_key(p)),
            "predecessors should be in the graph before a descendent op"
        );
        // The Lamport timestamp is the greatest timestamp of the immediate causal
        // predecessors plus 1.
        let lamport = op_predecessors
            .iter()
            .filter_map(|p| self.cgka_op_lamport_timestamps.get(p).copied())
            .max()
            .map_or(0, |latest| latest.saturating_add(1));
        self.cgka_op_lamport_timestamps.insert(op_hash, lamport);
        self.cgka_ops_predecessors.insert(op_hash, op_predecessors);
    }

    pub fn lamport_ts_for(&self, op_hash: &Digest<Signed<CgkaOperation>>) -> Option<u32> {
        self.cgka_op_lamport_timestamps.get(op_hash).copied()
    }

    pub fn heads_contained_in(&self, heads: &Set<Digest<Signed<CgkaOperation>>>) -> bool {
        self.cgka_op_heads.iter().all(|h| heads.contains(h))
    }

    fn is_add_op(&self, hash: &Digest<Signed<CgkaOperation>>) -> bool {
        let op = self.cgka_ops.get(hash).expect("op to be in history");
        matches!(&op.payload, &CgkaOperation::Add { .. })
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
mod lamport_timestamp_tests {
    use super::*;
    use crate::id::TreeId;
    use keyhive_crypto::{
        share_key::ShareSecretKey,
        signer::{async_signer, memory::MemorySigner},
        verifiable::Verifiable,
    };

    async fn sign(signer: &MemorySigner, op: CgkaOperation) -> Signed<CgkaOperation> {
        async_signer::try_sign_async::<future_form::Local, _, _>(signer, op)
            .await
            .unwrap()
    }

    /// A distinct operation each time.
    fn add_op(doc_id: TreeId, leaf_index: u32) -> CgkaOperation {
        CgkaOperation::Add {
            added_id: MemberId::public(),
            pk: ShareSecretKey::generate(&mut rand::thread_rng()).share_key(),
            leaf_index,
            predecessors: Vec::new(),
            add_predecessors: Vec::new(),
            doc_id,
        }
    }

    #[tokio::test]
    async fn lamport_ts_is_written_once_and_never_revised() {
        let signer = MemorySigner::generate(&mut rand::thread_rng());
        let doc_id = TreeId::from(signer.verifying_key());
        let mut graph = CgkaOperationGraph::new();

        // The first operation's ts is 0 because it has no predecessors.
        let root = sign(&signer, add_op(doc_id, 0)).await;
        let root_hash = Digest::hash(&root);
        graph.add_local_op(&root);
        assert_eq!(graph.lamport_ts_for(&root_hash), Some(0));

        // Ten descendants, each following the last.
        let mut hashes = alloc::vec![root_hash];
        for expected in 1..=10u32 {
            let op = sign(&signer, add_op(doc_id, expected)).await;
            let hash = Digest::hash(&op);
            graph.add_local_op(&op);
            assert_eq!(graph.lamport_ts_for(&hash), Some(expected));
            hashes.push(hash);

            // And nothing already in the graph has moved.
            for (i, earlier) in hashes.iter().enumerate() {
                assert_eq!(graph.lamport_ts_for(earlier), Some(i as u32));
            }
        }

        // An ancestor is always strictly earlier than its descendant.
        assert_eq!(graph.lamport_ts_for(&hashes[3]), Some(3));
        assert_eq!(graph.lamport_ts_for(&hashes[9]), Some(9));
        assert!(graph.lamport_ts_for(&hashes[3]) < graph.lamport_ts_for(&hashes[9]));
    }

    #[tokio::test]
    async fn a_merge_timestamp_is_one_greater_than_its_latest_predecessor() {
        let signer = MemorySigner::generate(&mut rand::thread_rng());
        let doc_id = TreeId::from(signer.verifying_key());
        let mut graph = CgkaOperationGraph::new();

        let root = sign(&signer, add_op(doc_id, 0)).await;
        let root_hash = Digest::hash(&root);
        graph.add_local_op(&root);

        // One branch two operations long. The other only one.
        let a1 = sign(&signer, add_op(doc_id, 1)).await;
        let a1_hash = Digest::hash(&a1);
        graph.add_op(&a1, &Set::from_iter([root_hash]));
        let a2 = sign(&signer, add_op(doc_id, 2)).await;
        let a2_hash = Digest::hash(&a2);
        graph.add_op(&a2, &Set::from_iter([a1_hash]));

        let b1 = sign(&signer, add_op(doc_id, 3)).await;
        let b1_hash = Digest::hash(&b1);
        graph.add_op(&b1, &Set::from_iter([root_hash]));

        assert_eq!(graph.lamport_ts_for(&a2_hash), Some(2));
        assert_eq!(graph.lamport_ts_for(&b1_hash), Some(1));

        // a1 and b1 are concurrent and tie.
        assert_eq!(
            graph.lamport_ts_for(&a1_hash),
            graph.lamport_ts_for(&b1_hash)
        );

        let merge = sign(&signer, add_op(doc_id, 4)).await;
        let merge_hash = Digest::hash(&merge);
        graph.add_op(&merge, &Set::from_iter([a2_hash, b1_hash]));

        // One greater than the longer branch.
        assert_eq!(graph.lamport_ts_for(&merge_hash), Some(3));

        // Every ancestor is strictly earlier, regardless of branch.
        for ancestor in [root_hash, a1_hash, a2_hash, b1_hash] {
            assert!(graph.lamport_ts_for(&ancestor) < graph.lamport_ts_for(&merge_hash));
        }
    }
}
