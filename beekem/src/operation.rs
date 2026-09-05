//! CGKA operations and their causal graph.

use crate::{
    collections::{Map, Set},
    content_addressed_map::CaMap,
    encrypted::EncryptedSecret,
    error::CgkaError,
    id::{MemberId, TreeId},
    topsort::TopologicalSort,
    transact::{Fork, Merge},
    tree::PathChange,
};
use alloc::{
    boxed::Box,
    collections::{BTreeMap, BTreeSet, VecDeque},
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

/// A root secret wrapped by an [`Invitation`].
#[derive(Debug, Clone, Hash, Eq, PartialEq, Deserialize, Serialize)]
#[cfg_attr(any(test, feature = "arbitrary"), derive(arbitrary::Arbitrary))]
pub struct InvitationSecret {
    /// The update operation that produced [`InvitationSecret::encrypted_root_secret`].
    pub update_op_hash: Digest<Signed<CgkaOperation>>,

    /// The root secret, encrypted to [`Invitation::invitee_pk`].
    pub encrypted_root_secret: EncryptedSecret<ShareSecretKey>,
}

/// When a member is added, it can't derive a root secret from the tree until the next
/// update. An invitation provides it the root secret associated with each update head
/// in the inviter's CGKA operation graph.
#[derive(Debug, Clone, Hash, Eq, PartialEq, Deserialize, Serialize)]
#[cfg_attr(any(test, feature = "arbitrary"), derive(arbitrary::Arbitrary))]
pub struct Invitation {
    /// The invited member.
    pub invitee_id: MemberId,

    /// The prekey the invited member was added under.
    pub invitee_pk: ShareKey,

    /// The inviter's share key corresponding to the secret key it used to encrypt
    /// each secret via Diffie-Hellman.
    pub inviter_pk: ShareKey,

    /// The root secret of each update head the inviter could reach.
    pub head_secrets: Vec<InvitationSecret>,
}

/// A member added after an update cannot derive that update's root secret from the
/// tree. A chain of predecessors (each encrypted by its successor) provides a way
/// in, at the cost of forward secrecy.
#[derive(Debug, Clone, Hash, Eq, PartialEq, Deserialize, Serialize)]
#[cfg_attr(any(test, feature = "arbitrary"), derive(arbitrary::Arbitrary))]
pub struct PredecessorSecret {
    /// The update operation that produced [`PredecessorSecret::encrypted_root_secret`].
    pub update_op_hash: Digest<Signed<CgkaOperation>>,

    /// The root secret produced by [`PredecessorSecret::update_op_hash`], encrypted
    /// under a key derived from its successor update.
    pub encrypted_root_secret: Vec<u8>,
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
        new_path: Box<PathChange>,
        /// The root secrets of the immediate update ancestors of this one
        predecessor_secrets: Vec<PredecessorSecret>,
        predecessors: Vec<Digest<Signed<CgkaOperation>>>,
        doc_id: TreeId,
    },
    /// Wraps an [`Invitation`] for a new member, allowing them to read content
    /// before the next PCS update. The only [`CgkaOperation`] that does not
    /// modify the tree.
    Invite {
        invitation: Box<Invitation>,
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
    }
}

impl CgkaOperationGraph {
    pub fn new() -> Self {
        Self {
            cgka_ops: CaMap::new(),
            cgka_ops_predecessors: Map::new(),
            cgka_op_heads: Set::new(),
            add_heads: Set::new(),
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
                .all(|p| self.cgka_ops.contains_key(p)),
            "predecessors should be in the graph before a descendent op"
        );
        self.cgka_ops_predecessors.insert(op_hash, op_predecessors);
    }

    /// The nearest [`CgkaOperation::Update`] operations at or before the provided
    /// heads.
    ///
    /// Skips operations of other kinds, since only an update produces
    /// a root secret. Returns an empty [`Set`] when no update precedes the heads.
    pub(crate) fn nearest_update_ancestors(
        &self,
        heads: &Set<Digest<Signed<CgkaOperation>>>,
    ) -> Set<Digest<Signed<CgkaOperation>>> {
        let mut updates = Set::new();
        let mut seen = Set::new();
        let mut frontier = Vec::from_iter(heads.iter().copied());
        while let Some(op_hash) = frontier.pop() {
            if !seen.insert(op_hash) {
                continue;
            }
            let Some(op) = self.cgka_ops.get(&op_hash) else {
                continue;
            };
            if matches!(op.payload, CgkaOperation::Update { .. }) {
                updates.insert(op_hash);
                continue;
            }
            if let Some(predecessors) = self.predecessors_for(&op_hash) {
                frontier.extend(predecessors.iter().copied());
            }
        }
        updates
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
        let mut frontier = VecDeque::new();
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
mod op_test_helpers {
    use super::*;
    use crate::id::TreeId;
    use keyhive_crypto::{
        share_key::ShareSecretKey,
        signer::{async_signer, memory::MemorySigner},
        verifiable::Verifiable,
    };

    pub(super) async fn sign(signer: &MemorySigner, op: CgkaOperation) -> Signed<CgkaOperation> {
        async_signer::try_sign_async::<future_form::Local, _, _>(signer, op)
            .await
            .unwrap()
    }

    pub(super) fn share_key() -> ShareKey {
        ShareSecretKey::generate(&mut rand::thread_rng()).share_key()
    }

    /// A new member id.
    pub(super) fn member_id() -> MemberId {
        MemberId(MemorySigner::generate(&mut rand::thread_rng()).verifying_key())
    }

    /// Add a new member that no other operation adds.
    pub(super) fn add_op(doc_id: TreeId, leaf_index: u32) -> CgkaOperation {
        CgkaOperation::Add {
            added_id: member_id(),
            pk: share_key(),
            leaf_index,
            predecessors: Vec::new(),
            add_predecessors: Vec::new(),
            doc_id,
        }
    }
}

#[cfg(test)]
mod nearest_update_ancestor_tests {
    use super::{
        op_test_helpers::{add_op, member_id, share_key, sign},
        *,
    };
    use crate::{id::TreeId, keys::NodeKey, tree::PathChange};
    use keyhive_crypto::{signer::memory::MemorySigner, verifiable::Verifiable};

    /// A new update by a fresh member. The path is empty because only the
    /// operation's kind matters here.
    fn update_op(doc_id: TreeId) -> CgkaOperation {
        let id = member_id();
        let leaf_pk = share_key();
        CgkaOperation::Update {
            id,
            new_path: Box::new(PathChange {
                leaf_id: id,
                leaf_idx: 0,
                leaf_pk: NodeKey::ShareKey(leaf_pk),
                path: Vec::new(),
                removed_keys: Vec::new(),
            }),
            predecessor_secrets: Vec::new(),
            predecessors: Vec::new(),
            doc_id,
        }
    }

    #[tokio::test]
    async fn traversal_skips_operations_that_produce_no_root_secret() {
        let signer = MemorySigner::generate(&mut rand::thread_rng());
        let doc_id = TreeId::from(signer.verifying_key());
        let mut graph = CgkaOperationGraph::new();

        // An update, then two adds on top of it.
        let update = sign(&signer, update_op(doc_id)).await;
        let update_hash = Digest::hash(&update);
        graph.add_local_op(&update);
        let add = sign(&signer, add_op(doc_id, 1)).await;
        let add_hash = Digest::hash(&add);
        graph.add_op(&add, &Set::from_iter([update_hash]));
        let later_add = sign(&signer, add_op(doc_id, 2)).await;
        let later_add_hash = Digest::hash(&later_add);
        graph.add_op(&later_add, &Set::from_iter([add_hash]));

        assert_eq!(
            graph.nearest_update_ancestors(&Set::from_iter([later_add_hash])),
            Set::from_iter([update_hash]),
            "the two adds produce no root secret, so the traversal should skip them"
        );

        // A head that is itself an update is returned rather than skipped.
        assert_eq!(
            graph.nearest_update_ancestors(&Set::from_iter([update_hash])),
            Set::from_iter([update_hash])
        );

        // No ops are found for a head with no updates in its ancestry.
        let orphan = sign(&signer, add_op(doc_id, 3)).await;
        let orphan_hash = Digest::hash(&orphan);
        graph.add_op(&orphan, &Set::new());
        assert_eq!(
            graph.nearest_update_ancestors(&Set::from_iter([orphan_hash])),
            Set::new()
        );
    }

    #[tokio::test]
    async fn each_head_contributes_its_own_nearest_update() {
        let signer = MemorySigner::generate(&mut rand::thread_rng());
        let doc_id = TreeId::from(signer.verifying_key());
        let mut graph = CgkaOperationGraph::new();

        let root = sign(&signer, add_op(doc_id, 0)).await;
        let root_hash = Digest::hash(&root);
        graph.add_local_op(&root);

        // Two concurrent branches, each an update followed by an add.
        let mut expected = Set::new();
        let mut heads = Set::new();
        for leaf_index in 1..=2u32 {
            let update = sign(&signer, update_op(doc_id)).await;
            let update_hash = Digest::hash(&update);
            graph.add_op(&update, &Set::from_iter([root_hash]));
            expected.insert(update_hash);

            let add = sign(&signer, add_op(doc_id, leaf_index)).await;
            graph.add_op(&add, &Set::from_iter([update_hash]));
            heads.insert(Digest::hash(&add));
        }

        assert_eq!(graph.nearest_update_ancestors(&heads), expected);
    }

    #[tokio::test]
    async fn only_the_nearest_update_on_a_path_is_returned() {
        let signer = MemorySigner::generate(&mut rand::thread_rng());
        let doc_id = TreeId::from(signer.verifying_key());
        let mut graph = CgkaOperationGraph::new();

        let earlier = sign(&signer, update_op(doc_id)).await;
        let earlier_hash = Digest::hash(&earlier);
        graph.add_local_op(&earlier);
        let later = sign(&signer, update_op(doc_id)).await;
        let later_hash = Digest::hash(&later);
        graph.add_op(&later, &Set::from_iter([earlier_hash]));
        let add = sign(&signer, add_op(doc_id, 1)).await;
        let add_hash = Digest::hash(&add);
        graph.add_op(&add, &Set::from_iter([later_hash]));

        assert_eq!(
            graph.nearest_update_ancestors(&Set::from_iter([add_hash])),
            Set::from_iter([later_hash]),
            "the traversal should stop at the first update on the path and not go past it"
        );
    }
}
