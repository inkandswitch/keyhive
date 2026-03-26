use std::collections::HashSet;

use super::{
    delegation::{Delegation, StaticDelegation},
    dependencies::Dependencies,
    revocation::{Revocation, StaticRevocation},
};
use crate::util::topsort::Topsort;
use crate::{
    crypto::signed_ext::SignedSubjectId,
    listener::{membership::MembershipListener, no_listener::NoListener},
    principal::{agent::Agent, document::id::DocumentId, identifier::Identifier},
    reversed::Reversed,
    store::{delegation::DelegationStore, revocation::RevocationStore},
    util::{content_addressed_map::CaMap, topsort::Topsort},
};
use derive_more::{From, Into};
use derive_where::derive_where;
use dupe::Dupe;
use future_form::FutureForm;
use keyhive_crypto::{
    content::reference::ContentRef, digest::Digest, signed::Signed,
    signer::async_signer::AsyncSigner, verifiable::Verifiable,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashMap},
    hash::Hash,
    sync::Arc,
};
use tracing::instrument;

#[derive_where(Debug, Clone, Eq; T)]
pub enum MembershipOperation<
    S: AsyncSigner<F>,
    T: ContentRef = [u8; 32],
    L: MembershipListener<F, S, T> = NoListener,
> {
    Delegation(Arc<Signed<Delegation<F, S, T, L>>>),
    Revocation(Arc<Signed<Revocation<F, S, T, L>>>),
}

impl<F: FutureForm, S: AsyncSigner<F>, T: ContentRef, L: MembershipListener<F, S, T>>
    std::hash::Hash for MembershipOperation<F, S, T, L>
{
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        match self {
            MembershipOperation::Delegation(delegation) => {
                delegation.signature.to_bytes().hash(state)
            }
            MembershipOperation::Revocation(revocation) => {
                revocation.signature.to_bytes().hash(state)
            }
        }
    }
}

impl<F: FutureForm, S: AsyncSigner<F>, T: ContentRef, L: MembershipListener<F, S, T>> PartialEq
    for MembershipOperation<F, S, T, L>
{
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (MembershipOperation::Delegation(d1), MembershipOperation::Delegation(d2)) => d1 == d2,
            (MembershipOperation::Revocation(r1), MembershipOperation::Revocation(r2)) => r1 == r2,
            _ => false,
        }
    }
}

impl<F: FutureForm, S: AsyncSigner<F>, T: ContentRef, L: MembershipListener<F, S, T>> PartialOrd
    for MembershipOperation<F, S, T, L>
{
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl<F: FutureForm, S: AsyncSigner<F>, T: ContentRef, L: MembershipListener<F, S, T>> Ord
    for MembershipOperation<F, S, T, L>
{
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.signature()
            .to_bytes()
            .cmp(&other.signature().to_bytes())
    }
}

impl<
        F: FutureForm,
        S: AsyncSigner<F>,
        T: ContentRef + Serialize,
        L: MembershipListener<F, S, T>,
    > Serialize for MembershipOperation<F, S, T, L>
{
    fn serialize<Z: serde::Serializer>(&self, serializer: Z) -> Result<Z::Ok, Z::Error> {
        match self {
            MembershipOperation::Delegation(delegation) => delegation.serialize(serializer),
            MembershipOperation::Revocation(revocation) => revocation.serialize(serializer),
        }
    }
}

impl<F: FutureForm, S: AsyncSigner<F>, T: ContentRef, L: MembershipListener<F, S, T>>
    MembershipOperation<F, S, T, L>
{
    pub fn subject_id(&self) -> Identifier {
        match self {
            MembershipOperation::Delegation(delegation) => delegation.subject_id(),
            MembershipOperation::Revocation(revocation) => revocation.subject_id(),
        }
    }

    pub fn is_delegation(&self) -> bool {
        match self {
            MembershipOperation::Delegation(_) => true,
            MembershipOperation::Revocation(_) => false,
        }
    }

    pub fn signature(&self) -> ed25519_dalek::Signature {
        match self {
            MembershipOperation::Delegation(delegation) => delegation.signature,
            MembershipOperation::Revocation(revocation) => revocation.signature,
        }
    }

    /// Get the memoized digest for this operation.
    pub fn digest(&self) -> Digest<MembershipOperation<F, S, T, L>> {
        match self {
            MembershipOperation::Delegation(delegation) => delegation.digest().coerce(),
            MembershipOperation::Revocation(revocation) => revocation.digest().coerce(),
        }
    }

    pub fn is_revocation(&self) -> bool {
        !self.is_delegation()
    }

    pub fn after_auth(&self) -> Vec<MembershipOperation<F, S, T, L>> {
        let deps = self.after();
        deps.delegations
            .into_iter()
            .map(|d| d.into())
            .chain(deps.revocations.into_iter().map(|r| r.into()))
            .collect()
    }

    pub fn after(&self) -> Dependencies<'_, F, S, T, L> {
        match self {
            MembershipOperation::Delegation(delegation) => delegation.payload.after(),
            MembershipOperation::Revocation(revocation) => revocation.payload.after(),
        }
    }

    pub fn after_content(&self) -> &BTreeMap<DocumentId, Vec<T>> {
        match self {
            MembershipOperation::Delegation(delegation) => &delegation.payload().after_content,
            MembershipOperation::Revocation(revocation) => &revocation.payload().after_content,
        }
    }

    pub fn is_root(&self) -> bool {
        match self {
            MembershipOperation::Delegation(delegation) => delegation.payload().is_root(),
            MembershipOperation::Revocation(_) => false,
        }
    }

    pub fn ancestors(&self) -> (CaMap<MembershipOperation<F, S, T, L>>, usize) {
        if self.is_root() {
            return (CaMap::new(), 1);
        }

        #[allow(clippy::mutable_key_type)]
        let mut ancestors = HashMap::new();
        let mut heads = vec![];

        let after_auth = self.after_auth();
        for op in after_auth.iter() {
            heads.push((op.clone(), 1));
        }

        while let Some((op, longest_known_path)) = heads.pop() {
            match ancestors.get(&op) {
                None => {
                    for parent_op in op.after_auth().iter() {
                        heads.push((parent_op.clone(), longest_known_path));
                    }

                    ancestors.insert(op, longest_known_path + 1)
                }
                Some(&count) if count > longest_known_path + 1 => continue,
                _ => ancestors.insert(op, longest_known_path + 1),
            };
        }

        ancestors.into_iter().fold(
            (CaMap::new(), 0),
            |(mut acc_set, acc_count), (op, count)| {
                acc_set.insert(Arc::new(op.clone()));

                if count > acc_count {
                    (acc_set, count)
                } else {
                    (acc_set, acc_count)
                }
            },
        )
    }

    /// Returns operations in reverse topological order (i.e., dependencies come
    /// later).
    ///
    /// Collects all reachable ops from heads via `after_auth()`,
    /// builds a topological sort from direct child→parent edges, and
    /// drains frontier by frontier. Concurrent revocations are forced
    /// into separate frontiers ordered by `(distance_to_root, digest)`
    /// so that [`Group::rebuild`] processes them sequentially with
    /// correct cascade semantics. Lower distance = closer to root =
    /// more senior authority = wins the tie-break.
    #[allow(clippy::type_complexity)] // Clippy doesn't like the returned pair
    #[instrument(skip_all)]
    pub fn reverse_topsort(
        delegation_heads: &DelegationStore<F, S, T, L>,
        revocation_heads: &RevocationStore<F, S, T, L>,
    ) -> Reversed<(
        Digest<MembershipOperation<F, S, T, L>>,
        MembershipOperation<F, S, T, L>,
    )> {
        // NOTE: BTreeMap to get deterministic order
        let mut all_ops: BTreeMap<
            Digest<MembershipOperation<F, S, T, L>>,
            (
                MembershipOperation<F, S, T, L>,
                Vec<Digest<MembershipOperation<F, S, T, L>>>,
            ),
        > = BTreeMap::new();

        #[derive(Debug, Clone, PartialEq, Eq, From, Into)]
        struct Key(ed25519_dalek::Signature);

        impl Hash for Key {
            fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
                self.0.to_bytes().hash(state)
            }
        }

        impl std::borrow::Borrow<ed25519_dalek::Signature> for Key {
            fn borrow(&self) -> &ed25519_dalek::Signature {
                &self.0
            }
        }

        // revoked delegation signature -> revocation digest
        let mut revoked_dependencies: HashMap<Key, Digest<MembershipOperation<F, S, T, L>>> =
            HashMap::new();

        let mut explore: Vec<MembershipOperation<F, S, T, L>> = vec![];

        for dlg in delegation_heads.values() {
            explore.push(dlg.dupe().into());
        }

        for rev in revocation_heads.values() {
            explore.push(rev.dupe().into());
        }

        // Collect all reachable ops from heads, storing parent digests alongside.
        while let Some(op) = explore.pop() {
            let digest = op.digest();
            if all_ops.contains_key(&digest) {
                continue;
            }

            let parents = op.after_auth();
            for parent in &parents {
                explore.push(parent.clone());
            }

            let parent_digests: Vec<_> = parents.iter().map(|p| p.digest()).collect();

            if let MembershipOperation::Revocation(r) = &op {
                revoked_dependencies.insert((*r.payload.revoke.signature()).into(), digest);
            }

            all_ops.insert(digest, (op, parent_digests));
        }

        // distance_to_root(node) = 1 + max(distance_to_root(p) for p in parents)
        // Root nodes (no parents in all_ops) have distance_to_root = 1.
        //
        // Computed via recursive DFS with memoization — each node is
        // visited at most once. The graph is a DAG (no cycles in
        // after_auth edges), so recursion terminates.
        //
        // Lower distance = closer to root = more senior authority.
        // An attacker cannot reduce their distance by creating puppet
        // delegations — those only increase depth.
        fn compute_distance<S: AsyncSigner<F>, T: ContentRef, L: MembershipListener<F, S, T>>(
            digest: &Digest<MembershipOperation<F, S, T, L>>,
            all_ops: &BTreeMap<
                Digest<MembershipOperation<F, S, T, L>>,
                (
                    MembershipOperation<F, S, T, L>,
                    Vec<Digest<MembershipOperation<F, S, T, L>>>,
                ),
            >,
            memo: &mut HashMap<Digest<MembershipOperation<F, S, T, L>>, usize>,
        ) -> usize {
            if let Some(&dist) = memo.get(digest) {
                return dist;
            }
            let dist = all_ops
                .get(digest)
                .map(|(_, parents)| {
                    parents
                        .iter()
                        .filter(|pd| all_ops.contains_key(pd))
                        .map(|pd| compute_distance(pd, all_ops, memo))
                        .max()
                        .unwrap_or(0)
                        + 1
                })
                .unwrap_or(1);
            memo.insert(*digest, dist);
            dist
        }

        let mut distance_to_root: HashMap<Digest<MembershipOperation<F, S, T, L>>, usize> =
            HashMap::new();
        for digest in all_ops.keys() {
            compute_distance(digest, &all_ops, &mut distance_to_root);
        }

        type TsKey<'a, S, T, L> = (
            Digest<MembershipOperation<F, S, T, L>>,
            &'a MembershipOperation<F, S, T, L>,
        );

        let mut adjacencies: Topsort<TsKey<'_, S, T, L>> = Topsort::new();

        let mut successors_of: HashMap<
            Digest<MembershipOperation<F, S, T, L>>,
            Vec<Digest<MembershipOperation<F, S, T, L>>>,
        > = HashMap::new();

        for (digest, (op, parent_digests)) in all_ops.iter() {
            adjacencies.add_node((*digest, op));

            for parent_digest in parent_digests {
                if let Some((parent_op, _)) = all_ops.get(parent_digest) {
                    adjacencies.add_dependency((*digest, op), (*parent_digest, parent_op));
                    successors_of
                        .entry(*digest)
                        .or_default()
                        .push(*parent_digest);
                }
            }

            if let MembershipOperation::Delegation(d) = op {
                if let Some(proof) = &d.payload.proof {
                    if let Some(revoked_digest) = revoked_dependencies.get(&Key(proof.signature)) {
                        if let Some((revoked_op, _)) = all_ops.get(revoked_digest) {
                            adjacencies
                                .add_dependency((*digest, op), (*revoked_digest, revoked_op));
                            successors_of
                                .entry(*digest)
                                .or_default()
                                .push(*revoked_digest);
                        }
                    }
                }
            }
        }

        let mut dependencies = vec![];

        while !adjacencies.is_empty() {
            let batch = adjacencies.pop_frontier();
            if batch.is_empty() {
                break; // cycle guard
            }

            let (mut revocations, mut others): (Vec<_>, Vec<_>) =
                batch.into_iter().partition(|(_, op)| op.is_revocation());

            others.sort_by_key(|(d, _)| *d);
            for (digest, op) in &others {
                dependencies.push((*digest, (*op).clone()));
            }

            if revocations.len() <= 1 {
                for (digest, op) in &revocations {
                    dependencies.push((*digest, (*op).clone()));
                }
            } else {
                revocations.sort_by(|(d1, _), (d2, _)| {
                    let dist1 = distance_to_root.get(d1).copied().unwrap_or(1);
                    let dist2 = distance_to_root.get(d2).copied().unwrap_or(1);
                    dist1.cmp(&dist2).then_with(|| d1.cmp(d2))
                });

                let (first_digest, first_op) = revocations[0];
                dependencies.push((first_digest, first_op.clone()));

                let remaining = &revocations[1..];
                for window in remaining.windows(2) {
                    let before = window[0];
                    let after = window[1];
                    adjacencies.add_dependency(after, before);
                }
                if remaining.len() == 1 {
                    adjacencies.add_node(remaining[0]);
                }

                for &(rev_digest, rev_op) in remaining {
                    if let Some(succs) = successors_of.get(&rev_digest) {
                        for succ_digest in succs {
                            if let Some((succ_op, _)) = all_ops.get(succ_digest) {
                                adjacencies
                                    .add_dependency((rev_digest, rev_op), (*succ_digest, succ_op));
                            }
                        }
                    }
                }
            }
        }

        Reversed(dependencies)
    }
}

impl<F: FutureForm, S: AsyncSigner<F>, T: ContentRef, L: MembershipListener<F, S, T>> Dupe
    for MembershipOperation<F, S, T, L>
{
    fn dupe(&self) -> Self {
        self.clone()
    }
}

impl<F: FutureForm, S: AsyncSigner<F>, T: ContentRef, L: MembershipListener<F, S, T>> Verifiable
    for MembershipOperation<F, S, T, L>
{
    fn verifying_key(&self) -> ed25519_dalek::VerifyingKey {
        match self {
            MembershipOperation::Delegation(delegation) => delegation.verifying_key(),
            MembershipOperation::Revocation(revocation) => revocation.verifying_key(),
        }
    }
}

impl<F: FutureForm, S: AsyncSigner<F>, T: ContentRef, L: MembershipListener<F, S, T>>
    From<Arc<Signed<Delegation<F, S, T, L>>>> for MembershipOperation<F, S, T, L>
{
    fn from(delegation: Arc<Signed<Delegation<F, S, T, L>>>) -> Self {
        MembershipOperation::Delegation(delegation)
    }
}

impl<F: FutureForm, S: AsyncSigner<F>, T: ContentRef, L: MembershipListener<F, S, T>>
    From<Arc<Signed<Revocation<F, S, T, L>>>> for MembershipOperation<F, S, T, L>
{
    fn from(revocation: Arc<Signed<Revocation<F, S, T, L>>>) -> Self {
        MembershipOperation::Revocation(revocation)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(any(test, feature = "arbitrary"), derive(arbitrary::Arbitrary))]
pub enum StaticMembershipOperation<T: ContentRef> {
    Delegation(Signed<StaticDelegation<T>>),
    Revocation(Signed<StaticRevocation<T>>),
}

impl<F: FutureForm, S: AsyncSigner<F>, T: ContentRef, L: MembershipListener<F, S, T>>
    From<MembershipOperation<F, S, T, L>> for StaticMembershipOperation<T>
{
    fn from(op: MembershipOperation<F, S, T, L>) -> Self {
        match op {
            MembershipOperation::Delegation(d) => {
                StaticMembershipOperation::Delegation(Arc::unwrap_or_clone(d).map(Into::into))
            }
            MembershipOperation::Revocation(r) => {
                StaticMembershipOperation::Revocation(Arc::unwrap_or_clone(r).map(Into::into))
            }
        }
    }
}

pub type MembershipOpMap<S, T, L> =
    HashMap<Digest<MembershipOperation<F, S, T, L>>, MembershipOperation<F, S, T, L>>;

pub type MembershipOpEntry<S, T, L> = (
    Digest<MembershipOperation<F, S, T, L>>,
    MembershipOperation<F, S, T, L>,
);

/// Membership ops for all agents, with shared storage.
///
/// Instead of computing BFS per agent (which repeats work for agents sharing
/// groups/docs), the BFS is computed once per source (group, doc, or agent)
/// and each agent has an index into the shared source sets.
#[derive_where(Debug; T)]
pub struct AllMembershipOps<
    S: AsyncSigner<F>,
    T: ContentRef = [u8; 32],
    L: MembershipListener<F, S, T> = NoListener,
> {
    /// Membership ops per source (group, doc, or agent), computed once.
    pub ops: HashMap<Identifier, MembershipOpMap<S, T, L>>,

    /// For each agent: the set of source identifiers whose ops are reachable.
    pub index: HashMap<Identifier, HashSet<Identifier>>,
}

#[allow(clippy::type_complexity)]
impl<F: FutureForm, S: AsyncSigner<F>, T: ContentRef, L: MembershipListener<F, S, T>>
    AllMembershipOps<S, T, L>
{
    /// Returns the set of agent identifiers that have reachable ops.
    pub fn agents(&self) -> impl Iterator<Item = &Identifier> {
        self.index.keys()
    }

    /// Returns an iterator over all reachable membership ops for the given agent
    /// (flattened across all source identifiers), or `None` if the agent is not
    /// in the index. May contain duplicates if sources share sub-chains.
    pub fn ops_for_agent(
        &self,
        agent_id: &Identifier,
    ) -> Option<
        impl Iterator<
            Item = (
                &Digest<MembershipOperation<F, S, T, L>>,
                &MembershipOperation<F, S, T, L>,
            ),
        >,
    > {
        self.index.get(agent_id).map(|ids| {
            ids.iter()
                .filter_map(|id| self.ops.get(id))
                .flat_map(|ops| ops.iter())
        })
    }
}

/// Build the initial BFS frontier from a group's or doc's delegation and
/// revocation head stores. Cheap (Arc clones + digest copies).
pub fn collect_membership_heads<
    S: AsyncSigner<F>,
    T: ContentRef,
    L: MembershipListener<F, S, T>,
>(
    dlg_heads: &DelegationStore<F, S, T, L>,
    rev_heads: &RevocationStore<F, S, T, L>,
) -> Vec<MembershipOpEntry<S, T, L>> {
    let mut heads = Vec::with_capacity(dlg_heads.len() + rev_heads.len());
    for (hash, dlg_head) in dlg_heads.iter() {
        heads.push((hash.coerce(), dlg_head.dupe().into()));
    }
    for (hash, rev_head) in rev_heads.iter() {
        heads.push((hash.coerce(), rev_head.dupe().into()));
    }
    heads
}

/// Enqueue BFS edges from a single [`MembershipOperation`].
///
/// For delegations, follows the proof chain and any `after_revocations`.
/// When `follow_group_heads` is true, also enqueues the group delegate's
/// own delegation heads (used during full BFS but not when extending from
/// a single revocation).
///
/// For revocations, follows the proof and revoke chains.
async fn push_membership_edges<S: AsyncSigner<F>, T: ContentRef, L: MembershipListener<F, S, T>>(
    op: &MembershipOperation<F, S, T, L>,
    heads: &mut Vec<MembershipOpEntry<S, T, L>>,
    visited: &HashSet<Digest<MembershipOperation<F, S, T, L>>>,
    follow_group_heads: bool,
) {
    match op {
        MembershipOperation::Delegation(dlg) => {
            if let Some(proof) = &dlg.payload.proof {
                heads.push((Digest::hash(proof.as_ref()).coerce(), proof.dupe().into()));
            }
            for rev in dlg.payload.after_revocations.iter() {
                heads.push((Digest::hash(rev.as_ref()).coerce(), rev.dupe().into()));
            }
            if follow_group_heads {
                if let Agent::Group(_group_id, group) = &dlg.payload.delegate {
                    for dlg in group.lock().await.delegation_heads().values() {
                        let dlg_hash = Digest::hash(dlg.as_ref()).coerce();
                        if !visited.contains(&dlg_hash) {
                            heads.push((dlg_hash, dlg.dupe().into()));
                        }
                    }
                }
            }
        }
        MembershipOperation::Revocation(rev) => {
            if let Some(proof) = &rev.payload.proof {
                heads.push((Digest::hash(proof.as_ref()).coerce(), proof.dupe().into()));
            }
            let r = rev.payload.revoke.dupe();
            heads.push((Digest::hash(r.as_ref()).coerce(), r.into()));
        }
    }
}

/// Walk all [`MembershipOperation`]s reachable from the given heads via BFS,
/// following proof chains, revoke chains, and (for delegations to groups) the
/// group's own delegation heads. Returns a map keyed by digest.
pub async fn bfs_membership_ops<
    S: AsyncSigner<F>,
    T: ContentRef,
    L: MembershipListener<F, S, T>,
>(
    mut heads: Vec<MembershipOpEntry<S, T, L>>,
) -> MembershipOpMap<S, T, L> {
    let mut ops = HashMap::new();
    let mut visited: HashSet<Digest<MembershipOperation<F, S, T, L>>> = HashSet::new();

    while let Some((hash, op)) = heads.pop() {
        if visited.contains(&hash) {
            continue;
        }
        visited.insert(hash);
        push_membership_edges(&op, &mut heads, &visited, true).await;
        ops.insert(hash, op);
    }

    ops
}

/// Extend an existing [`MembershipOpMap`] by following a single revocation's
/// proof and revoke chains. Skips already-visited digests so it can be called
/// incrementally for each agent-specific revocation.
pub async fn bfs_extend_from_revocation<
    S: AsyncSigner<F>,
    T: ContentRef,
    L: MembershipListener<F, S, T>,
>(
    rev: &Arc<Signed<Revocation<F, S, T, L>>>,
    all_ops: &mut MembershipOpMap<S, T, L>,
    visited: &mut HashSet<Digest<MembershipOperation<F, S, T, L>>>,
) {
    let mut heads: Vec<MembershipOpEntry<S, T, L>> = Vec::new();

    if let Some(proof) = &rev.payload.proof {
        heads.push((Digest::hash(proof.as_ref()).coerce(), proof.dupe().into()));
    }
    let r = rev.payload.revoke.dupe();
    heads.push((Digest::hash(r.as_ref()).coerce(), r.into()));

    while let Some((hash, op)) = heads.pop() {
        if visited.contains(&hash) {
            continue;
        }
        visited.insert(hash);
        push_membership_edges(&op, &mut heads, visited, false).await;
        all_ops.entry(hash).or_insert(op);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        access::Access,
        principal::{agent::Agent, individual::Individual},
        store::{delegation::DelegationStore, revocation::RevocationStore},
    };
    use dupe::Dupe;
    use future_form::Local;
    use futures::lock::Mutex;
    use keyhive_crypto::signer::memory::MemorySigner;
    use std::sync::{Arc, LazyLock};
    use testresult::TestResult;

    // FIXME
    // FIXME these should probbaly use `lazy_static!`
    static GROUP_SIGNER: LazyLock<MemorySigner> =
        LazyLock::new(|| MemorySigner::generate(&mut rand::thread_rng()));

    static ALICE_SIGNER: LazyLock<MemorySigner> =
        LazyLock::new(|| MemorySigner::generate(&mut rand::thread_rng()));

    static BOB_SIGNER: LazyLock<MemorySigner> =
        LazyLock::new(|| MemorySigner::generate(&mut rand::thread_rng()));

    static CAROL_SIGNER: LazyLock<MemorySigner> =
        LazyLock::new(|| MemorySigner::generate(&mut rand::thread_rng()));

    static DAN_SIGNER: LazyLock<MemorySigner> =
        LazyLock::new(|| MemorySigner::generate(&mut rand::thread_rng()));

    static ERIN_SIGNER: LazyLock<MemorySigner> =
        LazyLock::new(|| MemorySigner::generate(&mut rand::thread_rng()));

    /*
             ┌────────┐
             │ Remove │
        ┌────│  Dan   │──────┐
        │    └────────┘      │
        │         ║          │
        ▼         ║          ▼
    ┌───────┐     ║      ┌───────┐  ┌────────┐
    │ Erin  │     ║      │  Dan  │  │ Remove │
    └───────┘     ║      └───────┘  │ Carol  │══╗
        │         ║          │      └────────┘  ║
        │         ║          │           │      ║
        │         ▼          ▼           │      ║
        │     ┌───────┐  ┌───────┐       │      ║
        └────▶│  Bob  │  │ Carol │◀──────┘      ║
              └───────┘  └───────┘              ║
                  │          │                  ║
                  │          │                  ║
                  │          ▼                  ║
                  │      ┌───────┐              ║
                  └─────▶│ Alice │◀═════════════╝
                         └───────┘
                             │
                             │
                             ▼
                         ┌───────┐
                         │ Group │
                         └───────┘
    */

    async fn add_alice<R: rand::CryptoRng + rand::RngCore>(
        csprng: &mut R,
    ) -> Arc<Signed<Delegation<Local, MemorySigner, String>>> {
        let alice = Individual::generate::<Local, _, _>(fixture(&ALICE_SIGNER), csprng)
            .await
            .unwrap();
        let group_sk = LazyLock::force(&GROUP_SIGNER).clone();

        Arc::new(
            group_sk
                .try_sign_sync(Delegation {
                    delegate: alice.into(),
                    can: Access::Admin,
                    proof: None,
                    after_content: BTreeMap::new(),
                    after_revocations: vec![],
                })
                .unwrap(),
        )
        .dupe()
    }

    async fn add_bob<R: rand::CryptoRng + rand::RngCore>(
        csprng: &mut R,
    ) -> Arc<Signed<Delegation<Local, MemorySigner, String>>> {
        let bob = Individual::generate::<Local, _, _>(fixture(&BOB_SIGNER), csprng)
            .await
            .unwrap();

        Arc::new(
            fixture(&ALICE_SIGNER)
                .try_sign_sync(Delegation {
                    delegate: Agent::Individual(bob.id(), Arc::new(Mutex::new(bob))),
                    can: Access::Edit,
                    proof: Some(add_alice(csprng).await),
                    after_content: BTreeMap::new(),
                    after_revocations: vec![],
                })
                .unwrap(),
        )
    }

    async fn add_carol<R: rand::CryptoRng + rand::RngCore>(
        csprng: &mut R,
    ) -> Arc<Signed<Delegation<Local, MemorySigner, String>>> {
        let carol = Individual::generate::<Local, _, _>(fixture(&CAROL_SIGNER), csprng)
            .await
            .unwrap();

        Arc::new(
            fixture(&ALICE_SIGNER)
                .try_sign_sync(Delegation {
                    delegate: carol.into(),
                    can: Access::Edit,
                    proof: Some(add_alice(csprng).await),
                    after_content: BTreeMap::new(),
                    after_revocations: vec![],
                })
                .unwrap(),
        )
    }

    async fn add_dan<R: rand::CryptoRng + rand::RngCore>(
        csprng: &mut R,
    ) -> Arc<Signed<Delegation<Local, MemorySigner, String>>> {
        let dan = Individual::generate::<Local, _, _>(fixture(&DAN_SIGNER), csprng)
            .await
            .unwrap();

        Arc::new(
            fixture(&CAROL_SIGNER)
                .try_sign_sync(Delegation {
                    delegate: dan.into(),
                    can: Access::Edit,
                    proof: Some(add_carol(csprng).await),
                    after_content: BTreeMap::new(),
                    after_revocations: vec![],
                })
                .unwrap(),
        )
    }

    async fn add_erin<R: rand::CryptoRng + rand::RngCore>(
        csprng: &mut R,
    ) -> Arc<Signed<Delegation<Local, MemorySigner, String>>> {
        let erin = Individual::generate::<Local, _, _>(fixture(&ERIN_SIGNER), csprng)
            .await
            .unwrap();

        Arc::new(
            fixture(&BOB_SIGNER)
                .try_sign_sync(Delegation {
                    delegate: erin.into(),
                    can: Access::Edit,
                    proof: Some(add_bob(csprng).await),
                    after_content: BTreeMap::new(),
                    after_revocations: vec![],
                })
                .unwrap(),
        )
    }

    async fn remove_carol<R: rand::CryptoRng + rand::RngCore>(
        csprng: &mut R,
    ) -> Arc<Signed<Revocation<Local, MemorySigner, String>>> {
        Arc::new(
            fixture(&ALICE_SIGNER)
                .try_sign_sync(Revocation {
                    revoke: add_carol(csprng).await,
                    proof: Some(add_alice(csprng).await),
                    after_content: BTreeMap::new(),
                })
                .unwrap(),
        )
    }

    async fn remove_dan<R: rand::CryptoRng + rand::RngCore>(
        csprng: &mut R,
    ) -> Arc<Signed<Revocation<Local, MemorySigner, String>>> {
        Arc::new(
            fixture(&BOB_SIGNER)
                .try_sign_sync(Revocation {
                    revoke: add_dan(csprng).await,
                    proof: Some(add_bob(csprng).await),
                    after_content: BTreeMap::new(),
                })
                .unwrap(),
        )
    }

    fn fixture<T>(from: &LazyLock<T>) -> &T {
        LazyLock::force(from)
    }

    mod ancestors {
        use super::*;

        #[tokio::test]
        async fn test_singleton() {
            test_utils::init_logging();
            let csprng = &mut rand::thread_rng();
            let alice_dlg = add_alice(csprng).await;
            let (ancestors, longest) = MembershipOperation::from(alice_dlg).ancestors();
            assert!(ancestors.is_empty());
            assert_eq!(longest, 1);
        }

        #[tokio::test]
        async fn test_two_direct() {
            test_utils::init_logging();
            let csprng = &mut rand::thread_rng();
            let bob_dlg = add_bob(csprng).await;
            let (ancestors, longest) = MembershipOperation::from(bob_dlg).ancestors();
            assert_eq!(ancestors.len(), 1);
            assert_eq!(longest, 2);
        }

        #[tokio::test]
        async fn test_concurrent() {
            test_utils::init_logging();
            let csprng = &mut rand::thread_rng();
            let bob_dlg = add_bob(csprng).await;
            let carol_dlg = add_carol(csprng).await;

            let (bob_ancestors, bob_longest) = MembershipOperation::from(bob_dlg).ancestors();
            let (carol_ancestors, carol_longest) = MembershipOperation::from(carol_dlg).ancestors();

            assert_eq!(bob_ancestors.len(), carol_ancestors.len());
            assert_eq!(bob_longest, carol_longest);
        }

        #[tokio::test]
        async fn test_longer() {
            test_utils::init_logging();
            let csprng = &mut rand::thread_rng();
            let erin_dlg = add_erin(csprng).await;
            let (ancestors, longest) = MembershipOperation::from(erin_dlg).ancestors();
            assert_eq!(ancestors.len(), 2);
            assert_eq!(longest, 2);
        }

        #[tokio::test]
        async fn test_revocation() {
            test_utils::init_logging();
            let csprng = &mut rand::thread_rng();
            let rev = remove_carol(csprng).await;
            let (ancestors, longest) = MembershipOperation::from(rev).ancestors();
            assert_eq!(ancestors.len(), 2);
            assert_eq!(longest, 2);
        }
    }

    mod topsort {
        use super::*;
        use crate::principal::active::Active;

        #[test]
        fn test_empty() {
            test_utils::init_logging();

            let dlgs = DelegationStore::new();
            let revs = RevocationStore::new();

            let observed =
                MembershipOperation::<Local, MemorySigner, String>::reverse_topsort(&dlgs, &revs);
            assert_eq!(observed, Reversed(vec![]));
        }

        #[tokio::test]
        async fn test_one_delegation() {
            test_utils::init_logging();
            let csprng = &mut rand::thread_rng();

            let dlg = add_alice(csprng).await;

            let dlgs = DelegationStore::from_iter_direct([dlg.dupe()]);
            let revs = RevocationStore::new();

            let observed = MembershipOperation::reverse_topsort(&dlgs, &revs);
            let expected = dlg.into();

            assert_eq!(
                observed,
                Reversed(vec![(Digest::hash(&expected), expected)])
            );
        }

        #[tokio::test]
        async fn test_delegation_sequence() {
            test_utils::init_logging();
            let csprng = &mut rand::thread_rng();

            let alice_dlg = add_alice(csprng).await;
            let bob_dlg = add_bob(csprng).await;

            let dlg_heads = DelegationStore::from_iter_direct([bob_dlg.dupe()]);
            let rev_heads = RevocationStore::new();

            let observed = MembershipOperation::reverse_topsort(&dlg_heads, &rev_heads);

            let alice_op = alice_dlg.into();
            let bob_op = bob_dlg.into();

            let expected = vec![
                (Digest::hash(&bob_op), bob_op),
                (Digest::hash(&alice_op), alice_op),
            ];

            assert_eq!(observed.len(), 2);
            assert_eq!(observed, Reversed(expected));
        }

        #[tokio::test]
        async fn test_longer_delegation_chain() {
            test_utils::init_logging();
            let csprng = &mut rand::thread_rng();

            let alice_dlg = add_alice(csprng).await;
            let carol_dlg = add_carol(csprng).await;
            let dan_dlg = add_dan(csprng).await;

            let dlg_heads = DelegationStore::from_iter_direct([dan_dlg.dupe()]);
            let rev_heads = RevocationStore::new();

            let observed = MembershipOperation::reverse_topsort(&dlg_heads, &rev_heads);

            let alice_op: MembershipOperation<Local, MemorySigner, String> = alice_dlg.into();
            let alice_hash = Digest::hash(&alice_op);

            let carol_op: MembershipOperation<Local, MemorySigner, String> = carol_dlg.into();
            let carol_hash = Digest::hash(&carol_op);

            let dan_op: MembershipOperation<Local, MemorySigner, String> = dan_dlg.into();
            let dan_hash = Digest::hash(&dan_op);

            let a = (alice_hash, alice_op.clone());
            let c = (carol_hash, carol_op.clone());
            let d = (dan_hash, dan_op.clone());

            assert_eq!(observed, Reversed(vec![d, c, a]));
        }

        #[tokio::test]
        async fn test_delegation_concurrency() {
            //             ┌─────────┐
            //             │  Alice  │
            //             └─────────┘
            //      ┌───────────┴────────────┐
            //      │                        │
            //   (write)                   (read)
            //      │                        │
            //      ▼                        ▼
            // ┌─────────┐              ┌─────────┐
            // │   Bob   │              │   Dan   │
            // └─────────┘              └─────────┘
            //      │
            //    (pull)
            //      │
            //      ▼
            // ┌─────────┐
            // │  Carol  │
            // └─────────┘
            test_utils::init_logging();
            let csprng = &mut rand::thread_rng();

            let alice_sk = fixture(&ALICE_SIGNER).clone();
            let alice = Arc::new(Mutex::new(
                Active::<Local, _, [u8; 32], _>::generate(alice_sk, NoListener, csprng)
                    .await
                    .unwrap(),
            ));

            let bob_sk = fixture(&BOB_SIGNER).clone();
            let bob = Arc::new(Mutex::new(
                Active::<Local, _, _, _>::generate(bob_sk, NoListener, csprng)
                    .await
                    .unwrap(),
            ));

            let carol_sk = fixture(&CAROL_SIGNER).clone();
            let carol = Arc::new(Mutex::new(
                Active::<Local, _, _, _>::generate(carol_sk, NoListener, csprng)
                    .await
                    .unwrap(),
            ));

            let dan_sk = fixture(&DAN_SIGNER).clone();
            let dan = Arc::new(Mutex::new(
                Active::<Local, _, _, _>::generate(dan_sk, NoListener, csprng)
                    .await
                    .unwrap(),
            ));

            let locked_alice = alice.lock().await;

            let alice_to_bob: Arc<Signed<Delegation<Local, MemorySigner>>> = Arc::new(
                locked_alice
                    .signer
                    .try_sign_sync(Delegation {
                        delegate: Agent::Active(bob.lock().await.id(), bob.dupe()),
                        can: Access::Edit,
                        proof: None,
                        after_revocations: vec![],
                        after_content: BTreeMap::new(),
                    })
                    .unwrap(),
            );

            let alice_to_dan = Arc::new(
                locked_alice
                    .signer
                    .try_sign_sync(Delegation {
                        delegate: Agent::Active(dan.lock().await.id(), dan.dupe()),
                        can: Access::Read,
                        proof: None,
                        after_revocations: vec![],
                        after_content: BTreeMap::new(),
                    })
                    .unwrap(),
            );

            drop(locked_alice);

            let locked_bob = bob.lock().await;
            let bob_to_carol = Arc::new(
                locked_bob
                    .signer
                    .try_sign_sync(Delegation {
                        delegate: Agent::Active(carol.lock().await.id(), carol.dupe()),
                        can: Access::Relay,
                        proof: Some(alice_to_bob.dupe()),
                        after_revocations: vec![],
                        after_content: BTreeMap::new(),
                    })
                    .unwrap(),
            );

            let dlg_heads =
                DelegationStore::from_iter_direct([alice_to_dan.dupe(), bob_to_carol.dupe()]);
            let mut sorted =
                MembershipOperation::reverse_topsort(&dlg_heads, &RevocationStore::new());
            sorted.reverse();

            assert!(sorted.len() == 3);

            let ab_idx = sorted
                .iter()
                .position(|(_, op)| op == &alice_to_bob.dupe().into())
                .unwrap();

            // alice_to_dan has no causal relationship with the other
            // ops — just verify it exists in the output.
            sorted
                .iter()
                .position(|(_, op)| op == &alice_to_dan.dupe().into())
                .expect("alice_to_dan should be in output");

            let bc_idx = sorted
                .iter()
                .position(|(_, op)| op == &bob_to_carol.dupe().into())
                .unwrap();

            assert!(ab_idx < bc_idx);
        }

        #[tokio::test]
        async fn test_one_revocation() {
            test_utils::init_logging();

            let csprng = &mut rand::thread_rng();
            let alice_sk = fixture(&ALICE_SIGNER).clone();
            let alice_dlg = add_alice(csprng).await;
            let bob_dlg = add_bob(csprng).await;

            let alice_revokes_bob = Arc::new(
                alice_sk
                    .try_sign_sync(Revocation {
                        revoke: bob_dlg.dupe(),
                        proof: Some(alice_dlg.dupe()),
                        after_content: BTreeMap::new(),
                    })
                    .unwrap(),
            );
            let rev_op: MembershipOperation<Local, MemorySigner, String> =
                alice_revokes_bob.dupe().into();
            let rev_hash = Digest::hash(&rev_op);

            let dlgs = DelegationStore::new();
            let revs = RevocationStore::from_iter_direct([alice_revokes_bob.dupe()]);

            let mut observed = MembershipOperation::reverse_topsort(&dlgs, &revs);

            let alice_op: MembershipOperation<Local, MemorySigner, String> = alice_dlg.into();
            let alice_hash = Digest::hash(&alice_op);

            let bob_op: MembershipOperation<Local, MemorySigner, String> = bob_dlg.into();
            let bob_hash = Digest::hash(&bob_op);

            let a = (alice_hash, alice_op.clone());
            let b = (bob_hash, bob_op.clone());
            let r = (rev_hash, alice_revokes_bob.into());

            assert_eq!(observed.clone().len(), 3);

            assert_eq!(observed.pop(), Some(a));
            assert_eq!(observed.pop(), Some(b));
            assert_eq!(observed.pop(), Some(r));
            assert_eq!(observed.pop(), None);
        }

        #[tokio::test]
        async fn test_many_revocations() {
            test_utils::init_logging();
            let csprng = &mut rand::thread_rng();

            let alice_dlg = add_alice(csprng).await;
            let bob_dlg = add_bob(csprng).await;

            let carol_dlg = add_carol(csprng).await;
            let dan_dlg = add_dan(csprng).await;
            let erin_dlg = add_erin(csprng).await;

            let alice_revokes_carol = remove_carol(csprng).await;
            let bob_revokes_dan = remove_dan(csprng).await;

            let rev_carol_op: MembershipOperation<Local, MemorySigner, String> =
                alice_revokes_carol.dupe().into();
            let rev_carol_hash = Digest::hash(&rev_carol_op);

            let rev_dan_op: MembershipOperation<Local, MemorySigner, String> =
                bob_revokes_dan.dupe().into();
            let rev_dan_hash = Digest::hash(&rev_dan_op);

            let dlg_heads = DelegationStore::from_iter_direct([erin_dlg.dupe()]);
            let rev_heads = RevocationStore::from_iter_direct([
                alice_revokes_carol.dupe(),
                bob_revokes_dan.dupe(),
            ]);

            let observed = MembershipOperation::reverse_topsort(&dlg_heads, &rev_heads);

            let alice_op: MembershipOperation<Local, MemorySigner, String> =
                alice_dlg.clone().into();
            let alice_hash = Digest::hash(&alice_op);

            let bob_op: MembershipOperation<Local, MemorySigner, String> = bob_dlg.clone().into();
            let bob_hash = Digest::hash(&bob_op);

            let carol_op: MembershipOperation<Local, MemorySigner, String> =
                carol_dlg.clone().into();
            let carol_hash = Digest::hash(&carol_op);

            let dan_op: MembershipOperation<Local, MemorySigner, String> = dan_dlg.clone().into();
            let dan_hash = Digest::hash(&dan_op);

            let erin_op: MembershipOperation<Local, MemorySigner, String> = erin_dlg.clone().into();
            let erin_hash = Digest::hash(&erin_op);

            let mut bob_and_revoke_carol = [
                (bob_hash, bob_op.clone()),
                (rev_carol_hash, rev_carol_op.clone()),
            ];
            bob_and_revoke_carol.sort_by_key(|(hash, _)| *hash);

            let mut dan_and_erin = [(dan_hash, dan_op.clone()), (erin_hash, erin_op.clone())];
            dan_and_erin.sort_by_key(|(hash, _)| *hash);

            let mut revs = [(rev_dan_hash, rev_dan_op.clone())];
            revs.sort_by_key(|(hash, _)| *hash);

            assert_eq!(observed.clone().len(), 7);

            let len = observed.len();

            // In reverse topological order, alice (with no dependencies) should be at the end
            assert_eq!(observed[len - 1], (alice_hash, alice_op));

            let pos_alice = observed
                .iter()
                .position(|(hash, _)| *hash == alice_hash)
                .unwrap();

            let pos_bob = observed
                .iter()
                .position(|(hash, _)| *hash == bob_hash)
                .unwrap();

            let pos_carol = observed
                .iter()
                .position(|(hash, _)| *hash == carol_hash)
                .unwrap();

            let pos_dan = observed
                .iter()
                .position(|(hash, _)| *hash == dan_hash)
                .unwrap();

            let pos_erin = observed
                .iter()
                .position(|(hash, _)| *hash == erin_hash)
                .unwrap();

            let pos_rev_carol = observed
                .iter()
                .position(|(hash, _)| *hash == rev_carol_hash)
                .unwrap();

            let pos_rev_dan = observed
                .iter()
                .position(|(hash, _)| *hash == rev_dan_hash)
                .unwrap();

            // Remember: the order is reversed from what you'd expect because
            // the main interface is `next` or `pop`
            // Since we need to account for concurrency, some will be ordered by their hash,
            // which is difficult to account for in a test with random signing keys. Instead of
            // asserting some specific order, we just assert that the relationships are correct.
            assert!(pos_alice > pos_bob);
            assert!(pos_alice > pos_carol);
            assert!(pos_alice > pos_erin);
            assert!(pos_alice > pos_rev_carol);
            assert!(pos_alice > pos_rev_dan);
            assert!(pos_bob > pos_erin);
            assert!(pos_bob > pos_rev_dan);
            assert!(pos_carol > pos_dan);
            assert!(pos_carol > pos_rev_carol);
            assert!(pos_carol > pos_rev_dan);
            assert!(pos_dan > pos_rev_dan);
        }

        /// Two concurrent revocations that revoke each other's proofs.
        #[tokio::test]
        async fn test_concurrent_revocations_deterministic_order() {
            test_utils::init_logging();
            let csprng = &mut rand::thread_rng();

            let group_signer = MemorySigner::generate(csprng);
            let alice_signer = MemorySigner::generate(csprng);
            let bob_signer = MemorySigner::generate(csprng);
            let carol_signer = MemorySigner::generate(csprng);

            let alice = Individual::generate(&alice_signer, csprng).await.unwrap();
            let bob = Individual::generate(&bob_signer, csprng).await.unwrap();
            let carol = Individual::generate(&carol_signer, csprng).await.unwrap();

            // group -> alice
            let root_dlg: Arc<Signed<Delegation<MemorySigner, String>>> = Arc::new(
                group_signer
                    .try_sign_sync(Delegation {
                        delegate: alice.into(),
                        can: Access::Admin,
                        proof: None,
                        after_content: BTreeMap::new(),
                        after_revocations: vec![],
                    })
                    .unwrap(),
            );

            // alice -> bob
            let d_bob = Arc::new(
                alice_signer
                    .try_sign_sync(Delegation {
                        delegate: bob.into(),
                        can: Access::Edit,
                        proof: Some(root_dlg.dupe()),
                        after_content: BTreeMap::new(),
                        after_revocations: vec![],
                    })
                    .unwrap(),
            );

            // alice -> carol
            let d_carol = Arc::new(
                alice_signer
                    .try_sign_sync(Delegation {
                        delegate: carol.into(),
                        can: Access::Edit,
                        proof: Some(root_dlg.dupe()),
                        after_content: BTreeMap::new(),
                        after_revocations: vec![],
                    })
                    .unwrap(),
            );

            // bob revokes carol's delegation
            let r1 = Arc::new(
                bob_signer
                    .try_sign_sync(Revocation {
                        revoke: d_carol.dupe(),
                        proof: Some(d_bob.dupe()),
                        after_content: BTreeMap::new(),
                    })
                    .unwrap(),
            );

            // carol revokes bob's delegation
            let r2 = Arc::new(
                carol_signer
                    .try_sign_sync(Revocation {
                        revoke: d_bob.dupe(),
                        proof: Some(d_carol.dupe()),
                        after_content: BTreeMap::new(),
                    })
                    .unwrap(),
            );

            let r1_op: MembershipOperation<MemorySigner, String> = r1.dupe().into();
            let r2_op: MembershipOperation<MemorySigner, String> = r2.dupe().into();

            // Both revocations as heads
            let dlg_heads = DelegationStore::new();
            let rev_heads = RevocationStore::from_iter_direct([r1.dupe(), r2.dupe()]);

            let observed = MembershipOperation::reverse_topsort(&dlg_heads, &rev_heads);

            // Should contain all 5 ops
            assert_eq!(observed.len(), 5);

            let pos_r1 = observed.iter().position(|(_, op)| *op == r1_op).unwrap();
            let pos_r2 = observed.iter().position(|(_, op)| *op == r2_op).unwrap();

            // Both revocations should come before their dependencies
            let root_op: MembershipOperation<MemorySigner, String> = root_dlg.into();
            let d_bob_op: MembershipOperation<MemorySigner, String> = d_bob.into();
            let d_carol_op: MembershipOperation<MemorySigner, String> = d_carol.into();

            let pos_root = observed.iter().position(|(_, op)| *op == root_op).unwrap();
            let pos_d_bob = observed.iter().position(|(_, op)| *op == d_bob_op).unwrap();
            let pos_d_carol = observed
                .iter()
                .position(|(_, op)| *op == d_carol_op)
                .unwrap();

            // higher index is processed first (popped first)
            // Dependencies should be at higher indices
            assert!(pos_root > pos_d_bob);
            assert!(pos_root > pos_d_carol);
            assert!(pos_d_bob > pos_r1);
            assert!(pos_d_carol > pos_r2);

            // The two revocations should have a deterministic relative order.
            // Run the topsort again with reversed input order to verify stability.
            let observed2 = MembershipOperation::reverse_topsort(
                &DelegationStore::new(),
                &RevocationStore::from_iter_direct([r2.dupe(), r1.dupe()]),
            );

            let pos_r1_2 = observed2.iter().position(|(_, op)| *op == r1_op).unwrap();
            let pos_r2_2 = observed2.iter().position(|(_, op)| *op == r2_op).unwrap();

            // Same relative order regardless of input order
            assert_eq!(pos_r1 < pos_r2, pos_r1_2 < pos_r2_2);
        }

        /// An isolated root delegation (no parents and not referenced by anything)
        /// should appear in leftovers.
        #[tokio::test]
        async fn test_isolated_root_in_leftovers() {
            test_utils::init_logging();
            let csprng = &mut rand::thread_rng();

            let alice_dlg = add_alice(csprng).await;
            let bob_dlg = add_bob(csprng).await;

            let dlg_heads = DelegationStore::from_iter_direct([alice_dlg.dupe(), bob_dlg.dupe()]);
            let rev_heads = RevocationStore::new();

            let observed = MembershipOperation::reverse_topsort(&dlg_heads, &rev_heads);
            assert_eq!(observed.len(), 2);

            let group_signer2 = MemorySigner::generate(csprng);
            let dan_signer = MemorySigner::generate(csprng);
            let dan = Individual::generate(&dan_signer, csprng).await.unwrap();

            let isolated_dlg: Arc<Signed<Delegation<MemorySigner, String>>> = Arc::new(
                group_signer2
                    .try_sign_sync(Delegation {
                        delegate: dan.into(),
                        can: Access::Admin,
                        proof: None,
                        after_content: BTreeMap::new(),
                        after_revocations: vec![],
                    })
                    .unwrap(),
            );

            // Two unrelated root delegations. Both are isolated
            let dlg_heads2 =
                DelegationStore::from_iter_direct([alice_dlg.dupe(), isolated_dlg.dupe()]);

            let observed2 =
                MembershipOperation::reverse_topsort(&dlg_heads2, &RevocationStore::new());
            assert_eq!(observed2.len(), 2);

            // Both should be present
            let alice_op: MembershipOperation<MemorySigner, String> = alice_dlg.into();
            let isolated_op: MembershipOperation<MemorySigner, String> = isolated_dlg.into();
            assert!(observed2.iter().any(|(_, op)| *op == alice_op));
            assert!(observed2.iter().any(|(_, op)| *op == isolated_op));
        }

        /// Three-way concurrent revocation: Alice, Bob, Carol each
        /// revoke the next person's delegation. All three should
        /// appear in separate topsort levels, ordered by delegation
        /// chain length.
        #[tokio::test]
        async fn test_three_concurrent_revocations() -> TestResult {
            test_utils::init_logging();
            let csprng = &mut rand::thread_rng();

            let group_signer = MemorySigner::generate(csprng);
            let alice_signer = MemorySigner::generate(csprng);
            let bob_signer = MemorySigner::generate(csprng);
            let carol_signer = MemorySigner::generate(csprng);

            let alice = Individual::generate(&alice_signer, csprng).await?;
            let bob = Individual::generate(&bob_signer, csprng).await?;
            let carol = Individual::generate(&carol_signer, csprng).await?;

            let root_dlg: Arc<Signed<Delegation<MemorySigner, String>>> =
                Arc::new(group_signer.try_sign_sync(Delegation {
                    delegate: alice.into(),
                    can: Access::Admin,
                    proof: None,
                    after_content: BTreeMap::new(),
                    after_revocations: vec![],
                })?);

            let d_bob = Arc::new(alice_signer.try_sign_sync(Delegation {
                delegate: bob.into(),
                can: Access::Edit,
                proof: Some(root_dlg.dupe()),
                after_content: BTreeMap::new(),
                after_revocations: vec![],
            })?);

            let d_carol = Arc::new(alice_signer.try_sign_sync(Delegation {
                delegate: carol.into(),
                can: Access::Edit,
                proof: Some(root_dlg.dupe()),
                after_content: BTreeMap::new(),
                after_revocations: vec![],
            })?);

            let r_ab = Arc::new(alice_signer.try_sign_sync(Revocation {
                revoke: d_bob.dupe(),
                proof: Some(root_dlg.dupe()),
                after_content: BTreeMap::new(),
            })?);

            let r_bc = Arc::new(bob_signer.try_sign_sync(Revocation {
                revoke: d_carol.dupe(),
                proof: Some(d_bob.dupe()),
                after_content: BTreeMap::new(),
            })?);

            let r_ca = Arc::new(carol_signer.try_sign_sync(Revocation {
                revoke: d_bob.dupe(),
                proof: Some(d_carol.dupe()),
                after_content: BTreeMap::new(),
            })?);

            let r_ab_op: MembershipOperation<MemorySigner, String> = r_ab.dupe().into();
            let r_bc_op: MembershipOperation<MemorySigner, String> = r_bc.dupe().into();
            let r_ca_op: MembershipOperation<MemorySigner, String> = r_ca.dupe().into();

            let rev_heads =
                RevocationStore::from_iter_direct([r_ab.dupe(), r_bc.dupe(), r_ca.dupe()]);
            let observed =
                MembershipOperation::reverse_topsort(&DelegationStore::new(), &rev_heads);

            assert!(observed.iter().any(|(_, op)| *op == r_ab_op));
            assert!(observed.iter().any(|(_, op)| *op == r_bc_op));
            assert!(observed.iter().any(|(_, op)| *op == r_ca_op));

            let rev_heads2 =
                RevocationStore::from_iter_direct([r_ca.dupe(), r_ab.dupe(), r_bc.dupe()]);
            let observed2 =
                MembershipOperation::reverse_topsort(&DelegationStore::new(), &rev_heads2);
            assert_eq!(observed.len(), observed2.len());
            for (i, ((d1, op1), (d2, op2))) in observed.iter().zip(observed2.iter()).enumerate() {
                assert_eq!(d1, d2, "digest mismatch at position {i}");
                assert_eq!(op1, op2, "op mismatch at position {i}");
            }

            Ok(())
        }

        /// Concurrent revocations with different delegation chain
        /// lengths must be ordered by chain length (shorter first in
        /// drain, meaning shorter chain's revocation is at a lower
        /// index in the Reversed vec).
        ///
        /// ```text
        ///           group
        ///             |
        ///          root_dlg (-> alice)
        ///           /    \
        ///      d_bob     d_carol
        ///                    \
        ///                   d_dave
        ///
        ///  r_short: alice revokes d_bob  (proof: root_dlg)
        ///           distance_to_root = max(dist(d_bob), dist(root_dlg)) + 1
        ///                            = max(2, 1) + 1 = 3
        ///  r_long:  carol revokes d_bob  (proof: d_dave)
        ///           distance_to_root = max(dist(d_bob), dist(d_dave)) + 1
        ///                            = max(2, 3) + 1 = 4
        /// ```
        ///
        /// Both revocations target d_bob but `r_long` goes through a
        /// deeper proof chain (d_dave at depth 3 vs root_dlg at
        /// depth 1), giving it a greater distance to root.
        #[tokio::test]
        async fn test_concurrent_revocations_ordered_by_chain_length() -> TestResult {
            test_utils::init_logging();
            let csprng = &mut rand::thread_rng();

            let group_signer = MemorySigner::generate(csprng);
            let alice_signer = MemorySigner::generate(csprng);
            let bob_signer = MemorySigner::generate(csprng);
            let carol_signer = MemorySigner::generate(csprng);
            let dave_signer = MemorySigner::generate(csprng);

            let alice = Individual::generate(&alice_signer, csprng).await?;
            let bob = Individual::generate(&bob_signer, csprng).await?;
            let carol = Individual::generate(&carol_signer, csprng).await?;
            let dave = Individual::generate(&dave_signer, csprng).await?;

            let root_dlg: Arc<Signed<Delegation<MemorySigner, String>>> =
                Arc::new(group_signer.try_sign_sync(Delegation {
                    delegate: alice.into(),
                    can: Access::Admin,
                    proof: None,
                    after_content: BTreeMap::new(),
                    after_revocations: vec![],
                })?);

            let d_bob = Arc::new(alice_signer.try_sign_sync(Delegation {
                delegate: bob.into(),
                can: Access::Admin,
                proof: Some(root_dlg.dupe()),
                after_content: BTreeMap::new(),
                after_revocations: vec![],
            })?);

            let d_carol = Arc::new(alice_signer.try_sign_sync(Delegation {
                delegate: carol.into(),
                can: Access::Admin,
                proof: Some(root_dlg.dupe()),
                after_content: BTreeMap::new(),
                after_revocations: vec![],
            })?);

            // carol -> dave (chain length 3)
            let d_dave = Arc::new(carol_signer.try_sign_sync(Delegation {
                delegate: dave.into(),
                can: Access::Admin,
                proof: Some(d_carol.dupe()),
                after_content: BTreeMap::new(),
                after_revocations: vec![],
            })?);

            // Alice revokes d_bob (proof: root_dlg → distance_to_root 3)
            let r_short = Arc::new(alice_signer.try_sign_sync(Revocation {
                revoke: d_bob.dupe(),
                proof: Some(root_dlg.dupe()),
                after_content: BTreeMap::new(),
            })?);

            // Dave revokes d_bob (proof: d_dave → distance_to_root 4)
            let r_long = Arc::new(dave_signer.try_sign_sync(Revocation {
                revoke: d_bob.dupe(),
                proof: Some(d_dave.dupe()),
                after_content: BTreeMap::new(),
            })?);

            let r_short_op: MembershipOperation<MemorySigner, String> = r_short.dupe().into();
            let r_long_op: MembershipOperation<MemorySigner, String> = r_long.dupe().into();

            let rev_heads = RevocationStore::from_iter_direct([r_short.dupe(), r_long.dupe()]);
            let observed =
                MembershipOperation::reverse_topsort(&DelegationStore::new(), &rev_heads);

            let pos_short = observed
                .iter()
                .position(|(_, op)| *op == r_short_op)
                .expect("short-chain revocation should be in output");
            let pos_long = observed
                .iter()
                .position(|(_, op)| *op == r_long_op)
                .expect("long-chain revocation should be in output");

            // Shorter distance_to_root → sorted first → emitted first →
            // lower index in the Reversed vec.
            assert!(
                pos_short < pos_long,
                "short-chain revocation (pos {pos_short}) should come before \
                 long-chain revocation (pos {pos_long}) in the Reversed vec"
            );

            Ok(())
        }

        /// Property: reverse_topsort output is stable regardless of
        /// the insertion order of delegation and revocation heads.
        #[tokio::test]
        async fn test_reverse_topsort_stability_under_input_permutation() -> TestResult {
            test_utils::init_logging();
            let csprng = &mut rand::thread_rng();

            let group_signer = MemorySigner::generate(csprng);
            let alice_signer = MemorySigner::generate(csprng);
            let bob_signer = MemorySigner::generate(csprng);
            let carol_signer = MemorySigner::generate(csprng);
            let dan_signer = MemorySigner::generate(csprng);

            let alice = Individual::generate(&alice_signer, csprng).await?;
            let bob = Individual::generate(&bob_signer, csprng).await?;
            let carol = Individual::generate(&carol_signer, csprng).await?;
            let dan = Individual::generate(&dan_signer, csprng).await?;

            let root_dlg: Arc<Signed<Delegation<MemorySigner, String>>> =
                Arc::new(group_signer.try_sign_sync(Delegation {
                    delegate: alice.into(),
                    can: Access::Admin,
                    proof: None,
                    after_content: BTreeMap::new(),
                    after_revocations: vec![],
                })?);

            let d_bob = Arc::new(alice_signer.try_sign_sync(Delegation {
                delegate: bob.into(),
                can: Access::Edit,
                proof: Some(root_dlg.dupe()),
                after_content: BTreeMap::new(),
                after_revocations: vec![],
            })?);

            let d_carol = Arc::new(alice_signer.try_sign_sync(Delegation {
                delegate: carol.into(),
                can: Access::Edit,
                proof: Some(root_dlg.dupe()),
                after_content: BTreeMap::new(),
                after_revocations: vec![],
            })?);

            let d_dan = Arc::new(bob_signer.try_sign_sync(Delegation {
                delegate: dan.into(),
                can: Access::Relay,
                proof: Some(d_bob.dupe()),
                after_content: BTreeMap::new(),
                after_revocations: vec![],
            })?);

            // Bob revokes Carol
            let r1 = Arc::new(bob_signer.try_sign_sync(Revocation {
                revoke: d_carol.dupe(),
                proof: Some(d_bob.dupe()),
                after_content: BTreeMap::new(),
            })?);

            // Carol revokes Bob
            let r2 = Arc::new(carol_signer.try_sign_sync(Revocation {
                revoke: d_bob.dupe(),
                proof: Some(d_carol.dupe()),
                after_content: BTreeMap::new(),
            })?);

            // Permutation 1: heads in one order
            let dlg_heads_1 = DelegationStore::from_iter_direct([d_dan.dupe()]);
            let rev_heads_1 = RevocationStore::from_iter_direct([r1.dupe(), r2.dupe()]);
            let result_1 = MembershipOperation::reverse_topsort(&dlg_heads_1, &rev_heads_1);

            // Permutation 2: reversed revocation head order
            let dlg_heads_2 = DelegationStore::from_iter_direct([d_dan.dupe()]);
            let rev_heads_2 = RevocationStore::from_iter_direct([r2.dupe(), r1.dupe()]);
            let result_2 = MembershipOperation::reverse_topsort(&dlg_heads_2, &rev_heads_2);

            assert_eq!(result_1.len(), result_2.len(), "different number of ops");
            for (i, ((d1, op1), (d2, op2))) in result_1.iter().zip(result_2.iter()).enumerate() {
                assert_eq!(d1, d2, "digest mismatch at position {i}");
                assert_eq!(op1, op2, "op mismatch at position {i}");
            }

            Ok(())
        }

        /// Property: every op in the Reversed output has all its
        /// after_auth parents at higher indices (processed first by
        /// rebuild via pop).
        #[tokio::test]
        async fn test_causal_ordering_invariant() {
            test_utils::init_logging();
            let csprng = &mut rand::thread_rng();

            // Use the full fixture graph from the module-level diagram.
            // The add_* helpers are called for side effects (building
            // the parent chain); only dan and erin heads are used.
            let _alice_dlg = add_alice(csprng).await;
            let _bob_dlg = add_bob(csprng).await;
            let _carol_dlg = add_carol(csprng).await;
            let dan_dlg = add_dan(csprng).await;
            let erin_dlg = add_erin(csprng).await;
            let remove_carol_rev = remove_carol(csprng).await;
            let remove_dan_rev = remove_dan(csprng).await;

            let dlg_heads = DelegationStore::from_iter_direct([dan_dlg.dupe(), erin_dlg.dupe()]);
            let rev_heads =
                RevocationStore::from_iter_direct([remove_carol_rev.dupe(), remove_dan_rev.dupe()]);
            let observed = MembershipOperation::reverse_topsort(&dlg_heads, &rev_heads);

            // Build a position map: digest -> index in Reversed vec
            let pos: std::collections::HashMap<_, _> = observed
                .iter()
                .enumerate()
                .map(|(i, (d, _))| (*d, i))
                .collect();

            // For every op, all its after_auth() parents must be at
            // higher indices (they're popped first by rebuild).
            for (digest, op) in observed.iter() {
                let my_pos = pos[digest];
                for parent in op.after_auth() {
                    let parent_digest = parent.digest();
                    if let Some(&parent_pos) = pos.get(&parent_digest) {
                        assert!(
                            parent_pos > my_pos,
                            "op at pos {my_pos} (digest {digest:?}) has parent at pos \
                             {parent_pos} (digest {parent_digest:?}), but parent should \
                             be at a higher index"
                        );
                    }
                }
            }
        }

        /// Deep chain of alternating delegate/revoke cycles: ensure
        /// the topsort terminates and produces the right number of ops.
        #[tokio::test]
        async fn test_deep_delegate_revoke_chain() -> TestResult {
            test_utils::init_logging();
            let csprng = &mut rand::thread_rng();

            let group_signer = MemorySigner::generate(csprng);
            let alice_signer = MemorySigner::generate(csprng);
            let bob_signer = MemorySigner::generate(csprng);

            let alice = Individual::generate(&alice_signer, csprng).await?;
            let bob = Individual::generate(&bob_signer, csprng).await?;

            let root_dlg: Arc<Signed<Delegation<MemorySigner, String>>> =
                Arc::new(group_signer.try_sign_sync(Delegation {
                    delegate: alice.clone().into(),
                    can: Access::Admin,
                    proof: None,
                    after_content: BTreeMap::new(),
                    after_revocations: vec![],
                })?);

            let depth = 10;
            let mut all_dlgs = vec![root_dlg.dupe()];
            let mut all_revs: Vec<Arc<Signed<Revocation<MemorySigner, String>>>> = vec![];
            let mut current_proof = root_dlg.dupe();

            for i in 0..depth {
                // Alternate delegating to bob and alice
                let (signer, delegate) = if i % 2 == 0 {
                    (&alice_signer, bob.clone().into())
                } else {
                    (&bob_signer, alice.clone().into())
                };

                let dlg = Arc::new(signer.try_sign_sync(Delegation {
                    delegate,
                    can: Access::Admin,
                    proof: Some(current_proof.dupe()),
                    after_content: BTreeMap::new(),
                    after_revocations: all_revs.last().map_or(vec![], |r| vec![r.dupe()]),
                })?);

                // Revoke previous delegation (if any)
                if i > 0 {
                    let rev = Arc::new(signer.try_sign_sync(Revocation {
                        revoke: all_dlgs.last().expect("non-empty dlg list").dupe(),
                        proof: Some(current_proof.dupe()),
                        after_content: BTreeMap::new(),
                    })?);
                    all_revs.push(rev);
                }

                current_proof = dlg.dupe();
                all_dlgs.push(dlg);
            }

            let expected_ops = all_dlgs.len() + all_revs.len();

            let dlg_heads = DelegationStore::from_iter_direct([all_dlgs
                .last()
                .expect("non-empty dlg list")
                .dupe()]);
            let rev_heads = if all_revs.is_empty() {
                RevocationStore::new()
            } else {
                RevocationStore::from_iter_direct([all_revs
                    .last()
                    .expect("non-empty rev list")
                    .dupe()])
            };
            let observed = MembershipOperation::reverse_topsort(&dlg_heads, &rev_heads);

            assert_eq!(
                observed.len(),
                expected_ops,
                "expected {expected_ops} ops for depth {depth}, got {}",
                observed.len()
            );

            // Verify causal ordering
            let pos: std::collections::HashMap<_, _> = observed
                .iter()
                .enumerate()
                .map(|(i, (d, _))| (*d, i))
                .collect();

            for (digest, op) in observed.iter() {
                for parent in op.after_auth() {
                    let parent_digest = parent.digest();
                    if let Some(&parent_pos) = pos.get(&parent_digest) {
                        assert!(
                            parent_pos > pos[digest],
                            "causal ordering violated at depth chain"
                        );
                    }
                }
            }

            Ok(())
        }

        /// Exhaustive revocation cycle permutation tests.
        ///
        /// For each cycle size (2, 3, 4), we construct a delegation
        /// graph with mutual revocations forming the cycle plus
        /// downstream delegations, bystanders, and an unrelated
        /// revocation. We then run `reverse_topsort` with every
        /// permutation of the revocation heads and assert the
        /// output is identical regardless of insertion order.
        mod revocation_cycles {
            use super::*;

            fn permutations<T: Clone>(items: &[T]) -> Vec<Vec<T>> {
                if items.len() <= 1 {
                    return vec![items.to_vec()];
                }
                let mut result = vec![];
                for (i, item) in items.iter().enumerate() {
                    let mut rest = items.to_vec();
                    rest.remove(i);
                    for mut perm in permutations(&rest) {
                        perm.insert(0, item.clone());
                        result.push(perm);
                    }
                }
                result
            }

            /// Assert two Reversed outputs are identical element-by-element.
            #[allow(clippy::type_complexity)]
            fn assert_same_output<
                S: AsyncSigner<F>,
                T: ContentRef,
                L: MembershipListener<F, S, T>,
            >(
                label: &str,
                expected: &Reversed<(
                    Digest<MembershipOperation<F, S, T, L>>,
                    MembershipOperation<F, S, T, L>,
                )>,
                actual: &Reversed<(
                    Digest<MembershipOperation<F, S, T, L>>,
                    MembershipOperation<F, S, T, L>,
                )>,
            ) {
                assert_eq!(
                    expected.len(),
                    actual.len(),
                    "{label}: length mismatch ({} vs {})",
                    expected.len(),
                    actual.len(),
                );
                for (i, ((d1, op1), (d2, op2))) in expected.iter().zip(actual.iter()).enumerate() {
                    assert_eq!(d1, d2, "{label}: digest mismatch at position {i}");
                    assert_eq!(op1, op2, "{label}: op mismatch at position {i}");
                }
            }

            /// 2-cycle: A revokes B, B revokes A.
            ///
            /// Cycle members also have downstream delegations (bob
            /// delegates to eve, carol delegates to frank) and there
            /// is an unrelated revocation (alice revokes d_grace)
            /// that should be unaffected by cycle-breaking.
            ///
            /// ```text
            ///                   group
            ///                     |
            ///                 root_dlg (-> alice, Admin)
            ///              /    |      \        \
            ///         d_bob  d_carol  d_grace  d_heidi (bystander)
            ///          |       |
            ///        d_eve   d_frank
            ///
            ///  Cycle revocations:
            ///    r_ab: bob   revokes d_carol (proof: d_bob)
            ///    r_ba: carol revokes d_bob   (proof: d_carol)
            ///
            ///  Unrelated revocation:
            ///    r_grace: alice revokes d_grace (proof: root_dlg)
            /// ```
            ///
            /// Exhaustively tests all 2! = 2 permutations of cycle
            /// revocation head insertion order (unrelated heads fixed).
            #[tokio::test]
            async fn test_2_cycle_all_permutations() -> TestResult {
                test_utils::init_logging();
                let csprng = &mut rand::thread_rng();

                let group_signer = MemorySigner::generate(csprng);
                let alice_signer = MemorySigner::generate(csprng);
                let bob_signer = MemorySigner::generate(csprng);
                let carol_signer = MemorySigner::generate(csprng);
                let eve_signer = MemorySigner::generate(csprng);
                let frank_signer = MemorySigner::generate(csprng);
                let grace_signer = MemorySigner::generate(csprng);
                let heidi_signer = MemorySigner::generate(csprng);

                let alice = Individual::generate(&alice_signer, csprng).await?;
                let bob = Individual::generate(&bob_signer, csprng).await?;
                let carol = Individual::generate(&carol_signer, csprng).await?;
                let eve = Individual::generate(&eve_signer, csprng).await?;
                let frank = Individual::generate(&frank_signer, csprng).await?;
                let grace = Individual::generate(&grace_signer, csprng).await?;
                let heidi = Individual::generate(&heidi_signer, csprng).await?;

                let root_dlg: Arc<Signed<Delegation<MemorySigner, String>>> =
                    Arc::new(group_signer.try_sign_sync(Delegation {
                        delegate: alice.into(),
                        can: Access::Admin,
                        proof: None,
                        after_content: BTreeMap::new(),
                        after_revocations: vec![],
                    })?);

                let d_bob = Arc::new(alice_signer.try_sign_sync(Delegation {
                    delegate: bob.into(),
                    can: Access::Admin,
                    proof: Some(root_dlg.dupe()),
                    after_content: BTreeMap::new(),
                    after_revocations: vec![],
                })?);

                let d_carol = Arc::new(alice_signer.try_sign_sync(Delegation {
                    delegate: carol.into(),
                    can: Access::Admin,
                    proof: Some(root_dlg.dupe()),
                    after_content: BTreeMap::new(),
                    after_revocations: vec![],
                })?);

                // Downstream of bob
                let d_eve = Arc::new(bob_signer.try_sign_sync(Delegation {
                    delegate: eve.into(),
                    can: Access::Edit,
                    proof: Some(d_bob.dupe()),
                    after_content: BTreeMap::new(),
                    after_revocations: vec![],
                })?);

                // Downstream of carol
                let d_frank = Arc::new(carol_signer.try_sign_sync(Delegation {
                    delegate: frank.into(),
                    can: Access::Edit,
                    proof: Some(d_carol.dupe()),
                    after_content: BTreeMap::new(),
                    after_revocations: vec![],
                })?);

                // Unrelated delegation + revocation target
                let d_grace = Arc::new(alice_signer.try_sign_sync(Delegation {
                    delegate: grace.into(),
                    can: Access::Edit,
                    proof: Some(root_dlg.dupe()),
                    after_content: BTreeMap::new(),
                    after_revocations: vec![],
                })?);

                // Bystander with no involvement
                let d_heidi = Arc::new(alice_signer.try_sign_sync(Delegation {
                    delegate: heidi.into(),
                    can: Access::Read,
                    proof: Some(root_dlg.dupe()),
                    after_content: BTreeMap::new(),
                    after_revocations: vec![],
                })?);

                // Cycle: bob <-> carol
                let r_ab = Arc::new(bob_signer.try_sign_sync(Revocation {
                    revoke: d_carol.dupe(),
                    proof: Some(d_bob.dupe()),
                    after_content: BTreeMap::new(),
                })?);

                let r_ba = Arc::new(carol_signer.try_sign_sync(Revocation {
                    revoke: d_bob.dupe(),
                    proof: Some(d_carol.dupe()),
                    after_content: BTreeMap::new(),
                })?);

                // Unrelated revocation
                let r_grace = Arc::new(alice_signer.try_sign_sync(Revocation {
                    revoke: d_grace.dupe(),
                    proof: Some(root_dlg.dupe()),
                    after_content: BTreeMap::new(),
                })?);

                let cycle_revs = [r_ab.dupe(), r_ba.dupe()];
                let dlg_heads = DelegationStore::from_iter_direct([
                    d_eve.dupe(),
                    d_frank.dupe(),
                    d_heidi.dupe(),
                ]);

                let perms = permutations(&cycle_revs);

                let reference = MembershipOperation::reverse_topsort(
                    &dlg_heads,
                    &RevocationStore::from_iter_direct(
                        perms[0]
                            .iter()
                            .map(|r| r.dupe())
                            .chain(std::iter::once(r_grace.dupe())),
                    ),
                );

                for (pi, perm) in perms.iter().enumerate() {
                    let rev_heads = RevocationStore::from_iter_direct(
                        perm.iter()
                            .map(|r| r.dupe())
                            .chain(std::iter::once(r_grace.dupe())),
                    );
                    let result = MembershipOperation::reverse_topsort(&dlg_heads, &rev_heads);
                    assert_same_output(&format!("2-cycle permutation {pi}"), &reference, &result);
                }

                Ok(())
            }

            /// 3-cycle: A revokes B, B revokes C, C revokes A.
            ///
            /// Cycle members have downstream delegations and there is
            /// an unrelated revocation outside the cycle.
            ///
            /// ```text
            ///                    group
            ///                      |
            ///                  root_dlg (-> alice, Admin)
            ///           /      |       |      \          \
            ///      d_bob   d_carol  d_dave  d_grace    d_heidi
            ///        |        |       |
            ///     d_eve    d_frank  d_ivan
            ///
            ///  Cycle revocations:
            ///    r_ab: bob   revokes d_carol (proof: d_bob)
            ///    r_bc: carol revokes d_dave  (proof: d_carol)
            ///    r_ca: dave  revokes d_bob   (proof: d_dave)
            ///
            ///  Unrelated revocation:
            ///    r_grace: alice revokes d_grace (proof: root_dlg)
            /// ```
            ///
            /// Exhaustively tests all 3! = 6 permutations.
            #[tokio::test]
            async fn test_3_cycle_all_permutations() -> TestResult {
                test_utils::init_logging();
                let csprng = &mut rand::thread_rng();

                let group_signer = MemorySigner::generate(csprng);
                let alice_signer = MemorySigner::generate(csprng);
                let bob_signer = MemorySigner::generate(csprng);
                let carol_signer = MemorySigner::generate(csprng);
                let dave_signer = MemorySigner::generate(csprng);
                let eve_signer = MemorySigner::generate(csprng);
                let frank_signer = MemorySigner::generate(csprng);
                let grace_signer = MemorySigner::generate(csprng);
                let heidi_signer = MemorySigner::generate(csprng);
                let ivan_signer = MemorySigner::generate(csprng);

                let alice = Individual::generate(&alice_signer, csprng).await?;
                let bob = Individual::generate(&bob_signer, csprng).await?;
                let carol = Individual::generate(&carol_signer, csprng).await?;
                let dave = Individual::generate(&dave_signer, csprng).await?;
                let eve = Individual::generate(&eve_signer, csprng).await?;
                let frank = Individual::generate(&frank_signer, csprng).await?;
                let grace = Individual::generate(&grace_signer, csprng).await?;
                let heidi = Individual::generate(&heidi_signer, csprng).await?;
                let ivan = Individual::generate(&ivan_signer, csprng).await?;

                let root_dlg: Arc<Signed<Delegation<MemorySigner, String>>> =
                    Arc::new(group_signer.try_sign_sync(Delegation {
                        delegate: alice.into(),
                        can: Access::Admin,
                        proof: None,
                        after_content: BTreeMap::new(),
                        after_revocations: vec![],
                    })?);

                let d_bob = Arc::new(alice_signer.try_sign_sync(Delegation {
                    delegate: bob.into(),
                    can: Access::Admin,
                    proof: Some(root_dlg.dupe()),
                    after_content: BTreeMap::new(),
                    after_revocations: vec![],
                })?);

                let d_carol = Arc::new(alice_signer.try_sign_sync(Delegation {
                    delegate: carol.into(),
                    can: Access::Admin,
                    proof: Some(root_dlg.dupe()),
                    after_content: BTreeMap::new(),
                    after_revocations: vec![],
                })?);

                let d_dave = Arc::new(alice_signer.try_sign_sync(Delegation {
                    delegate: dave.into(),
                    can: Access::Admin,
                    proof: Some(root_dlg.dupe()),
                    after_content: BTreeMap::new(),
                    after_revocations: vec![],
                })?);

                // Downstream delegations from cycle members
                let d_eve = Arc::new(bob_signer.try_sign_sync(Delegation {
                    delegate: eve.into(),
                    can: Access::Edit,
                    proof: Some(d_bob.dupe()),
                    after_content: BTreeMap::new(),
                    after_revocations: vec![],
                })?);

                let d_frank = Arc::new(carol_signer.try_sign_sync(Delegation {
                    delegate: frank.into(),
                    can: Access::Edit,
                    proof: Some(d_carol.dupe()),
                    after_content: BTreeMap::new(),
                    after_revocations: vec![],
                })?);

                let d_ivan = Arc::new(dave_signer.try_sign_sync(Delegation {
                    delegate: ivan.into(),
                    can: Access::Edit,
                    proof: Some(d_dave.dupe()),
                    after_content: BTreeMap::new(),
                    after_revocations: vec![],
                })?);

                // Unrelated delegation + revocation
                let d_grace = Arc::new(alice_signer.try_sign_sync(Delegation {
                    delegate: grace.into(),
                    can: Access::Edit,
                    proof: Some(root_dlg.dupe()),
                    after_content: BTreeMap::new(),
                    after_revocations: vec![],
                })?);

                let d_heidi = Arc::new(alice_signer.try_sign_sync(Delegation {
                    delegate: heidi.into(),
                    can: Access::Read,
                    proof: Some(root_dlg.dupe()),
                    after_content: BTreeMap::new(),
                    after_revocations: vec![],
                })?);

                // Cycle revocations
                let r_ab = Arc::new(bob_signer.try_sign_sync(Revocation {
                    revoke: d_carol.dupe(),
                    proof: Some(d_bob.dupe()),
                    after_content: BTreeMap::new(),
                })?);

                let r_bc = Arc::new(carol_signer.try_sign_sync(Revocation {
                    revoke: d_dave.dupe(),
                    proof: Some(d_carol.dupe()),
                    after_content: BTreeMap::new(),
                })?);

                let r_ca = Arc::new(dave_signer.try_sign_sync(Revocation {
                    revoke: d_bob.dupe(),
                    proof: Some(d_dave.dupe()),
                    after_content: BTreeMap::new(),
                })?);

                // Unrelated revocation
                let r_grace = Arc::new(alice_signer.try_sign_sync(Revocation {
                    revoke: d_grace.dupe(),
                    proof: Some(root_dlg.dupe()),
                    after_content: BTreeMap::new(),
                })?);

                let cycle_revs = [r_ab.dupe(), r_bc.dupe(), r_ca.dupe()];
                let dlg_heads = DelegationStore::from_iter_direct([
                    d_eve.dupe(),
                    d_frank.dupe(),
                    d_ivan.dupe(),
                    d_heidi.dupe(),
                ]);

                let perms = permutations(&cycle_revs);
                assert_eq!(perms.len(), 6, "expected 3! = 6 permutations");

                let reference = MembershipOperation::reverse_topsort(
                    &dlg_heads,
                    &RevocationStore::from_iter_direct(
                        perms[0]
                            .iter()
                            .map(|r| r.dupe())
                            .chain(std::iter::once(r_grace.dupe())),
                    ),
                );

                for (pi, perm) in perms.iter().enumerate() {
                    let rev_heads = RevocationStore::from_iter_direct(
                        perm.iter()
                            .map(|r| r.dupe())
                            .chain(std::iter::once(r_grace.dupe())),
                    );
                    let result = MembershipOperation::reverse_topsort(&dlg_heads, &rev_heads);
                    assert_same_output(&format!("3-cycle permutation {pi}"), &reference, &result);
                }

                Ok(())
            }

            /// 4-cycle: A→B→C→D→A, with downstream delegations from
            /// each cycle member and an unrelated revocation.
            ///
            /// ```text
            ///                        group
            ///                          |
            ///                      root_dlg (-> alice, Admin)
            ///            /      |       |       |      \       \
            ///       d_bob   d_carol  d_dave  d_frank  d_grace d_heidi
            ///         |        |       |       |
            ///       d_eve   d_ivan  d_judy  d_karl
            ///
            ///  Cycle revocations:
            ///    r_ab: bob   revokes d_carol (proof: d_bob)
            ///    r_bc: carol revokes d_dave  (proof: d_carol)
            ///    r_cd: dave  revokes d_frank (proof: d_dave)
            ///    r_da: frank revokes d_bob   (proof: d_frank)
            ///
            ///  Unrelated revocation:
            ///    r_grace: alice revokes d_grace (proof: root_dlg)
            /// ```
            ///
            /// Exhaustively tests all 4! = 24 permutations.
            #[tokio::test]
            async fn test_4_cycle_all_permutations() -> TestResult {
                test_utils::init_logging();
                let csprng = &mut rand::thread_rng();

                let group_signer = MemorySigner::generate(csprng);
                let alice_signer = MemorySigner::generate(csprng);
                let bob_signer = MemorySigner::generate(csprng);
                let carol_signer = MemorySigner::generate(csprng);
                let dave_signer = MemorySigner::generate(csprng);
                let eve_signer = MemorySigner::generate(csprng);
                let frank_signer = MemorySigner::generate(csprng);
                let grace_signer = MemorySigner::generate(csprng);
                let heidi_signer = MemorySigner::generate(csprng);
                let ivan_signer = MemorySigner::generate(csprng);
                let judy_signer = MemorySigner::generate(csprng);
                let karl_signer = MemorySigner::generate(csprng);

                let alice = Individual::generate(&alice_signer, csprng).await?;
                let bob = Individual::generate(&bob_signer, csprng).await?;
                let carol = Individual::generate(&carol_signer, csprng).await?;
                let dave = Individual::generate(&dave_signer, csprng).await?;
                let eve = Individual::generate(&eve_signer, csprng).await?;
                let frank = Individual::generate(&frank_signer, csprng).await?;
                let grace = Individual::generate(&grace_signer, csprng).await?;
                let heidi = Individual::generate(&heidi_signer, csprng).await?;
                let ivan = Individual::generate(&ivan_signer, csprng).await?;
                let judy = Individual::generate(&judy_signer, csprng).await?;
                let karl = Individual::generate(&karl_signer, csprng).await?;

                let root_dlg: Arc<Signed<Delegation<MemorySigner, String>>> =
                    Arc::new(group_signer.try_sign_sync(Delegation {
                        delegate: alice.into(),
                        can: Access::Admin,
                        proof: None,
                        after_content: BTreeMap::new(),
                        after_revocations: vec![],
                    })?);

                // Cycle members
                let d_bob = Arc::new(alice_signer.try_sign_sync(Delegation {
                    delegate: bob.into(),
                    can: Access::Admin,
                    proof: Some(root_dlg.dupe()),
                    after_content: BTreeMap::new(),
                    after_revocations: vec![],
                })?);

                let d_carol = Arc::new(alice_signer.try_sign_sync(Delegation {
                    delegate: carol.into(),
                    can: Access::Admin,
                    proof: Some(root_dlg.dupe()),
                    after_content: BTreeMap::new(),
                    after_revocations: vec![],
                })?);

                let d_dave = Arc::new(alice_signer.try_sign_sync(Delegation {
                    delegate: dave.into(),
                    can: Access::Admin,
                    proof: Some(root_dlg.dupe()),
                    after_content: BTreeMap::new(),
                    after_revocations: vec![],
                })?);

                let d_frank = Arc::new(alice_signer.try_sign_sync(Delegation {
                    delegate: frank.into(),
                    can: Access::Admin,
                    proof: Some(root_dlg.dupe()),
                    after_content: BTreeMap::new(),
                    after_revocations: vec![],
                })?);

                // Downstream from each cycle member
                let d_eve = Arc::new(bob_signer.try_sign_sync(Delegation {
                    delegate: eve.into(),
                    can: Access::Edit,
                    proof: Some(d_bob.dupe()),
                    after_content: BTreeMap::new(),
                    after_revocations: vec![],
                })?);

                let d_ivan = Arc::new(carol_signer.try_sign_sync(Delegation {
                    delegate: ivan.into(),
                    can: Access::Edit,
                    proof: Some(d_carol.dupe()),
                    after_content: BTreeMap::new(),
                    after_revocations: vec![],
                })?);

                let d_judy = Arc::new(dave_signer.try_sign_sync(Delegation {
                    delegate: judy.into(),
                    can: Access::Edit,
                    proof: Some(d_dave.dupe()),
                    after_content: BTreeMap::new(),
                    after_revocations: vec![],
                })?);

                let d_karl = Arc::new(frank_signer.try_sign_sync(Delegation {
                    delegate: karl.into(),
                    can: Access::Edit,
                    proof: Some(d_frank.dupe()),
                    after_content: BTreeMap::new(),
                    after_revocations: vec![],
                })?);

                // Unrelated delegation + revocation
                let d_grace = Arc::new(alice_signer.try_sign_sync(Delegation {
                    delegate: grace.into(),
                    can: Access::Edit,
                    proof: Some(root_dlg.dupe()),
                    after_content: BTreeMap::new(),
                    after_revocations: vec![],
                })?);

                let d_heidi = Arc::new(alice_signer.try_sign_sync(Delegation {
                    delegate: heidi.into(),
                    can: Access::Read,
                    proof: Some(root_dlg.dupe()),
                    after_content: BTreeMap::new(),
                    after_revocations: vec![],
                })?);

                // Cycle revocations
                let r_ab = Arc::new(bob_signer.try_sign_sync(Revocation {
                    revoke: d_carol.dupe(),
                    proof: Some(d_bob.dupe()),
                    after_content: BTreeMap::new(),
                })?);

                let r_bc = Arc::new(carol_signer.try_sign_sync(Revocation {
                    revoke: d_dave.dupe(),
                    proof: Some(d_carol.dupe()),
                    after_content: BTreeMap::new(),
                })?);

                let r_cd = Arc::new(dave_signer.try_sign_sync(Revocation {
                    revoke: d_frank.dupe(),
                    proof: Some(d_dave.dupe()),
                    after_content: BTreeMap::new(),
                })?);

                let r_da = Arc::new(frank_signer.try_sign_sync(Revocation {
                    revoke: d_bob.dupe(),
                    proof: Some(d_frank.dupe()),
                    after_content: BTreeMap::new(),
                })?);

                // Unrelated revocation
                let r_grace = Arc::new(alice_signer.try_sign_sync(Revocation {
                    revoke: d_grace.dupe(),
                    proof: Some(root_dlg.dupe()),
                    after_content: BTreeMap::new(),
                })?);

                let cycle_revs = [r_ab.dupe(), r_bc.dupe(), r_cd.dupe(), r_da.dupe()];
                let dlg_heads = DelegationStore::from_iter_direct([
                    d_eve.dupe(),
                    d_ivan.dupe(),
                    d_judy.dupe(),
                    d_karl.dupe(),
                    d_heidi.dupe(),
                ]);

                let perms = permutations(&cycle_revs);
                assert_eq!(perms.len(), 24, "expected 4! = 24 permutations");

                let reference = MembershipOperation::reverse_topsort(
                    &dlg_heads,
                    &RevocationStore::from_iter_direct(
                        perms[0]
                            .iter()
                            .map(|r| r.dupe())
                            .chain(std::iter::once(r_grace.dupe())),
                    ),
                );

                for (pi, perm) in perms.iter().enumerate() {
                    let rev_heads = RevocationStore::from_iter_direct(
                        perm.iter()
                            .map(|r| r.dupe())
                            .chain(std::iter::once(r_grace.dupe())),
                    );
                    let result = MembershipOperation::reverse_topsort(&dlg_heads, &rev_heads);
                    assert_same_output(&format!("4-cycle permutation {pi}"), &reference, &result);
                }

                Ok(())
            }
        }
    }
}
