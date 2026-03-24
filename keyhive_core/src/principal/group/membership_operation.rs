use super::{
    delegation::{Delegation, StaticDelegation},
    dependencies::Dependencies,
    revocation::{Revocation, StaticRevocation},
};
use crate::{
    crypto::signed_ext::SignedSubjectId,
    listener::{membership::MembershipListener, no_listener::NoListener},
    principal::{document::id::DocumentId, identifier::Identifier},
    reversed::Reversed,
    store::{delegation::DelegationStore, revocation::RevocationStore},
    util::content_addressed_map::CaMap,
};
use derive_more::{From, Into};
use derive_where::derive_where;
use dupe::Dupe;
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
    S: AsyncSigner,
    T: ContentRef = [u8; 32],
    L: MembershipListener<S, T> = NoListener,
> {
    Delegation(Arc<Signed<Delegation<S, T, L>>>),
    Revocation(Arc<Signed<Revocation<S, T, L>>>),
}

impl<S: AsyncSigner, T: ContentRef, L: MembershipListener<S, T>> std::hash::Hash
    for MembershipOperation<S, T, L>
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

impl<S: AsyncSigner, T: ContentRef, L: MembershipListener<S, T>> PartialEq
    for MembershipOperation<S, T, L>
{
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (MembershipOperation::Delegation(d1), MembershipOperation::Delegation(d2)) => d1 == d2,
            (MembershipOperation::Revocation(r1), MembershipOperation::Revocation(r2)) => r1 == r2,
            _ => false,
        }
    }
}

impl<S: AsyncSigner, T: ContentRef + Serialize, L: MembershipListener<S, T>> Serialize
    for MembershipOperation<S, T, L>
{
    fn serialize<Z: serde::Serializer>(&self, serializer: Z) -> Result<Z::Ok, Z::Error> {
        match self {
            MembershipOperation::Delegation(delegation) => delegation.serialize(serializer),
            MembershipOperation::Revocation(revocation) => revocation.serialize(serializer),
        }
    }
}

impl<S: AsyncSigner, T: ContentRef, L: MembershipListener<S, T>> MembershipOperation<S, T, L> {
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
    pub fn digest(&self) -> Digest<MembershipOperation<S, T, L>> {
        match self {
            MembershipOperation::Delegation(delegation) => delegation.digest().coerce(),
            MembershipOperation::Revocation(revocation) => revocation.digest().coerce(),
        }
    }

    pub fn is_revocation(&self) -> bool {
        !self.is_delegation()
    }

    pub fn after_auth(&self) -> Vec<MembershipOperation<S, T, L>> {
        let deps = self.after();
        deps.delegations
            .into_iter()
            .map(|d| d.into())
            .chain(deps.revocations.into_iter().map(|r| r.into()))
            .collect()
    }

    pub fn after(&self) -> Dependencies<'_, S, T, L> {
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

    pub fn ancestors(&self) -> (CaMap<MembershipOperation<S, T, L>>, usize) {
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
    /// drains level by level. Concurrent revocations are forced into
    /// separate levels ordered by `(longest_path, digest)` so that
    /// [`Group::rebuild`] processes them sequentially with correct
    /// cascade semantics.
    #[allow(clippy::type_complexity)] // Clippy doesn't like the returned pair
    #[instrument(skip_all)]
    pub fn reverse_topsort(
        delegation_heads: &DelegationStore<S, T, L>,
        revocation_heads: &RevocationStore<S, T, L>,
    ) -> Reversed<(
        Digest<MembershipOperation<S, T, L>>,
        MembershipOperation<S, T, L>,
    )> {
        // NOTE: BTreeMap to get deterministic order
        let mut all_ops: BTreeMap<
            Digest<MembershipOperation<S, T, L>>,
            (
                MembershipOperation<S, T, L>,
                Vec<Digest<MembershipOperation<S, T, L>>>,
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
        let mut revoked_dependencies: HashMap<Key, Digest<MembershipOperation<S, T, L>>> =
            HashMap::new();

        let mut explore: Vec<MembershipOperation<S, T, L>> = vec![];

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

        // ── Compute longest_path bottom-up (Kahn's algorithm) ─────
        //
        // longest_path(node) = 1 + max(longest_path(parent) for parent in parents)
        // Root nodes (no parents in all_ops) have longest_path = 1.
        //
        // Computed before the main topsort so the values are available
        // when we need to force ordering between concurrent revocations.

        let mut longest_paths: HashMap<Digest<MembershipOperation<S, T, L>>, usize> =
            HashMap::new();
        {
            // Reverse index: parent_digest → children that list it as a parent
            let mut children_of: HashMap<
                Digest<MembershipOperation<S, T, L>>,
                Vec<Digest<MembershipOperation<S, T, L>>>,
            > = HashMap::new();
            // parent_remaining[child] = # of unprocessed parents
            let mut parent_remaining: HashMap<Digest<MembershipOperation<S, T, L>>, usize> =
                HashMap::new();

            for (digest, (_, parents)) in &all_ops {
                let n_parents = parents.iter().filter(|p| all_ops.contains_key(p)).count();
                parent_remaining.insert(*digest, n_parents);
                for p in parents {
                    if all_ops.contains_key(p) {
                        children_of.entry(*p).or_default().push(*digest);
                    }
                }
            }

            let mut ready: Vec<Digest<MembershipOperation<S, T, L>>> = parent_remaining
                .iter()
                .filter(|(_, &cnt)| cnt == 0)
                .map(|(d, _)| *d)
                .collect();
            ready.sort(); // deterministic processing order

            while let Some(digest) = ready.pop() {
                let lp = all_ops
                    .get(&digest)
                    .map(|(_, parents)| {
                        parents
                            .iter()
                            .filter_map(|pd| longest_paths.get(pd))
                            .max()
                            .copied()
                            .unwrap_or(0)
                            + 1
                    })
                    .unwrap_or(1);
                longest_paths.insert(digest, lp);

                if let Some(children) = children_of.get(&digest) {
                    for child in children {
                        if let Some(rem) = parent_remaining.get_mut(child) {
                            *rem = rem.saturating_sub(1);
                            if *rem == 0 {
                                ready.push(*child);
                            }
                        }
                    }
                }
            }
        }

        // ── Build topsort with structural + revocation edges ────────

        type TsKey<'a, S, T, L> = (
            Digest<MembershipOperation<S, T, L>>,
            &'a MembershipOperation<S, T, L>,
        );

        let mut adjacencies: crate::util::topsort::TopologicalSort<TsKey<'_, S, T, L>> =
            crate::util::topsort::TopologicalSort::new();

        // Reverse index: for each op, which ops list it as a parent.
        // Used when re-inserting deferred revocations to restore their
        // outgoing edges.
        let mut successors_of: HashMap<
            Digest<MembershipOperation<S, T, L>>,
            Vec<Digest<MembershipOperation<S, T, L>>>,
        > = HashMap::new();

        for (digest, (op, parent_digests)) in all_ops.iter() {
            adjacencies.add_node((*digest, op));

            for parent_digest in parent_digests {
                if let Some((parent_op, _)) = all_ops.get(parent_digest) {
                    // "child before parent" in drain order
                    adjacencies.add_dependency((*digest, op), (*parent_digest, parent_op));
                    // child (digest) is a predecessor of parent — so
                    // parent is a successor of child.
                    successors_of
                        .entry(*digest)
                        .or_default()
                        .push(*parent_digest);
                }
            }

            // If this delegation's proof was revoked, add an edge to the revocation
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

        // ── Drain, forcing concurrent revocations into separate levels ──
        //
        // Each pop_all() returns all nodes with zero in-degree
        // (concurrent frontier). Non-revocations are emitted
        // immediately. When multiple revocations appear in the same
        // batch, they are concurrent and must be forced into separate
        // levels ordered by delegation chain length (longest_path,
        // with digest as tie-breaker): we emit only the first and
        // re-insert the rest — restoring their outgoing edges so that
        // downstream nodes stay blocked until the revocation is
        // actually emitted.

        let mut dependencies = vec![];

        while !adjacencies.is_empty() {
            let batch = adjacencies.pop_all();
            if batch.is_empty() {
                break; // cycle guard
            }

            let (mut revocations, mut others): (Vec<_>, Vec<_>) =
                batch.into_iter().partition(|(_, op)| op.is_revocation());

            // Emit all non-revocations sorted by digest for determinism.
            others.sort_by_key(|(d, _)| *d);
            for (digest, op) in &others {
                dependencies.push((*digest, (*op).clone()));
            }

            if revocations.len() <= 1 {
                for (digest, op) in &revocations {
                    dependencies.push((*digest, (*op).clone()));
                }
            } else {
                // Multiple concurrent revocations: force ordering by
                // delegation chain length (longest_path), breaking ties
                // by digest.
                revocations.sort_by(|(d1, _), (d2, _)| {
                    let lp1 = longest_paths.get(d1).copied().unwrap_or(1);
                    let lp2 = longest_paths.get(d2).copied().unwrap_or(1);
                    lp1.cmp(&lp2).then_with(|| d1.cmp(d2))
                });

                // Emit the first (shortest delegation chain).
                let (first_digest, first_op) = revocations[0];
                dependencies.push((first_digest, first_op.clone()));

                // Re-insert remaining revocations chained pairwise, and
                // restore their outgoing edges so that successor nodes
                // (which had their in-degrees decremented when this
                // batch was popped) stay blocked.
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
                                // "rev before succ" — succ depends on rev
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

impl<S: AsyncSigner, T: ContentRef, L: MembershipListener<S, T>> Dupe
    for MembershipOperation<S, T, L>
{
    fn dupe(&self) -> Self {
        self.clone()
    }
}

impl<S: AsyncSigner, T: ContentRef, L: MembershipListener<S, T>> Verifiable
    for MembershipOperation<S, T, L>
{
    fn verifying_key(&self) -> ed25519_dalek::VerifyingKey {
        match self {
            MembershipOperation::Delegation(delegation) => delegation.verifying_key(),
            MembershipOperation::Revocation(revocation) => revocation.verifying_key(),
        }
    }
}

impl<S: AsyncSigner, T: ContentRef, L: MembershipListener<S, T>>
    From<Arc<Signed<Delegation<S, T, L>>>> for MembershipOperation<S, T, L>
{
    fn from(delegation: Arc<Signed<Delegation<S, T, L>>>) -> Self {
        MembershipOperation::Delegation(delegation)
    }
}

impl<S: AsyncSigner, T: ContentRef, L: MembershipListener<S, T>>
    From<Arc<Signed<Revocation<S, T, L>>>> for MembershipOperation<S, T, L>
{
    fn from(revocation: Arc<Signed<Revocation<S, T, L>>>) -> Self {
        MembershipOperation::Revocation(revocation)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(any(test, feature = "arbitrary"), derive(arbitrary::Arbitrary))]
pub enum StaticMembershipOperation<T: ContentRef> {
    Delegation(Signed<StaticDelegation<T>>),
    Revocation(Signed<StaticRevocation<T>>),
}

impl<S: AsyncSigner, T: ContentRef, L: MembershipListener<S, T>> From<MembershipOperation<S, T, L>>
    for StaticMembershipOperation<T>
{
    fn from(op: MembershipOperation<S, T, L>) -> Self {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        access::Access,
        principal::{agent::Agent, individual::Individual},
        store::{delegation::DelegationStore, revocation::RevocationStore},
    };
    use dupe::Dupe;
    use futures::lock::Mutex;
    use keyhive_crypto::signer::{memory::MemorySigner, sync_signer::SyncSigner};
    use std::sync::{Arc, LazyLock};

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
    ) -> Arc<Signed<Delegation<MemorySigner, String>>> {
        let alice = Individual::generate(fixture(&ALICE_SIGNER), csprng)
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
    ) -> Arc<Signed<Delegation<MemorySigner, String>>> {
        let bob = Individual::generate(fixture(&BOB_SIGNER), csprng)
            .await
            .unwrap();

        Arc::new(
            fixture(&ALICE_SIGNER)
                .try_sign_sync(Delegation {
                    delegate: Agent::Individual(bob.id(), Arc::new(Mutex::new(bob))),
                    can: Access::Write,
                    proof: Some(add_alice(csprng).await),
                    after_content: BTreeMap::new(),
                    after_revocations: vec![],
                })
                .unwrap(),
        )
    }

    async fn add_carol<R: rand::CryptoRng + rand::RngCore>(
        csprng: &mut R,
    ) -> Arc<Signed<Delegation<MemorySigner, String>>> {
        let carol = Individual::generate(fixture(&CAROL_SIGNER), csprng)
            .await
            .unwrap();

        Arc::new(
            fixture(&ALICE_SIGNER)
                .try_sign_sync(Delegation {
                    delegate: carol.into(),
                    can: Access::Write,
                    proof: Some(add_alice(csprng).await),
                    after_content: BTreeMap::new(),
                    after_revocations: vec![],
                })
                .unwrap(),
        )
    }

    async fn add_dan<R: rand::CryptoRng + rand::RngCore>(
        csprng: &mut R,
    ) -> Arc<Signed<Delegation<MemorySigner, String>>> {
        let dan = Individual::generate(fixture(&DAN_SIGNER), csprng)
            .await
            .unwrap();

        Arc::new(
            fixture(&CAROL_SIGNER)
                .try_sign_sync(Delegation {
                    delegate: dan.into(),
                    can: Access::Write,
                    proof: Some(add_carol(csprng).await),
                    after_content: BTreeMap::new(),
                    after_revocations: vec![],
                })
                .unwrap(),
        )
    }

    async fn add_erin<R: rand::CryptoRng + rand::RngCore>(
        csprng: &mut R,
    ) -> Arc<Signed<Delegation<MemorySigner, String>>> {
        let erin = Individual::generate(fixture(&ERIN_SIGNER), csprng)
            .await
            .unwrap();

        Arc::new(
            fixture(&BOB_SIGNER)
                .try_sign_sync(Delegation {
                    delegate: erin.into(),
                    can: Access::Write,
                    proof: Some(add_bob(csprng).await),
                    after_content: BTreeMap::new(),
                    after_revocations: vec![],
                })
                .unwrap(),
        )
    }

    async fn remove_carol<R: rand::CryptoRng + rand::RngCore>(
        csprng: &mut R,
    ) -> Arc<Signed<Revocation<MemorySigner, String>>> {
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
    ) -> Arc<Signed<Revocation<MemorySigner, String>>> {
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
                MembershipOperation::<MemorySigner, String>::reverse_topsort(&dlgs, &revs);
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

            let alice_op: MembershipOperation<MemorySigner, String> = alice_dlg.into();
            let alice_hash = Digest::hash(&alice_op);

            let carol_op: MembershipOperation<MemorySigner, String> = carol_dlg.into();
            let carol_hash = Digest::hash(&carol_op);

            let dan_op: MembershipOperation<MemorySigner, String> = dan_dlg.into();
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
                Active::<_, [u8; 32], _>::generate(alice_sk, NoListener, csprng)
                    .await
                    .unwrap(),
            ));

            let bob_sk = fixture(&BOB_SIGNER).clone();
            let bob = Arc::new(Mutex::new(
                Active::generate(bob_sk, NoListener, csprng).await.unwrap(),
            ));

            let carol_sk = fixture(&CAROL_SIGNER).clone();
            let carol = Arc::new(Mutex::new(
                Active::generate(carol_sk, NoListener, csprng)
                    .await
                    .unwrap(),
            ));

            let dan_sk = fixture(&DAN_SIGNER).clone();
            let dan = Arc::new(Mutex::new(
                Active::generate(dan_sk, NoListener, csprng).await.unwrap(),
            ));

            let locked_alice = alice.lock().await;

            let alice_to_bob: Arc<Signed<Delegation<MemorySigner>>> = Arc::new(
                locked_alice
                    .signer
                    .try_sign_sync(Delegation {
                        delegate: Agent::Active(bob.lock().await.id(), bob.dupe()),
                        can: Access::Write,
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
                        can: Access::Pull,
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

            let ad_idx = sorted
                .iter()
                .position(|(_, op)| op == &alice_to_dan.dupe().into())
                .unwrap();

            let bc_idx = sorted
                .iter()
                .position(|(_, op)| op == &bob_to_carol.dupe().into())
                .unwrap();

            assert!(ab_idx < bc_idx);
            // alice_to_dan has no causal relationship with the other ops,
            // so we only check that it exists (already verified via unwrap
            // above) and that the real causal constraint holds.
            let _ = ad_idx;
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
            let rev_op: MembershipOperation<MemorySigner, String> = alice_revokes_bob.dupe().into();
            let rev_hash = Digest::hash(&rev_op);

            let dlgs = DelegationStore::new();
            let revs = RevocationStore::from_iter_direct([alice_revokes_bob.dupe()]);

            let mut observed = MembershipOperation::reverse_topsort(&dlgs, &revs);

            let alice_op: MembershipOperation<MemorySigner, String> = alice_dlg.into();
            let alice_hash = Digest::hash(&alice_op);

            let bob_op: MembershipOperation<MemorySigner, String> = bob_dlg.into();
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

            let rev_carol_op: MembershipOperation<MemorySigner, String> =
                alice_revokes_carol.dupe().into();
            let rev_carol_hash = Digest::hash(&rev_carol_op);

            let rev_dan_op: MembershipOperation<MemorySigner, String> =
                bob_revokes_dan.dupe().into();
            let rev_dan_hash = Digest::hash(&rev_dan_op);

            let dlg_heads = DelegationStore::from_iter_direct([erin_dlg.dupe()]);
            let rev_heads = RevocationStore::from_iter_direct([
                alice_revokes_carol.dupe(),
                bob_revokes_dan.dupe(),
            ]);

            let observed = MembershipOperation::reverse_topsort(&dlg_heads, &rev_heads);

            let alice_op: MembershipOperation<MemorySigner, String> = alice_dlg.clone().into();
            let alice_hash = Digest::hash(&alice_op);

            let bob_op: MembershipOperation<MemorySigner, String> = bob_dlg.clone().into();
            let bob_hash = Digest::hash(&bob_op);

            let carol_op: MembershipOperation<MemorySigner, String> = carol_dlg.clone().into();
            let carol_hash = Digest::hash(&carol_op);

            let dan_op: MembershipOperation<MemorySigner, String> = dan_dlg.clone().into();
            let dan_hash = Digest::hash(&dan_op);

            let erin_op: MembershipOperation<MemorySigner, String> = erin_dlg.clone().into();
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
                        can: Access::Write,
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
                        can: Access::Write,
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
    }
}
