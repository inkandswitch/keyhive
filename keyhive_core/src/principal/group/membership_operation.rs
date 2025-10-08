use super::{
    delegation::{Delegation, StaticDelegation},
    dependencies::Dependencies,
    revocation::{Revocation, StaticRevocation},
};
use crate::{
    content::reference::ContentRef,
    crypto::{
        digest::Digest, signed::Signed, signer::async_signer::AsyncSigner, verifiable::Verifiable,
    },
    listener::{membership::MembershipListener, no_listener::NoListener},
    principal::{document::id::DocumentId, identifier::Identifier},
    util::content_addressed_map::CaMap,
};
use derive_more::{From, Into};
use derive_where::derive_where;
use dupe::Dupe;
use serde::{Deserialize, Serialize};
use std::{
    cmp::Ordering,
    collections::{BTreeMap, HashMap, HashSet},
    hash::Hash,
    sync::Arc,
};
use topological_sort::TopologicalSort;
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

    #[allow(clippy::type_complexity)] // Clippy doens't like the returned pair
    #[instrument(skip_all)]
    pub fn topsort(
        delegation_heads: &CaMap<Signed<Delegation<S, T, L>>>,
        revocation_heads: &CaMap<Signed<Revocation<S, T, L>>>,
    ) -> Vec<(
        Digest<MembershipOperation<S, T, L>>,
        MembershipOperation<S, T, L>,
    )> {
        // NOTE: BTreeMap to get deterministic order
        let mut ops_with_ancestors: BTreeMap<
            Digest<MembershipOperation<S, T, L>>,
            (
                MembershipOperation<S, T, L>,
                CaMap<MembershipOperation<S, T, L>>,
                usize,
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

        let mut leftovers: HashMap<Key, MembershipOperation<S, T, L>> = HashMap::new();
        let mut explore: Vec<MembershipOperation<S, T, L>> = vec![];

        for dlg in delegation_heads.values() {
            let op: MembershipOperation<S, T, L> = dlg.dupe().into();
            leftovers.insert(op.signature().into(), op.clone());
            explore.push(op);
        }

        for rev in revocation_heads.values() {
            let op: MembershipOperation<S, T, L> = rev.dupe().into();
            leftovers.insert(op.signature().into(), op.clone());
            explore.push(op);
        }

        // {being revoked => revocation}
        let mut revoked_dependencies: HashMap<
            Key,
            (
                Digest<MembershipOperation<S, T, L>>,
                MembershipOperation<S, T, L>,
            ),
        > = HashMap::new();

        while let Some(op) = explore.pop() {
            let (ancestors, longest_path) = op.ancestors();
            let digest = Digest::hash(&op);

            for ancestor in ancestors.values() {
                explore.push(ancestor.as_ref().dupe());
            }

            if let MembershipOperation::Revocation(r) = &op {
                revoked_dependencies
                    .insert((*r.payload.revoke.signature()).into(), (digest, op.dupe()));
            }

            ops_with_ancestors.insert(digest, (op, ancestors, longest_path));
        }

        let mut adjacencies: TopologicalSort<(
            Digest<MembershipOperation<S, T, L>>,
            &MembershipOperation<S, T, L>,
        )> = topological_sort::TopologicalSort::new();

        for (digest, (op, op_ancestors, longest_path)) in ops_with_ancestors.iter() {
            if let MembershipOperation::Delegation(d) = op {
                if let Some(proof) = &d.payload.proof {
                    if let Some((revoked_digest, revoked_op)) =
                        revoked_dependencies.get(&Key(proof.signature))
                    {
                        adjacencies.add_dependency((*digest, op), (*revoked_digest, revoked_op));
                    }
                }
            }

            for (other_digest, other_op) in op_ancestors.iter() {
                let (_, other_ancestors, other_longest_path) = ops_with_ancestors
                    .get(other_digest)
                    .expect("values that we just put there to be there");

                #[allow(clippy::mutable_key_type)]
                let ancestor_set: HashSet<&MembershipOperation<S, T, L>> =
                    op_ancestors.values().map(|op| op.as_ref()).collect();

                #[allow(clippy::mutable_key_type)]
                let other_ancestor_set: HashSet<&MembershipOperation<S, T, L>> =
                    other_ancestors.values().map(|op| op.as_ref()).collect();

                if other_ancestor_set.contains(op) || ancestor_set.is_subset(&other_ancestor_set) {
                    leftovers.remove(&Key(other_op.signature()));
                    adjacencies.add_dependency((*other_digest, other_op.as_ref()), (*digest, op));
                    continue;
                }

                if ancestor_set.contains(other_op.as_ref())
                    || ancestor_set.is_superset(&other_ancestor_set)
                {
                    leftovers.remove(&Key(op.signature()));
                    adjacencies.add_dependency((*digest, op), (*other_digest, other_op.as_ref()));
                    continue;
                }

                // NOTE for concurrent case:
                // if both are revocations then do extra checks to force order
                // in order to ensure no revocation cycles
                if op.is_revocation() && other_op.is_revocation() {
                    match longest_path.cmp(other_longest_path) {
                        Ordering::Less => {
                            leftovers.remove(&Key(op.signature()));
                            adjacencies
                                .add_dependency((*digest, op), (*other_digest, other_op.as_ref()));
                        }
                        Ordering::Greater => {
                            leftovers.remove(&Key(other_op.signature()));
                            adjacencies
                                .add_dependency((*other_digest, other_op.as_ref()), (*digest, op));
                        }
                        Ordering::Equal => match other_digest.cmp(digest) {
                            Ordering::Less => {
                                leftovers.remove(&Key(op.signature()));
                                adjacencies.add_dependency(
                                    (*digest, op),
                                    (*other_digest, other_op.as_ref()),
                                );
                            }
                            Ordering::Greater => {
                                leftovers.remove(&Key(other_op.signature()));
                                adjacencies.add_dependency(
                                    (*other_digest, other_op.as_ref()),
                                    (*digest, op),
                                );
                            }
                            Ordering::Equal => {
                                debug_assert!(false, "should not need to compare to self")
                            }
                        },
                    }
                    continue;
                }
            }
        }

        let mut history: Vec<(
            Digest<MembershipOperation<S, T, L>>,
            MembershipOperation<S, T, L>,
        )> = leftovers
            .values()
            .map(|op| (Digest::hash(op), op.clone()))
            .collect();

        history.sort_by_key(|(digest, _)| *digest);

        let mut dependencies = vec![];

        while !adjacencies.is_empty() {
            let mut latest = adjacencies.pop_all();

            // NOTE sort all concurrent heads by hash for more determinism
            latest.sort_by_key(|(digest, _)| *digest);

            for (digest, op) in latest.into_iter() {
                dependencies.push((digest, op.clone()));
            }
        }

        history.extend(dependencies);
        history
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
        crypto::signer::{memory::MemorySigner, sync_signer::SyncSigner},
        principal::agent::Agent,
        principal::individual::Individual,
    };
    use dupe::Dupe;
    use futures::lock::Mutex;
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
        use crate::principal::active::Active;

        use super::*;

        #[test]
        fn test_empty() {
            test_utils::init_logging();

            let dlgs = CaMap::new();
            let revs = CaMap::new();

            let observed = MembershipOperation::<MemorySigner, String>::topsort(&dlgs, &revs);
            assert_eq!(observed, vec![]);
        }

        #[tokio::test]
        async fn test_one_delegation() {
            test_utils::init_logging();
            let csprng = &mut rand::thread_rng();

            let dlg = add_alice(csprng).await;

            let dlgs = CaMap::from_iter_direct([dlg.dupe()]);
            let revs = CaMap::new();

            let observed = MembershipOperation::topsort(&dlgs, &revs);
            let expected = dlg.into();

            assert_eq!(observed, vec![(Digest::hash(&expected), expected)]);
        }

        #[tokio::test]
        async fn test_delegation_sequence() {
            test_utils::init_logging();
            let csprng = &mut rand::thread_rng();

            let alice_dlg = add_alice(csprng).await;
            let bob_dlg = add_bob(csprng).await;

            let dlg_heads = CaMap::from_iter_direct([bob_dlg.dupe()]);
            let rev_heads = CaMap::new();

            let observed = MembershipOperation::topsort(&dlg_heads, &rev_heads);

            let alice_op = alice_dlg.into();
            let bob_op = bob_dlg.into();

            let expected = vec![
                (Digest::hash(&bob_op), bob_op),
                (Digest::hash(&alice_op), alice_op),
            ];

            assert_eq!(observed.len(), 2);
            assert_eq!(observed, expected);
        }

        #[tokio::test]
        async fn test_longer_delegation_chain() {
            test_utils::init_logging();
            let csprng = &mut rand::thread_rng();

            let alice_dlg = add_alice(csprng).await;
            let carol_dlg = add_carol(csprng).await;
            let dan_dlg = add_dan(csprng).await;

            let dlg_heads = CaMap::from_iter_direct([dan_dlg.dupe()]);
            let rev_heads = CaMap::new();

            let observed = MembershipOperation::topsort(&dlg_heads, &rev_heads);

            let alice_op: MembershipOperation<MemorySigner, String> = alice_dlg.into();
            let alice_hash = Digest::hash(&alice_op);

            let carol_op: MembershipOperation<MemorySigner, String> = carol_dlg.into();
            let carol_hash = Digest::hash(&carol_op);

            let dan_op: MembershipOperation<MemorySigner, String> = dan_dlg.into();
            let dan_hash = Digest::hash(&dan_op);

            let a = (alice_hash, alice_op.clone());
            let c = (carol_hash, carol_op.clone());
            let d = (dan_hash, dan_op.clone());

            assert_eq!(observed, vec![d, c, a]);
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

            let dlg_heads = CaMap::from_iter_direct([alice_to_dan.dupe(), bob_to_carol.dupe()]);
            let mut sorted = MembershipOperation::topsort(&dlg_heads, &CaMap::new());
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
            assert!(ab_idx < ad_idx);
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

            let dlgs = CaMap::new();
            let revs = CaMap::from_iter_direct([alice_revokes_bob.dupe()]);

            let mut observed = MembershipOperation::topsort(&dlgs, &revs);

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

            let dlg_heads = CaMap::from_iter_direct([erin_dlg.dupe()]);
            let rev_heads =
                CaMap::from_iter_direct([alice_revokes_carol.dupe(), bob_revokes_dan.dupe()]);

            let observed = MembershipOperation::topsort(&dlg_heads, &rev_heads);

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
    }
}
