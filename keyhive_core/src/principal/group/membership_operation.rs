use super::{
    delegation::{Delegation, StaticDelegation},
    dependencies::Dependencies,
    revocation::{Revocation, StaticRevocation},
};
use crate::{
    content::reference::ContentRef,
    crypto::{digest::Digest, signed::Signed, verifiable::Verifiable},
    listener::{membership::MembershipListener, no_listener::NoListener},
    principal::{document::id::DocumentId, identifier::Identifier},
    util::content_addressed_map::CaMap,
};
use derive_more::{From, Into};
use dupe::Dupe;
use serde::{Deserialize, Serialize};
use std::{
    cmp::Ordering,
    collections::{BTreeMap, HashMap, HashSet},
    hash::Hash,
    rc::Rc,
};
use topological_sort::TopologicalSort;

#[derive(Debug, Dupe, Clone)]
pub enum MembershipOperation<T: ContentRef = [u8; 32], L: MembershipListener<T> = NoListener> {
    Delegation(Rc<Signed<Delegation<T, L>>>),
    Revocation(Rc<Signed<Revocation<T, L>>>),
}

impl<T: ContentRef, L: MembershipListener<T>> std::hash::Hash for MembershipOperation<T, L> {
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

impl<T: ContentRef, L: MembershipListener<T>> PartialEq for MembershipOperation<T, L> {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (MembershipOperation::Delegation(d1), MembershipOperation::Delegation(d2)) => d1 == d2,
            (MembershipOperation::Revocation(r1), MembershipOperation::Revocation(r2)) => r1 == r2,
            _ => false,
        }
    }
}

impl<T: ContentRef, L: MembershipListener<T>> Eq for MembershipOperation<T, L> {}

impl<T: ContentRef + Serialize, L: MembershipListener<T>> Serialize for MembershipOperation<T, L> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            MembershipOperation::Delegation(delegation) => delegation.serialize(serializer),
            MembershipOperation::Revocation(revocation) => revocation.serialize(serializer),
        }
    }
}

impl<T: ContentRef, L: MembershipListener<T>> MembershipOperation<T, L> {
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

    pub fn after_auth(&self) -> Vec<MembershipOperation<T, L>> {
        let deps = self.after();
        deps.delegations
            .into_iter()
            .map(|d| d.into())
            .chain(deps.revocations.into_iter().map(|r| r.into()))
            .collect()
    }

    pub fn after(&self) -> Dependencies<T, L> {
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

    pub fn ancestors(&self) -> (CaMap<MembershipOperation<T, L>>, usize) {
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
                acc_set.insert(Rc::new(op.clone()));

                if count > acc_count {
                    (acc_set, count)
                } else {
                    (acc_set, acc_count)
                }
            },
        )
    }

    #[allow(clippy::type_complexity)] // Clippy doens't like the returned pair
    pub fn topsort(
        delegation_heads: &CaMap<Signed<Delegation<T, L>>>,
        revocation_heads: &CaMap<Signed<Revocation<T, L>>>,
    ) -> Vec<(Digest<MembershipOperation<T, L>>, MembershipOperation<T, L>)> {
        // NOTE: BTreeMap to get deterministic order
        let mut ops_with_ancestors: BTreeMap<
            Digest<MembershipOperation<T, L>>,
            (
                MembershipOperation<T, L>,
                CaMap<MembershipOperation<T, L>>,
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

        let mut leftovers: HashMap<Key, MembershipOperation<T, L>> = HashMap::new();
        let mut explore: Vec<MembershipOperation<T, L>> = vec![];

        for dlg in delegation_heads.values() {
            let op: MembershipOperation<T, L> = dlg.dupe().into();
            leftovers.insert(op.signature().into(), op.clone());
            explore.push(op);
        }

        for rev in revocation_heads.values() {
            let op: MembershipOperation<T, L> = rev.dupe().into();
            leftovers.insert(op.signature().into(), op.clone());
            explore.push(op);
        }

        while let Some(op) = explore.pop() {
            let (ancestors, longest_path) = op.ancestors();

            for ancestor in ancestors.values() {
                explore.push(ancestor.as_ref().clone());
            }

            ops_with_ancestors.insert(Digest::hash(&op), (op, ancestors, longest_path));
        }

        let mut adjacencies: TopologicalSort<(
            Digest<MembershipOperation<T, L>>,
            &MembershipOperation<T, L>,
        )> = topological_sort::TopologicalSort::new();

        for (digest, (op, op_ancestors, longest_path)) in ops_with_ancestors.iter() {
            for (other_digest, other_op) in op_ancestors.iter() {
                let (_, other_ancestors, other_longest_path) = ops_with_ancestors
                    .get(other_digest)
                    .expect("values that we just put there to be there");

                #[allow(clippy::mutable_key_type)]
                let ancestor_set: HashSet<&MembershipOperation<T, L>> =
                    op_ancestors.values().map(|op| op.as_ref()).collect();

                #[allow(clippy::mutable_key_type)]
                let other_ancestor_set: HashSet<&MembershipOperation<T, L>> =
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

                // Concurrent: if both are revocations then do extra checks to force order
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
                            Ordering::Equal => {}
                        },
                    }
                    continue;
                }
            }
        }

        let mut history: Vec<(Digest<MembershipOperation<T, L>>, MembershipOperation<T, L>)> =
            leftovers
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

impl<T: ContentRef, L: MembershipListener<T>> Verifiable for MembershipOperation<T, L> {
    fn verifying_key(&self) -> ed25519_dalek::VerifyingKey {
        match self {
            MembershipOperation::Delegation(delegation) => delegation.verifying_key(),
            MembershipOperation::Revocation(revocation) => revocation.verifying_key(),
        }
    }
}

impl<T: ContentRef, L: MembershipListener<T>> From<Rc<Signed<Delegation<T, L>>>>
    for MembershipOperation<T, L>
{
    fn from(delegation: Rc<Signed<Delegation<T, L>>>) -> Self {
        MembershipOperation::Delegation(delegation)
    }
}

impl<T: ContentRef, L: MembershipListener<T>> From<Rc<Signed<Revocation<T, L>>>>
    for MembershipOperation<T, L>
{
    fn from(revocation: Rc<Signed<Revocation<T, L>>>) -> Self {
        MembershipOperation::Revocation(revocation)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(any(test, feature = "arbitrary"), derive(arbitrary::Arbitrary))]
pub enum StaticMembershipOperation<T: ContentRef> {
    Delegation(Signed<StaticDelegation<T>>),
    Revocation(Signed<StaticRevocation<T>>),
}

impl<T: ContentRef, L: MembershipListener<T>> From<MembershipOperation<T, L>>
    for StaticMembershipOperation<T>
{
    fn from(op: MembershipOperation<T, L>) -> Self {
        match op {
            MembershipOperation::Delegation(d) => {
                StaticMembershipOperation::Delegation(Rc::unwrap_or_clone(d).map(Into::into))
            }
            MembershipOperation::Revocation(r) => {
                StaticMembershipOperation::Revocation(Rc::unwrap_or_clone(r).map(Into::into))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::principal::agent::Agent;
    use crate::{access::Access, principal::individual::Individual};
    use dupe::Dupe;
    use std::cell::RefCell;
    use std::rc::Rc;

    use std::sync::LazyLock;

    static GROUP_SIGNER: LazyLock<ed25519_dalek::SigningKey> =
        LazyLock::new(|| ed25519_dalek::SigningKey::generate(&mut rand::thread_rng()));

    static ALICE_SIGNER: LazyLock<ed25519_dalek::SigningKey> =
        LazyLock::new(|| ed25519_dalek::SigningKey::generate(&mut rand::thread_rng()));

    static BOB_SIGNER: LazyLock<ed25519_dalek::SigningKey> =
        LazyLock::new(|| ed25519_dalek::SigningKey::generate(&mut rand::thread_rng()));

    static CAROL_SIGNER: LazyLock<ed25519_dalek::SigningKey> =
        LazyLock::new(|| ed25519_dalek::SigningKey::generate(&mut rand::thread_rng()));

    static DAN_SIGNER: LazyLock<ed25519_dalek::SigningKey> =
        LazyLock::new(|| ed25519_dalek::SigningKey::generate(&mut rand::thread_rng()));

    static ERIN_SIGNER: LazyLock<ed25519_dalek::SigningKey> =
        LazyLock::new(|| ed25519_dalek::SigningKey::generate(&mut rand::thread_rng()));

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

    fn add_alice<R: rand::CryptoRng + rand::RngCore>(
        csprng: &mut R,
    ) -> Rc<Signed<Delegation<String>>> {
        let alice = Individual::generate(fixture(&ALICE_SIGNER), csprng).unwrap();
        let group_sk = LazyLock::force(&GROUP_SIGNER).clone();

        Rc::new(
            Signed::try_sign(
                Delegation {
                    delegate: alice.into(),
                    can: Access::Admin,
                    proof: None,
                    after_content: BTreeMap::new(),
                    after_revocations: vec![],
                },
                &group_sk,
            )
            .unwrap(),
        )
        .dupe()
    }

    fn add_bob<R: rand::CryptoRng + rand::RngCore>(
        csprng: &mut R,
    ) -> Rc<Signed<Delegation<String>>> {
        let bob = Individual::generate(fixture(&BOB_SIGNER), csprng).unwrap();

        Rc::new(
            Signed::try_sign(
                Delegation {
                    delegate: Agent::Individual(Rc::new(RefCell::new(bob))),
                    can: Access::Write,
                    proof: Some(add_alice(csprng)),
                    after_content: BTreeMap::new(),
                    after_revocations: vec![],
                },
                &fixture(&ALICE_SIGNER),
            )
            .unwrap(),
        )
    }

    fn add_carol<R: rand::CryptoRng + rand::RngCore>(
        csprng: &mut R,
    ) -> Rc<Signed<Delegation<String>>> {
        let carol = Individual::generate(fixture(&CAROL_SIGNER), csprng).unwrap();

        Rc::new(
            Signed::try_sign(
                Delegation {
                    delegate: carol.into(),
                    can: Access::Write,
                    proof: Some(add_alice(csprng)),
                    after_content: BTreeMap::new(),
                    after_revocations: vec![],
                },
                fixture(&ALICE_SIGNER),
            )
            .unwrap(),
        )
    }

    fn add_dan<R: rand::CryptoRng + rand::RngCore>(
        csprng: &mut R,
    ) -> Rc<Signed<Delegation<String>>> {
        let dan = Individual::generate(fixture(&DAN_SIGNER), csprng).unwrap();

        Rc::new(
            Signed::try_sign(
                Delegation {
                    delegate: dan.into(),
                    can: Access::Write,
                    proof: Some(add_carol(csprng)),
                    after_content: BTreeMap::new(),
                    after_revocations: vec![],
                },
                fixture(&CAROL_SIGNER),
            )
            .unwrap(),
        )
    }

    fn add_erin<R: rand::CryptoRng + rand::RngCore>(
        csprng: &mut R,
    ) -> Rc<Signed<Delegation<String>>> {
        let erin = Individual::generate(fixture(&ERIN_SIGNER), csprng).unwrap();

        Rc::new(
            Signed::try_sign(
                Delegation {
                    delegate: erin.into(),
                    can: Access::Write,
                    proof: Some(add_bob(csprng)),
                    after_content: BTreeMap::new(),
                    after_revocations: vec![],
                },
                fixture(&BOB_SIGNER),
            )
            .unwrap(),
        )
    }

    fn remove_carol<R: rand::CryptoRng + rand::RngCore>(
        csprng: &mut R,
    ) -> Rc<Signed<Revocation<String>>> {
        Rc::new(
            Signed::try_sign(
                Revocation {
                    revoke: add_carol(csprng),
                    proof: Some(add_alice(csprng)),
                    after_content: BTreeMap::new(),
                },
                fixture(&ALICE_SIGNER),
            )
            .unwrap(),
        )
    }

    fn remove_dan<R: rand::CryptoRng + rand::RngCore>(
        csprng: &mut R,
    ) -> Rc<Signed<Revocation<String>>> {
        Rc::new(
            Signed::try_sign(
                Revocation {
                    revoke: add_dan(csprng),
                    proof: Some(add_bob(csprng)),
                    after_content: BTreeMap::new(),
                },
                fixture(&BOB_SIGNER),
            )
            .unwrap(),
        )
    }

    fn fixture<T>(from: &LazyLock<T>) -> &T {
        LazyLock::force(from)
    }

    mod ancestors {
        use super::*;

        #[test]
        fn test_singleton() {
            let csprng = &mut rand::thread_rng();
            let alice_dlg = add_alice(csprng);
            let (ancestors, longest) = MembershipOperation::from(alice_dlg).ancestors();
            assert!(ancestors.is_empty());
            assert_eq!(longest, 1);
        }

        #[test]
        fn test_two_direct() {
            let csprng = &mut rand::thread_rng();
            let bob_dlg = add_bob(csprng);
            let (ancestors, longest) = MembershipOperation::from(bob_dlg).ancestors();
            assert_eq!(ancestors.len(), 1);
            assert_eq!(longest, 2);
        }

        #[test]
        fn test_concurrent() {
            let csprng = &mut rand::thread_rng();
            let bob_dlg = add_bob(csprng);
            let carol_dlg = add_carol(csprng);

            let (bob_ancestors, bob_longest) = MembershipOperation::from(bob_dlg).ancestors();
            let (carol_ancestors, carol_longest) = MembershipOperation::from(carol_dlg).ancestors();

            assert_eq!(bob_ancestors.len(), carol_ancestors.len());
            assert_eq!(bob_longest, carol_longest);
        }

        #[test]
        fn test_longer() {
            let csprng = &mut rand::thread_rng();
            let erin_dlg = add_erin(csprng);
            let (ancestors, longest) = MembershipOperation::from(erin_dlg).ancestors();
            assert_eq!(ancestors.len(), 2);
            assert_eq!(longest, 2);
        }

        #[test]
        fn test_revocation() {
            let csprng = &mut rand::thread_rng();
            let rev = remove_carol(csprng);
            let (ancestors, longest) = MembershipOperation::from(rev).ancestors();
            assert_eq!(ancestors.len(), 2);
            assert_eq!(longest, 2);
        }
    }

    mod topsort {
        use super::*;

        #[test]
        fn test_empty() {
            let dlgs = CaMap::new();
            let revs = CaMap::new();

            let observed = MembershipOperation::<String>::topsort(&dlgs, &revs);
            assert_eq!(observed, vec![]);
        }

        #[test]
        fn test_one_delegation() {
            let csprng = &mut rand::thread_rng();

            let dlg = add_alice(csprng);

            let dlgs = CaMap::from_iter_direct([dlg.dupe()]);
            let revs = CaMap::new();

            let observed = MembershipOperation::topsort(&dlgs, &revs);
            let expected = dlg.into();

            assert_eq!(observed, vec![(Digest::hash(&expected), expected)]);
        }

        #[test]
        fn test_delegation_sequence() {
            let csprng = &mut rand::thread_rng();

            let alice_dlg = add_alice(csprng);
            let bob_dlg = add_bob(csprng);

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

        #[test]
        fn test_longer_delegation_chain() {
            let csprng = &mut rand::thread_rng();

            let alice_dlg = add_alice(csprng);
            let carol_dlg = add_carol(csprng);
            let dan_dlg = add_dan(csprng);

            let dlg_heads = CaMap::from_iter_direct([dan_dlg.dupe()]);
            let rev_heads = CaMap::new();

            let observed = MembershipOperation::topsort(&dlg_heads, &rev_heads);

            let alice_op: MembershipOperation<String> = alice_dlg.into();
            let alice_hash = Digest::hash(&alice_op);

            let carol_op: MembershipOperation<String> = carol_dlg.into();
            let carol_hash = Digest::hash(&carol_op);

            let dan_op: MembershipOperation<String> = dan_dlg.into();
            let dan_hash = Digest::hash(&dan_op);

            let a = (alice_hash, alice_op.clone());
            let c = (carol_hash, carol_op.clone());
            let d = (dan_hash, dan_op.clone());

            assert_eq!(observed, vec![d, c, a]);
        }

        #[test]
        fn test_one_revocation() {
            let csprng = &mut rand::thread_rng();
            let alice_sk = fixture(&ALICE_SIGNER).clone();
            let alice_dlg = add_alice(csprng);
            let bob_dlg = add_bob(csprng);

            let alice_revokes_bob = Rc::new(
                Signed::try_sign(
                    Revocation {
                        revoke: bob_dlg.dupe(),
                        proof: Some(alice_dlg.dupe()),
                        after_content: BTreeMap::new(),
                    },
                    &alice_sk,
                )
                .unwrap(),
            );
            let rev_op: MembershipOperation<String> = alice_revokes_bob.dupe().into();
            let rev_hash = Digest::hash(&rev_op);

            let dlgs = CaMap::new();
            let revs = CaMap::from_iter_direct([alice_revokes_bob.dupe()]);

            let mut observed = MembershipOperation::topsort(&dlgs, &revs);

            let alice_op: MembershipOperation<String> = alice_dlg.into();
            let alice_hash = Digest::hash(&alice_op);

            let bob_op: MembershipOperation<String> = bob_dlg.into();
            let bob_hash = Digest::hash(&bob_op);

            let a = (alice_hash, alice_op.clone());
            let b = (bob_hash, bob_op.clone());
            let r = (rev_hash.into(), alice_revokes_bob.into());

            assert_eq!(observed.clone().len(), 3);

            assert_eq!(observed.pop(), Some(a));
            assert_eq!(observed.pop(), Some(b));
            assert_eq!(observed.pop(), Some(r));
            assert_eq!(observed.pop(), None);
        }

        #[test]
        fn test_many_revocations() {
            let csprng = &mut rand::thread_rng();

            let alice_dlg = add_alice(csprng);
            let bob_dlg = add_bob(csprng);

            let carol_dlg = add_carol(csprng);
            let dan_dlg = add_dan(csprng);
            let erin_dlg = add_erin(csprng);

            let alice_revokes_carol = remove_carol(csprng);
            let bob_revokes_dan = remove_dan(csprng);

            let rev_carol_op: MembershipOperation<String> = alice_revokes_carol.dupe().into();
            let rev_carol_hash = Digest::hash(&rev_carol_op);

            let rev_dan_op: MembershipOperation<String> = bob_revokes_dan.dupe().into();
            let rev_dan_hash = Digest::hash(&rev_dan_op);

            let dlg_heads = CaMap::from_iter_direct([erin_dlg.dupe()]);
            let rev_heads =
                CaMap::from_iter_direct([alice_revokes_carol.dupe(), bob_revokes_dan.dupe()]);

            let observed = MembershipOperation::topsort(&dlg_heads, &rev_heads);

            let alice_op: MembershipOperation<String> = alice_dlg.clone().into();
            let alice_hash = Digest::hash(&alice_op);

            let bob_op: MembershipOperation<String> = bob_dlg.clone().into();
            let bob_hash = Digest::hash(&bob_op);

            let carol_op: MembershipOperation<String> = carol_dlg.clone().into();
            let carol_hash = Digest::hash(&carol_op);

            let dan_op: MembershipOperation<String> = dan_dlg.clone().into();
            let dan_hash = Digest::hash(&dan_op);

            let erin_op: MembershipOperation<String> = erin_dlg.clone().into();
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
