pub mod delegation;
pub mod revocation;

use crate::{
    content::reference::ContentRef,
    crypto::{digest::Digest, signed::Signed},
    principal::{
        document::{id::DocumentId, Document},
        identifier::Identifier,
    },
    util::content_addressed_map::CaMap,
};
use delegation::Delegation;
use dupe::Dupe;
use revocation::Revocation;
use serde::Serialize;
use std::{
    cell::RefCell,
    cmp::Ordering,
    collections::{BTreeMap, HashMap, HashSet},
    hash::Hash,
    rc::Rc,
};
use topological_sort::TopologicalSort;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Dupe)]
pub enum Operation<T: ContentRef> {
    Delegation(Rc<Signed<Delegation<T>>>),
    Revocation(Rc<Signed<Revocation<T>>>),
}

impl<T: ContentRef + Serialize> Serialize for Operation<T> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Operation::Delegation(delegation) => delegation.serialize(serializer),
            Operation::Revocation(revocation) => revocation.serialize(serializer),
        }
    }
}

impl<T: ContentRef> Operation<T> {
    pub fn subject(&self) -> Identifier {
        match self {
            Operation::Delegation(delegation) => delegation.subject(),
            Operation::Revocation(revocation) => revocation.subject(),
        }
    }

    pub fn is_delegation(&self) -> bool {
        match self {
            Operation::Delegation(_) => true,
            Operation::Revocation(_) => false,
        }
    }

    pub fn is_revocation(&self) -> bool {
        !self.is_delegation()
    }

    pub fn after_auth(&self) -> Vec<Operation<T>> {
        let (dlgs, revs, _) = self.after();
        dlgs.into_iter()
            .map(|d| d.into())
            .chain(revs.into_iter().map(|r| r.into()))
            .collect()
    }

    pub fn after(
        &self,
    ) -> (
        Vec<Rc<Signed<Delegation<T>>>>,
        Vec<Rc<Signed<Revocation<T>>>>,
        &BTreeMap<DocumentId, (Rc<RefCell<Document<T>>>, Vec<T>)>,
    ) {
        match self {
            Operation::Delegation(delegation) => {
                let (dlgs, revs, content) = delegation.payload().after();
                (dlgs, revs, content)
            }
            Operation::Revocation(revocation) => {
                let (dlg, revs, content) = revocation.payload().after();
                (dlg, revs, content)
            }
        }
    }

    pub fn after_content(&self) -> &BTreeMap<DocumentId, (Rc<RefCell<Document<T>>>, Vec<T>)> {
        match self {
            Operation::Delegation(delegation) => &delegation.payload().after_content,
            Operation::Revocation(revocation) => &revocation.payload().after_content,
        }
    }

    pub fn is_root(&self) -> bool {
        match self {
            Operation::Delegation(delegation) => delegation.payload().is_root(),
            Operation::Revocation(_) => false,
        }
    }

    pub fn ancestors(&self) -> (CaMap<Operation<T>>, usize) {
        if self.is_root() {
            return (CaMap::new(), 1);
        }

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

    pub fn topsort(
        delegation_heads: &HashSet<Rc<Signed<Delegation<T>>>>,
        revocation_heads: &HashSet<Rc<Signed<Revocation<T>>>>,
    ) -> Vec<(Digest<Operation<T>>, Operation<T>)> {
        // NOTE: BTreeMap to get deterministic order
        let mut ops_with_ancestors: BTreeMap<
            Digest<Operation<T>>,
            (Operation<T>, CaMap<Operation<T>>, usize),
        > = BTreeMap::new();

        let mut leftovers: HashSet<Operation<T>> = HashSet::new();
        let mut explore: Vec<Operation<T>> = vec![];

        for dlg in delegation_heads.iter() {
            let op: Operation<T> = dlg.dupe().into();
            leftovers.insert(op.clone());
            explore.push(op);
        }

        for rev in revocation_heads.iter() {
            let op: Operation<T> = rev.dupe().into();
            leftovers.insert(op.clone());
            explore.push(op);
        }

        while let Some(op) = explore.pop() {
            let (ancestors, longest_path) = op.ancestors();

            for ancestor in ancestors.values() {
                explore.push(ancestor.as_ref().clone());
            }

            ops_with_ancestors.insert(Digest::hash(&op), (op, ancestors, longest_path));
        }

        let mut adjacencies: TopologicalSort<(Digest<Operation<T>>, &Operation<T>)> =
            topological_sort::TopologicalSort::new();

        for (digest, (op, op_ancestors, longest_path)) in ops_with_ancestors.iter() {
            for (other_digest, other_op) in op_ancestors.iter() {
                let (_, other_ancestors, other_longest_path) = ops_with_ancestors
                    .get(&other_digest.coerce())
                    .expect("values that we just put there to be there");

                let ancestor_set: HashSet<&Operation<T>> =
                    op_ancestors.values().map(|op| op.as_ref()).collect();

                let other_ancestor_set: HashSet<&Operation<T>> =
                    other_ancestors.values().map(|op| op.as_ref()).collect();

                if other_ancestor_set.contains(op) || ancestor_set.is_subset(&other_ancestor_set) {
                    leftovers.remove(other_op);
                    adjacencies.add_dependency((*other_digest, other_op.as_ref()), (*digest, op));
                    continue;
                }

                if ancestor_set.contains(other_op.as_ref())
                    || ancestor_set.is_superset(&other_ancestor_set)
                {
                    leftovers.remove(op);
                    adjacencies.add_dependency((*digest, op), (*other_digest, other_op.as_ref()));
                    continue;
                }

                // Concurrent: if both are revocations then do extra checks to force order
                // in order to ensure no revocation cycles
                if op.is_revocation() && other_op.is_revocation() {
                    match longest_path.cmp(other_longest_path) {
                        Ordering::Less => {
                            leftovers.remove(op);
                            adjacencies
                                .add_dependency((*digest, op), (*other_digest, other_op.as_ref()));
                        }
                        Ordering::Greater => {
                            leftovers.remove(other_op);
                            adjacencies
                                .add_dependency((*other_digest, other_op.as_ref()), (*digest, op));
                        }
                        Ordering::Equal => match other_digest.cmp(&digest.coerce()) {
                            Ordering::Less => {
                                leftovers.remove(op);
                                adjacencies.add_dependency(
                                    (*digest, op),
                                    (*other_digest, other_op.as_ref()),
                                );
                            }
                            Ordering::Greater => {
                                leftovers.remove(other_op);
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

        let mut history: Vec<_> = leftovers
            .iter()
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

impl<T: ContentRef> From<Rc<Signed<Delegation<T>>>> for Operation<T> {
    fn from(delegation: Rc<Signed<Delegation<T>>>) -> Self {
        Operation::Delegation(delegation)
    }
}

impl<T: ContentRef> From<Rc<Signed<Revocation<T>>>> for Operation<T> {
    fn from(revocation: Rc<Signed<Revocation<T>>>) -> Self {
        Operation::Revocation(revocation)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{access::Access, principal::individual::Individual};
    use dupe::Dupe;
    use std::rc::Rc;

    use std::sync::LazyLock;

    static GROUP_SK: LazyLock<ed25519_dalek::SigningKey> =
        LazyLock::new(|| ed25519_dalek::SigningKey::generate(&mut rand::thread_rng()));

    static ALICE_SK: LazyLock<ed25519_dalek::SigningKey> =
        LazyLock::new(|| ed25519_dalek::SigningKey::generate(&mut rand::thread_rng()));

    static BOB_SK: LazyLock<ed25519_dalek::SigningKey> =
        LazyLock::new(|| ed25519_dalek::SigningKey::generate(&mut rand::thread_rng()));

    static CAROL_SK: LazyLock<ed25519_dalek::SigningKey> =
        LazyLock::new(|| ed25519_dalek::SigningKey::generate(&mut rand::thread_rng()));

    static DAN_SK: LazyLock<ed25519_dalek::SigningKey> =
        LazyLock::new(|| ed25519_dalek::SigningKey::generate(&mut rand::thread_rng()));

    static ERIN_SK: LazyLock<ed25519_dalek::SigningKey> =
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

    fn add_alice() -> Rc<Signed<Delegation<String>>> {
        let alice: Individual = fixture(&ALICE_SK).verifying_key().into();
        let group_sk = LazyLock::force(&GROUP_SK).clone();

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

    fn add_bob() -> Rc<Signed<Delegation<String>>> {
        let alice_sk = fixture(&ALICE_SK).clone();
        let bob: Individual = fixture(&BOB_SK).verifying_key().into();

        Rc::new(
            Signed::try_sign(
                Delegation {
                    delegate: bob.into(),
                    can: Access::Write,
                    proof: Some(add_alice().into()),
                    after_content: BTreeMap::new(),
                    after_revocations: vec![],
                },
                &alice_sk,
            )
            .unwrap(),
        )
    }

    fn add_carol() -> Rc<Signed<Delegation<String>>> {
        let alice_sk = fixture(&ALICE_SK).clone();
        let carol: Individual = fixture(&CAROL_SK).verifying_key().into();

        Rc::new(
            Signed::try_sign(
                Delegation {
                    delegate: carol.into(),
                    can: Access::Write,
                    proof: Some(add_alice().into()),
                    after_content: BTreeMap::new(),
                    after_revocations: vec![],
                },
                &alice_sk,
            )
            .unwrap(),
        )
    }

    fn add_dan() -> Rc<Signed<Delegation<String>>> {
        let carol_sk = fixture(&CAROL_SK).clone();
        let dan: Individual = fixture(&DAN_SK).verifying_key().into();

        Rc::new(
            Signed::try_sign(
                Delegation {
                    delegate: dan.into(),
                    can: Access::Write,
                    proof: Some(add_carol().into()),
                    after_content: BTreeMap::new(),
                    after_revocations: vec![],
                },
                &carol_sk,
            )
            .unwrap(),
        )
    }

    fn add_erin() -> Rc<Signed<Delegation<String>>> {
        let bob_sk = fixture(&BOB_SK).clone();
        let erin: Individual = fixture(&ERIN_SK).verifying_key().into();

        Rc::new(
            Signed::try_sign(
                Delegation {
                    delegate: erin.into(),
                    can: Access::Write,
                    proof: Some(add_bob().into()),
                    after_content: BTreeMap::new(),
                    after_revocations: vec![],
                },
                &bob_sk,
            )
            .unwrap(),
        )
    }

    fn remove_carol() -> Rc<Signed<Revocation<String>>> {
        let alice_sk = fixture(&ALICE_SK).clone();

        Rc::new(
            Signed::try_sign(
                Revocation {
                    revoke: add_carol(),
                    proof: Some(add_alice()),
                    after_content: BTreeMap::new(),
                },
                &alice_sk,
            )
            .unwrap(),
        )
    }

    fn remove_dan() -> Rc<Signed<Revocation<String>>> {
        let bob_sk = fixture(&BOB_SK).clone();

        Rc::new(
            Signed::try_sign(
                Revocation {
                    revoke: add_dan(),
                    proof: Some(add_bob().into()),
                    after_content: BTreeMap::new(),
                },
                &bob_sk,
            )
            .unwrap(),
        )
    }

    fn fixture<T>(from: &LazyLock<T>) -> &T {
        LazyLock::force(&from)
    }

    mod ancestors {
        use super::*;

        #[test]
        fn test_singleton() {
            let alice_dlg = add_alice();
            let (ancestors, longest) = Operation::from(alice_dlg).ancestors();
            assert!(ancestors.is_empty());
            assert_eq!(longest, 1);
        }

        #[test]
        fn test_two_direct() {
            let bob_dlg = add_bob();
            let (ancestors, longest) = Operation::from(bob_dlg).ancestors();
            assert_eq!(ancestors.len(), 1);
            assert_eq!(longest, 2);
        }

        #[test]
        fn test_concurrent() {
            let bob_dlg = add_bob();
            let carol_dlg = add_carol();

            let (bob_ancestors, bob_longest) = Operation::from(bob_dlg).ancestors();
            let (carol_ancestors, carol_longest) = Operation::from(carol_dlg).ancestors();

            assert_eq!(bob_ancestors.len(), carol_ancestors.len());
            assert_eq!(bob_longest, carol_longest);
        }

        #[test]
        fn test_longer() {
            let erin_dlg = add_erin();
            let (ancestors, longest) = Operation::from(erin_dlg).ancestors();
            assert_eq!(ancestors.len(), 2);
            assert_eq!(longest, 2);
        }

        #[test]
        fn test_revocation() {
            let rev = remove_carol();
            let (ancestors, longest) = Operation::from(rev).ancestors();
            assert_eq!(ancestors.len(), 2);
            assert_eq!(longest, 2);
        }
    }

    mod topsort {
        use super::*;

        #[test]
        fn test_empty() {
            let dlgs = HashSet::new();
            let revs = HashSet::new();

            let observed = Operation::<String>::topsort(&dlgs, &revs);
            assert_eq!(observed, vec![]);
        }

        #[test]
        fn test_one_delegation() {
            let dlg = add_alice();

            let dlgs = HashSet::from_iter([dlg.dupe()]);
            let revs = HashSet::new();

            let observed = Operation::topsort(&dlgs, &revs);
            let expected = dlg.into();

            assert_eq!(observed, vec![(Digest::hash(&expected), expected)]);
        }

        #[test]
        fn test_delegation_sequence() {
            let alice_dlg = add_alice();
            let bob_dlg = add_bob();

            let dlg_heads = HashSet::from_iter([bob_dlg.dupe()]);
            let rev_heads = HashSet::new();

            let observed = Operation::topsort(&dlg_heads, &rev_heads);

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
            let alice_dlg = add_alice();
            let carol_dlg = add_carol();
            let dan_dlg = add_dan();

            let dlg_heads = HashSet::from_iter([dan_dlg.dupe()]);
            let rev_heads = HashSet::new();

            let mut observed = Operation::topsort(&dlg_heads, &rev_heads);

            let alice_op: Operation<String> = alice_dlg.into();
            let alice_hash = Digest::hash(&alice_op);

            let carol_op: Operation<String> = carol_dlg.into();
            let carol_hash = Digest::hash(&carol_op);

            let dan_op: Operation<String> = dan_dlg.into();
            let dan_hash = Digest::hash(&dan_op);

            let a = (alice_hash, alice_op.clone());
            let c = (carol_hash, carol_op.clone());
            let d = (dan_hash, dan_op.clone());

            assert_eq!(observed.pop(), Some(a));
            assert_eq!(observed.pop(), Some(c));
            assert_eq!(observed.pop(), Some(d));
            assert_eq!(observed.pop(), None);
        }

        #[test]
        fn test_one_revocation() {
            let alice_sk = fixture(&ALICE_SK).clone();
            let alice_dlg = add_alice();
            let bob_dlg = add_bob();

            let alice_revokes_bob = Rc::new(
                Signed::try_sign(
                    Revocation {
                        revoke: bob_dlg.dupe(),
                        proof: Some(alice_dlg.dupe().into()),
                        after_content: BTreeMap::new(),
                    },
                    &alice_sk,
                )
                .unwrap(),
            );
            let rev_op: Operation<String> = alice_revokes_bob.dupe().into();
            let rev_hash = Digest::hash(&rev_op);

            let dlgs = HashSet::new();
            let revs = HashSet::from_iter([alice_revokes_bob.dupe()]);

            let mut observed = Operation::topsort(&dlgs, &revs);

            let alice_op: Operation<String> = alice_dlg.into();
            let alice_hash = Digest::hash(&alice_op);

            let bob_op: Operation<String> = bob_dlg.into();
            let bob_hash = Digest::hash(&bob_op);

            let a = (alice_hash, alice_op.clone());
            let b = (bob_hash, bob_op.clone());
            let r = (rev_hash.coerce(), alice_revokes_bob.into());

            assert_eq!(observed.clone().len(), 3);

            assert_eq!(observed.pop(), Some(a));
            assert_eq!(observed.pop(), Some(b));
            assert_eq!(observed.pop(), Some(r));
            assert_eq!(observed.pop(), None);
        }

        #[test]
        fn test_many_revocations() {
            let alice_dlg = add_alice();
            let bob_dlg = add_bob();

            let carol_dlg = add_carol();
            let dan_dlg = add_dan();
            let erin_dlg = add_erin();

            let alice_revokes_carol = remove_carol();
            let bob_revokes_dan = remove_dan();

            let rev_carol_op: Operation<String> = alice_revokes_carol.dupe().into();
            let rev_carol_hash = Digest::hash(&rev_carol_op);

            let rev_dan_op: Operation<String> = bob_revokes_dan.dupe().into();
            let rev_dan_hash = Digest::hash(&rev_dan_op);

            let dlg_heads = HashSet::from_iter([erin_dlg.dupe()]);
            let rev_heads =
                HashSet::from_iter([alice_revokes_carol.dupe(), bob_revokes_dan.dupe()]);

            let observed = Operation::topsort(&dlg_heads, &rev_heads);

            let alice_op: Operation<String> = alice_dlg.clone().into();
            let alice_hash = Digest::hash(&alice_op);

            let bob_op: Operation<String> = bob_dlg.clone().into();
            let bob_hash = Digest::hash(&bob_op);

            let carol_op: Operation<String> = carol_dlg.clone().into();
            let carol_hash = Digest::hash(&carol_op);

            let dan_op: Operation<String> = dan_dlg.clone().into();
            let dan_hash = Digest::hash(&dan_op);

            let erin_op: Operation<String> = erin_dlg.clone().into();
            let erin_hash = Digest::hash(&erin_op);

            let mut bob_and_revoke_carol = vec![
                (bob_hash, bob_op.clone()),
                (rev_carol_hash, rev_carol_op.clone()),
            ];
            bob_and_revoke_carol.sort_by_key(|(hash, _)| *hash);

            let mut dan_and_erin = vec![(dan_hash, dan_op.clone()), (erin_hash, erin_op.clone())];
            dan_and_erin.sort_by_key(|(hash, _)| *hash);

            let mut revs = vec![(rev_dan_hash, rev_dan_op.clone())];
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
