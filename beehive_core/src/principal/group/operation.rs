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
use thiserror::Error;
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

    pub fn ancestors(&self) -> Result<(CaMap<Operation<T>>, usize), AncestorError<T>> {
        if self.is_root() {
            return Ok((CaMap::new(), 0));
        }

        let mut ancestors = HashMap::new();
        let mut heads = vec![];

        let after_auth = self.after_auth();
        for op in after_auth.iter() {
            heads.push((op.dupe(), 0));
        }

        while let Some(head) = heads.pop() {
            let (op, longest_known_path) = head;

            match ancestors.get(&op) {
                None => ancestors.insert(op, longest_known_path + 1),
                Some(&count) if count > longest_known_path + 1 => continue,
                _ => {
                    if op.subject() != self.subject() {
                        return Err(AncestorError::MismatchedSubject(op.subject()));
                    }

                    for parent_op in after_auth.iter() {
                        heads.push((parent_op.dupe(), longest_known_path + 1));
                    }

                    ancestors.insert(op, longest_known_path + 1)
                }
            };
        }

        Ok(ancestors.into_iter().fold(
            (CaMap::new(), 0),
            |(mut acc_set, acc_count), (op, count)| {
                acc_set.insert(Rc::new(op.clone()));

                if count > acc_count {
                    (acc_set, count)
                } else {
                    (acc_set, acc_count)
                }
            },
        ))
    }

    pub fn topsort(
        delegation_heads: &HashSet<Rc<Signed<Delegation<T>>>>,
        revocation_heads: &HashSet<Rc<Signed<Revocation<T>>>>,
    ) -> Result<Vec<(Digest<Operation<T>>, Operation<T>)>, AncestorError<T>> {
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
            let (ancestors, longest_path) = op.ancestors()?;

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

                if ancestor_set.is_subset(&other_ancestor_set) {
                    leftovers.remove(other_op);
                    adjacencies.add_dependency((*other_digest, other_op.as_ref()), (*digest, op));
                    continue;
                }

                if ancestor_set.is_superset(&other_ancestor_set) {
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

                leftovers.insert(op.clone());
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
        Ok(history)
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

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Error)]
pub enum AncestorError<T: ContentRef> {
    #[error("Mismatched subject: {0}")]
    MismatchedSubject(Identifier),

    #[error("Dependency not available: {0}")]
    DependencyNotAvailable(Digest<Operation<T>>),
}

#[cfg(test)]
mod tests {
    use super::*;

    mod topsort {
        use super::*;
        use crate::{access::Access, principal::individual::Individual};
        use dupe::Dupe;
        use std::rc::Rc;

        #[test]
        fn test_empty() {
            let dlgs = HashSet::new();
            let revs = HashSet::new();

            let observed = Operation::<String>::topsort(&dlgs, &revs);
            assert_eq!(observed, Ok(vec![]));
        }

        #[test]
        fn test_one_delegation() {
            let alice: Individual = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng())
                .verifying_key()
                .into();

            let sk = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());

            let dlg: Rc<Signed<Delegation<String>>> = Rc::new(
                Signed::try_sign(
                    Delegation {
                        delegate: alice.into(),
                        can: Access::Write,
                        proof: None,
                        after_content: BTreeMap::new(),
                        after_revocations: vec![],
                    },
                    &sk,
                )
                .unwrap(),
            );

            let dlgs = HashSet::from_iter([dlg.dupe()]);
            let revs = HashSet::new();

            let observed = Operation::topsort(&dlgs, &revs);
            let expected = dlg.into();

            assert_eq!(observed, Ok(vec![(Digest::hash(&expected), expected)]));
        }

        #[test]
        fn test_delegation_sequence() {
            let root_sk = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());

            let alice_sk = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
            let alice: Individual = alice_sk.verifying_key().into();

            let bob: Individual = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng())
                .verifying_key()
                .into();

            let alice_dlg: Rc<Signed<Delegation<String>>> = Rc::new(
                Signed::try_sign(
                    Delegation {
                        delegate: alice.into(),
                        can: Access::Write,
                        proof: None,
                        after_content: BTreeMap::new(),
                        after_revocations: vec![],
                    },
                    &root_sk,
                )
                .unwrap(),
            );

            let bob_dlg: Rc<Signed<Delegation<String>>> = Rc::new(
                Signed::try_sign(
                    Delegation {
                        delegate: bob.into(),
                        can: Access::Write,
                        proof: Some(alice_dlg.dupe().into()),
                        after_content: BTreeMap::new(),
                        after_revocations: vec![],
                    },
                    &alice_sk,
                )
                .unwrap(),
            );
            let dlg_heads = HashSet::from_iter([bob_dlg.dupe()]);
            let rev_heads = HashSet::new();

            let observed = Operation::topsort(&dlg_heads, &rev_heads);

            let alice_op = alice_dlg.into();
            let bob_op = bob_dlg.into();

            let expected = vec![
                (Digest::hash(&bob_op), bob_op),
                (Digest::hash(&alice_op), alice_op),
            ];

            assert_eq!(observed.clone().unwrap().len(), 2);
            assert_eq!(observed, Ok(expected));
        }

        #[test]
        fn test_longer_delegation_chain() {
            let root_sk = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());

            let alice_sk = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
            let alice: Individual = alice_sk.verifying_key().into();

            let bob_sk = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
            let bob: Individual = bob_sk.verifying_key().into();

            let carol: Individual = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng())
                .verifying_key()
                .into();

            let alice_dlg: Rc<Signed<Delegation<String>>> = Rc::new(
                Signed::try_sign(
                    Delegation {
                        delegate: alice.into(),
                        can: Access::Write,
                        proof: None,
                        after_content: BTreeMap::new(),
                        after_revocations: vec![],
                    },
                    &root_sk,
                )
                .unwrap(),
            );

            let bob_dlg: Rc<Signed<Delegation<String>>> = Rc::new(
                Signed::try_sign(
                    Delegation {
                        delegate: bob.into(),
                        can: Access::Write,
                        proof: Some(alice_dlg.dupe().into()),
                        after_content: BTreeMap::new(),
                        after_revocations: vec![],
                    },
                    &alice_sk,
                )
                .unwrap(),
            );

            let carol_dlg: Rc<Signed<Delegation<String>>> = Rc::new(
                Signed::try_sign(
                    Delegation {
                        delegate: carol.into(),
                        can: Access::Read,
                        proof: Some(bob_dlg.dupe().into()),
                        after_content: BTreeMap::new(),
                        after_revocations: vec![],
                    },
                    &bob_sk,
                )
                .unwrap(),
            );

            let dlg_heads = HashSet::from_iter([carol_dlg.dupe()]);
            let rev_heads = HashSet::new();

            let mut observed = Operation::topsort(&dlg_heads, &rev_heads).unwrap();

            let alice_op: Operation<String> = alice_dlg.into();
            let alice_hash = Digest::hash(&alice_op);

            let bob_op: Operation<String> = bob_dlg.into();
            let bob_hash = Digest::hash(&bob_op);

            let carol_op: Operation<String> = carol_dlg.into();
            let carol_hash = Digest::hash(&carol_op);

            let a = (alice_hash, alice_op.clone());
            let b = (bob_hash, bob_op.clone());
            let c = (carol_hash, carol_op.clone());

            assert_eq!(observed.pop(), Some(a));
            assert_eq!(observed.pop(), Some(b));
            assert_eq!(observed.pop(), Some(c));
            assert_eq!(observed.pop(), None);
        }

        #[test]
        fn test_one_revocation() {
            let root_sk = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());

            let alice_sk = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
            let alice: Individual = alice_sk.verifying_key().into();

            let bob: Individual = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng())
                .verifying_key()
                .into();

            let alice_dlg: Rc<Signed<Delegation<String>>> = Rc::new(
                Signed::try_sign(
                    Delegation {
                        delegate: alice.into(),
                        can: Access::Write,
                        proof: None,
                        after_content: BTreeMap::new(),
                        after_revocations: vec![],
                    },
                    &root_sk,
                )
                .unwrap(),
            );

            let bob_dlg: Rc<Signed<Delegation<String>>> = Rc::new(
                Signed::try_sign(
                    Delegation {
                        delegate: bob.into(),
                        can: Access::Write,
                        proof: Some(alice_dlg.dupe().into()),
                        after_content: BTreeMap::new(),
                        after_revocations: vec![],
                    },
                    &alice_sk,
                )
                .unwrap(),
            );

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

            let mut observed = Operation::topsort(&dlgs, &revs).unwrap();

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
            let root_sk = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());

            let alice_sk = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
            let alice: Individual = alice_sk.verifying_key().into();

            let bob_sk = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
            let bob: Individual = bob_sk.verifying_key().into();

            let carol_sk = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
            let carol: Individual = carol_sk.verifying_key().into();

            let dan_sk = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
            let dan: Individual = dan_sk.verifying_key().into();

            let erin_sk = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
            let erin: Individual = erin_sk.verifying_key().into();

            let alice_dlg: Rc<Signed<Delegation<String>>> = Rc::new(
                Signed::try_sign(
                    Delegation {
                        delegate: alice.into(),
                        can: Access::Admin,
                        proof: None,
                        after_content: BTreeMap::new(),
                        after_revocations: vec![],
                    },
                    &root_sk,
                )
                .unwrap(),
            );

            let bob_dlg: Rc<Signed<Delegation<String>>> = Rc::new(
                Signed::try_sign(
                    Delegation {
                        delegate: bob.into(),
                        can: Access::Write,
                        proof: Some(alice_dlg.dupe()),
                        after_content: BTreeMap::new(),
                        after_revocations: vec![],
                    },
                    &alice_sk,
                )
                .unwrap(),
            );

            let carol_dlg: Rc<Signed<Delegation<String>>> = Rc::new(
                Signed::try_sign(
                    Delegation {
                        delegate: carol.into(),
                        can: Access::Write,
                        proof: Some(alice_dlg.dupe()),
                        after_content: BTreeMap::new(),
                        after_revocations: vec![],
                    },
                    &alice_sk,
                )
                .unwrap(),
            );

            let dan_dlg: Rc<Signed<Delegation<String>>> = Rc::new(
                Signed::try_sign(
                    Delegation {
                        delegate: dan.into(),
                        can: Access::Write,
                        proof: Some(carol_dlg.dupe()),
                        after_content: BTreeMap::new(),
                        after_revocations: vec![],
                    },
                    &carol_sk,
                )
                .unwrap(),
            );

            let erin_dlg: Rc<Signed<Delegation<String>>> = Rc::new(
                Signed::try_sign(
                    Delegation {
                        delegate: erin.into(),
                        can: Access::Write,
                        proof: Some(bob_dlg.dupe()),
                        after_content: BTreeMap::new(),
                        after_revocations: vec![],
                    },
                    &bob_sk,
                )
                .unwrap(),
            );

            let alice_revokes_carol = Rc::new(
                Signed::try_sign(
                    Revocation {
                        revoke: carol_dlg.dupe(),
                        proof: Some(alice_dlg.dupe()),
                        after_content: BTreeMap::new(),
                    },
                    &alice_sk,
                )
                .unwrap(),
            );

            let bob_revokes_dan = Rc::new(
                Signed::try_sign(
                    Revocation {
                        revoke: dan_dlg.dupe(),
                        proof: Some(bob_dlg.dupe()),
                        after_content: BTreeMap::new(),
                    },
                    &bob_sk,
                )
                .unwrap(),
            );

            let rev_carol_op: Operation<String> = alice_revokes_carol.dupe().into();
            let rev_carol_hash = Digest::hash(&rev_carol_op);
            dbg!(&rev_carol_hash);

            let rev_dan_op: Operation<String> = bob_revokes_dan.dupe().into();
            let rev_dan_hash = Digest::hash(&rev_dan_op);
            dbg!(&rev_dan_hash);

            let dlg_heads = HashSet::from_iter([erin_dlg.dupe()]);
            let rev_heads =
                HashSet::from_iter([alice_revokes_carol.dupe(), bob_revokes_dan.dupe()]);

            let mut observed = Operation::topsort(&dlg_heads, &rev_heads).unwrap();

            let alice_op: Operation<String> = alice_dlg.clone().into();
            let alice_hash = Digest::hash(&alice_op);
            dbg!(alice_hash);

            let bob_op: Operation<String> = bob_dlg.clone().into();
            let bob_hash = Digest::hash(&bob_op);
            dbg!(bob_hash);

            let carol_op: Operation<String> = carol_dlg.clone().into();
            let carol_hash = Digest::hash(&carol_op);
            dbg!(carol_hash);

            let dan_op: Operation<String> = dan_dlg.clone().into();
            let dan_hash = Digest::hash(&dan_op);
            dbg!(dan_hash);

            let erin_op: Operation<String> = erin_dlg.clone().into();
            let erin_hash = Digest::hash(&erin_op);
            dbg!(erin_hash);

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
            assert!(pos_alice > pos_bob);
            assert!(pos_alice > pos_carol);
            assert!(pos_alice > pos_erin);
            assert!(pos_bob > pos_erin);
            assert!(pos_carol > pos_dan);
            assert!(pos_carol > pos_rev_carol);
            assert!(pos_carol > pos_rev_dan);
            assert!(pos_dan > pos_rev_dan);
        }
    }
}
