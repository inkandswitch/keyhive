use crate::crypto::hash::{CAStore, Hash};
use crate::principal::agent::Agent;
use crate::principal::membered::Membered;
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;
use topological_sort::TopologicalSort;

pub mod delegation;
pub mod revocation;
pub mod store;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Operation {
    Delegation(delegation::Delegation),
    Revocation(revocation::Revocation),
}

impl From<Operation> for Vec<u8> {
    fn from(op: Operation) -> Self {
        match op {
            Operation::Delegation(_delegation) => todo!(), // delegation.into(),
            Operation::Revocation(_revocation) => todo!(), // revocation.into(),
        }
    }
}

impl Operation {
    pub fn after_auth(&self) -> Vec<Hash<Operation>> {
        match self {
            Operation::Delegation(delegation) => delegation.after_auth.clone(),
            Operation::Revocation(_revocation) => todo!(), // revocation.to_auth_dependencies(),
        }
    }

    //     pub fn subject(&self) -> &Membered {
    //         todo!()
    //         // match self {
    //         //     Operation::Delegation(delegation) => &delegation.subject,
    //         //     Operation::Revocation(revocation) => &revocation.subject,
    //         // }
    //     }
    //
    //     // NOTE: cmplete transitive history
    //     pub fn auth_history_set(&self, store: &CAStore<Operation>) -> BTreeSet<Hash<Operation>> {
    //         let heads: Vec<Hash<Operation>> = match self {
    //             Operation::Delegation(delegation) => delegation.after_auth.clone(),
    //             Operation::Revocation(_revocation) => todo!(), // revocation.to_auth_dependencies(),
    //         };
    //
    //         let mut history: BTreeSet<Hash<Operation>> = BTreeSet::new();
    //
    //         for head in heads.iter() {
    //             loop {
    //                 if let Some(op) = store.get(&head) {
    //                     let mut next_heads = BTreeSet::new();
    //
    //                     for hash in op.after_auth() {
    //                         if history.insert(hash) {
    //                             next_heads.insert(hash);
    //                         }
    //                     }
    //                 } else {
    //                     break;
    //                 }
    //             }
    //         }
    //
    //         history
    //     }
    //
    //     pub fn auth_history_topsort(
    //         &self,
    //         store: &CAStore<Operation>,
    //     ) -> TopologicalSort<Hash<Operation>> {
    //         let mut topsort = TopologicalSort::new();
    //
    //         let mut heads = BTreeSet::from_iter(self.after_auth());
    //         let mut already_seen = BTreeSet::new();
    //
    //         while !heads.is_empty() {
    //             // FIXME clone breaks this?
    //             for head in heads.clone().iter() {
    //                 let h = heads.take(head).expect("FIXME");
    //                 already_seen.insert(h);
    //
    //                 for parent in store.get(head).expect("FIXME").after_auth() {
    //                     heads.insert(parent.clone());
    //                     topsort.add_dependency(parent.clone(), head.clone());
    //                 }
    //             }
    //         }
    //
    //         topsort
    //     }
    //
    //     // FIXME make partial ord?
    //     pub fn compare(
    //         &self,
    //         other: &Operation,
    //         store: &CAStore<Operation>,
    //     ) -> Result<Option<Ordering>, DifferentGroup> {
    //         if self.subject() != other.subject() {
    //             return Err(DifferentGroup);
    //         }
    //
    //         if self == other {
    //             return Ok(Some(Ordering::Equal));
    //         }
    //
    //         let self_auth_history: BTreeSet<Hash<Operation>> = self.auth_history_set(store);
    //         let other_hash: Hash<Operation> = Hash::hash(other.clone());
    //
    //         if self_auth_history.contains(&other_hash) {
    //             return Ok(Some(Ordering::Greater));
    //         }
    //
    //         let self_hash = Hash::hash(self.clone());
    //         let other_auth_history = other.auth_history_set(store);
    //
    //         if other_auth_history.contains(&self_hash) {
    //             return Ok(Some(Ordering::Less));
    //         }
    //
    //         Ok(None)
    //     }
}

// pub struct WipCap<'a> {
//     pub agent: Agent,
//     pub cap: Capability,
//     pub proof: &'a Operation,
//     pub all_ancestors: BTreeSet<&'a Operation>,
// }

// pub struct Materializer<'a> {
//     pub ops: CAStore<Operation>,
//     pub child_table: BTreeMap<Hash<Operation>, Vec<Hash<Operation>>>,
//
//     pub head_horizon: BTreeSet<Hash<Operation>>,
//     pub all_revocations: BTreeSet<Hash<Operation>>,
//
//     pub cap_view: BTreeMap<Agent, WipCap<'a>>,
//     pub revocation_view: BTreeSet<Hash<Operation>>,
// }
//
// pub struct ProvableRevocation {
//     pub revocation: revocation::Revocation,
//     pub revoker_proof: Vec<delegation::Delegation>,
// }
//
// pub struct Stratum {
//     pub delegations: Vec<delegation::Delegation>,
//     pub revocations: BTreeSet<Hash<revocation::Revocation>>,
// }
//
// // pub fn materialize(idb: CAStore<Operation>) -> Vec<()> {
// //     let mut strata: Vec<Stratum> = vec![];
// //
// //     // FIXME invert idb
// //     // play forward, bredth-first
// //     // on first revocation encountered, stop exploring head delegations.
// // }
//
// // impl<'a> Materializer<'a> {
// //     pub fn materialize(&mut self) -> Self {
// //         // - For each head hash
// //         //   - get the operation from the store
// //         //   - get the op's after_auth
// //         //   - for each parent op in after_auth
// //         //     - expect proof that parent is able to perform this action
// //         //       - Trace this, since they may be revoked
// //         //     - walk graph history and add to the child's parent set
// //         //       - expect this to bottom out at an op from the group itself
// //
// //         for hash in self.head_horizon.iter() {
// //             let op = self.ops.get(&hash).expect("FIXME");
// //
// //             for parent in op.after_auth() {
// //                 self.child_table.insert(parent, op.after_auth());
// //             }
// //         }
// //
// //         todo!()
// //     }
// // }
//
// #[derive(Debug, Clone, PartialEq, Eq, Error)]
// #[error("Different group")]
// pub struct DifferentGroup;
//
// // pub struct Store {
// //     store: CAStore<Operation>,
// // }
//
// // impl Store {
// //     pub fn new() -> Self {
// //         Self {
// //             store: CAStore::new(),
// //         }
// //     }
// //
// //     pub fn append(&mut self, op: Operation) {
// //         self.store.insert(op);
// //     }
// //
// //     pub fn materialize(&self, heads: Vec<Operation>) -> BTreeMap<Agent, Vec<Capability>> {
// //         materialize(heads, self.store.clone())
// //     }
// // }
//
// // pub fn materialize(
// //     heads: Vec<Operation>,
// //     store: CAStore<Operation>,
// // ) -> BTreeMap<Agent, Vec<Capability>> {
// //     // FIXME use custom linearizer
// //     let mut linearized = heads
// //         .into_iter()
// //         .fold(TopologicalSort::new(), |mut acc, op| {
// //             let links = op.to_auth_dependencies(&store);
// //             for link in links {
// //                 acc.add_link(link.clone())
// //             }
// //
// //             acc
// //         });
// //
// //     let mut materialized: BTreeMap<Agent, Vec<Capability>> = BTreeMap::new();
// //
// //     while let Some(op) = linearized.next() {
// //         match op {
// //             Operation::Delegation(delegation) => {
// //                 materialized.insert(delegation.to.into(), vec![delegation.capability]);
// //             }
// //             Operation::Revocation(_revocation) => {
// //                 // FIXME
// //                 todo!();
// //             }
// //         }
// //     }
// //
// //     materialized
// // }
