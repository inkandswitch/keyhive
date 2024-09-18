pub mod delegation;
pub mod revocation;
pub mod store;

use crate::crypto::hash::{CAStore, Hash};
use crate::crypto::signed::Signed;
use crate::principal::agent::Agent;
use crate::principal::membered::Membered;
use crate::principal::membered::MemberedId;
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use thiserror::Error;
use topological_sort::TopologicalSort;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Operation {
    Delegation(delegation::Delegation),
    Revocation(revocation::Revocation),
}

impl fmt::Display for Operation {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Operation::Delegation(delegation) => write!(f, "{}", delegation),
            Operation::Revocation(_revocation) => todo!(), // write!(f, "{}", revocation),
        }
    }
}

impl From<delegation::Delegation> for Operation {
    fn from(delegation: delegation::Delegation) -> Self {
        Operation::Delegation(delegation)
    }
}

impl From<revocation::Revocation> for Operation {
    fn from(revocation: revocation::Revocation) -> Self {
        Operation::Revocation(revocation)
    }
}

impl From<Operation> for Vec<u8> {
    fn from(op: Operation) -> Self {
        match op {
            Operation::Delegation(_delegation) => todo!(), // delegation.into(),
            Operation::Revocation(_revocation) => todo!(), // revocation.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Error)]
pub enum AncestorError {
    #[error("Mismatched subject: {0}")]
    MismatchedSubject(MemberedId),

    #[error("Unrooted: {0:?}")] // FIXME debug
    Unrooted(BTreeSet<Signed<Operation>>),

    #[error("Dependency not available: {0}")]
    DependencyNotAvailable(Hash<Signed<Operation>>),
}

impl Operation {
    pub fn after_auth(&self) -> &[Hash<Signed<Operation>>] {
        match self {
            Operation::Delegation(delegation) => &delegation.after_auth.as_slice(),
            Operation::Revocation(_revocation) => todo!(), // revocation.to_auth_dependencies(),
        }
    }

    pub fn subject(&self) -> &MemberedId {
        match self {
            Operation::Delegation(delegation) => &delegation.subject,
            Operation::Revocation(revocation) => &revocation.subject,
        }
    }

    pub fn ancestors<'a>(
        &'a self,
        ops: &'a CAStore<Signed<Operation>>,
    ) -> Result<(BTreeSet<Signed<Operation>>, usize), AncestorError> {
        if self.after_auth().is_empty() {
            return Ok((BTreeSet::new(), 0));
        }

        let mut ancestors = BTreeSet::new();
        let mut head_hashes: Vec<(&Hash<Signed<Operation>>, usize)> =
            self.after_auth().iter().map(|hash| (&hash, 0)).collect();

        let mut touched_root = false;

        while !head_hashes.is_empty() {
            if let Some((head_hash, longest_known_path)) = head_hashes.pop() {
                if ops.contains_key(&head_hash) {
                    continue;
                }

                if let Some(op) = ops.get(&head_hash) {
                    if op.payload.subject() != self.subject() {
                        return Err(AncestorError::MismatchedSubject(self.subject().clone()));
                    }

                    ancestors.insert((op.clone(), longest_known_path + 1));

                    if op.payload.after_auth().is_empty() {
                        touched_root = true;
                    }

                    for parent in op.payload.after_auth() {
                        head_hashes.push((parent, longest_known_path + 1));
                    }
                } else {
                    return Err(AncestorError::DependencyNotAvailable(*head_hash));
                }
            }
        }

        if !touched_root {
            todo!()
            // return Err(AncestorError::Unrooted(ancestors.0));
        }

        Ok(ancestors.into_iter().fold(
            (BTreeSet::new(), 0),
            |(mut acc_set, acc_count), (op, count)| {
                acc_set.insert(op);
                if count > acc_count {
                    (acc_set, count)
                } else {
                    (acc_set, acc_count)
                }
            },
        ))
    }

    pub fn topsort(
        mut heads: Vec<Hash<Signed<Operation>>>,
        ops: &CAStore<Signed<Operation>>,
    ) -> Result<Vec<Signed<Operation>>, AncestorError> {
        let mut ops_with_ancestors: BTreeMap<
            Hash<Signed<Operation>>,
            (&Signed<Operation>, BTreeSet<Signed<Operation>>, usize),
        > = BTreeMap::new();

        let mut sorted = vec![];

        while !heads.is_empty() {
            if let Some(hash) = heads.pop() {
                if ops_with_ancestors.contains_key(head) {
                    continue;
                }

                if let Some(op) = ops.get(&hash) {
                    let ancestors = op.payload.ancestors(ops)?;
                    let longest_path = todo!("Find longest path");
                    ops_with_ancestors.insert(hash.clone(), (op, ancestors, longest_path));
                } else {
                    return Err(AncestorError::DependencyNotAvailable(hash));
                }
            }
        }

        // let mut graph = BTreeMap::new();
        // for (hash, op) in ops.iter() {
        //     let after_auth = op.payload.after_auth();
        //     for parent in after_auth {
        //         graph
        //             .entry(parent.clone())
        //             .or_insert_with(Vec::new)
        //             .push(hash.clone());
        //     }
        // }

        // let mut sorted = Vec::new();
        // let mut visited = BTreeSet::new();
        // let mut stack = Vec::new();

        // for (hash, _) in ops.iter() {
        //     stack.push(hash.clone());
        //     while let Some(node) = stack.pop() {
        //         if visited.contains(&node) {
        //             continue;
        //         }

        //         if let Some(children) = graph.get(&node) {
        //             stack.push(node.clone());
        //             for child in children {
        //                 stack.push(child.clone());
        //             }
        //         } else {
        //             visited.insert(node.clone());
        //             sorted.push(ops.get(&node).unwrap());
        //         }
        //     }
        // }

        Ok(sorted)
    }
}
