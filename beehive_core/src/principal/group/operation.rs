pub mod delegation;
pub mod revocation;
pub mod store;

use crate::{
    crypto::{digest::Digest, signed::Signed},
    principal::{document::Document, identifier::Identifier, membered::MemberedId},
    util::content_addressed_map::CaMap,
};
use delegation::Delegation;
use revocation::Revocation;
use serde::Serialize;
use std::{
    cmp::Ordering,
    collections::{BTreeMap, BTreeSet},
    hash::Hash,
};
use thiserror::Error;
use topological_sort::TopologicalSort;

#[derive(Debug, Clone, Hash, Serialize)]
pub enum Operation<T: Serialize> {
    Delegation(Delegation<T>),
    Revocation(Revocation<T>),
}

impl<T: Serialize> Operation<T> {
    pub fn is_delegation(&self) -> bool {
        match self {
            Operation::Delegation(_) => true,
            Operation::Revocation(_) => false,
        }
    }

    pub fn is_revocation(&self) -> bool {
        !self.is_delegation()
    }

    pub fn after(
        &self,
    ) -> (
        &[&Signed<Delegation<T>>],
        &[&Signed<Revocation<T>>],
        &[(&Document<T>, Digest<T>)],
    ) {
        match self {
            Operation::Delegation(delegation) => delegation.after(),
            Operation::Revocation(revocation) => revocation.after(),
        }
    }

    // pub fn subject(&self) -> Option<Identifier> {
    //     match self {
    //         Operation::Delegation(delegation) => delegation.subject(),
    //         Operation::Revocation(revocation) => revocation.subject(),
    //     }
    // }

    pub fn ancestors(
        &self,
        ops: &CaMap<Signed<Operation<T>>>,
    ) -> Result<(CaMap<Signed<Operation<T>>>, usize), AncestorError<T>> {
        if self.after_auth().is_empty() {
            return Ok((CaMap::new(), 0));
        }

        let mut ancestors = BTreeSet::new();
        let mut head_hashes: Vec<(&Digest<Signed<Operation>>, usize)> =
            self.after_auth().iter().map(|hash| (hash, 0)).collect();

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
            return Err(AncestorError::Unrooted);
        }

        Ok(ancestors.into_iter().fold(
            (CaMap::new(), 0),
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

    // FIXME verified gdp

    pub fn topsort(
        mut heads: Vec<Digest<Signed<Operation<T>>>>,
        ops: &CaMap<Signed<Operation<T>>>,
    ) -> Result<Vec<Signed<Operation<T>>>, AncestorError<T>> {
        let mut ops_with_ancestors: BTreeMap<
            Digest<Signed<Operation<T>>>,
            (&Signed<Operation<T>>, CaMap<Signed<Operation<T>>>, usize),
        > = BTreeMap::new();

        while !heads.is_empty() {
            if let Some(hash) = heads.pop() {
                if ops_with_ancestors.contains_key(&hash) {
                    continue;
                }

                if let Some(op) = ops.get(&hash) {
                    let ancestors = op.payload.ancestors(ops)?;
                    ops_with_ancestors.insert(hash.clone(), (op, ancestors.0, ancestors.1));
                } else {
                    return Err(AncestorError::DependencyNotAvailable(hash));
                }
            }
        }

        let mut seen = BTreeSet::new();
        // FIXME use pointers?
        let mut adjacencies: TopologicalSort<Signed<Operation<T>>> =
            topological_sort::TopologicalSort::new();

        for (hash, (op, op_ancestors, longest_path)) in ops_with_ancestors.iter() {
            seen.insert(hash);

            for (other_hash, other_op) in op_ancestors.iter() {
                if let Some((_, other_ancestors, other_longest_path)) =
                    ops_with_ancestors.get(other_hash)
                {
                    let ancestor_set: BTreeSet<Signed<Operation<T>>> =
                        op_ancestors.clone().into_values().collect();

                    let other_ancestor_set: BTreeSet<Signed<Operation<T>>> =
                        other_ancestors.clone().into_values().collect();

                    if ancestor_set.is_subset(&other_ancestor_set) {
                        adjacencies.add_dependency(other_op.clone(), (*op).clone());
                    }

                    if ancestor_set.is_superset(&other_ancestor_set) {
                        adjacencies.add_dependency((*op).clone(), other_op.clone());
                    }

                    // Concurrent, so check revocations
                    if op.payload.is_revocation() {
                        match longest_path.cmp(&other_longest_path) {
                            Ordering::Less => {
                                adjacencies.add_dependency((*op).clone(), other_op.clone())
                            }
                            Ordering::Greater => {
                                adjacencies.add_dependency(other_op.clone(), (*op).clone())
                            }
                            Ordering::Equal => match other_hash.cmp(hash) {
                                Ordering::Less => {
                                    adjacencies.add_dependency((*op).clone(), other_op.clone())
                                }
                                Ordering::Greater => {
                                    adjacencies.add_dependency(other_op.clone(), (*op).clone())
                                }
                                Ordering::Equal => {
                                    todo!("why are you comparing with yourself? LOL")
                                }
                            },
                        }
                    }
                } else {
                    return Err(AncestorError::DependencyNotAvailable(other_hash.clone()));
                }
            }
        }

        Ok(adjacencies.into_iter().collect())
    }
}

impl<T: Serialize> PartialEq for Operation<T> {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Operation::Delegation(lhs), Operation::Delegation(rhs)) => lhs == rhs,
            (Operation::Revocation(lhs), Operation::Revocation(rhs)) => lhs == rhs,
            _ => false,
        }
    }
}

impl<T: Serialize> Eq for Operation<T> {}

impl<T: Serialize> PartialOrd for Operation<T> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        match (self, other) {
            (Operation::Delegation(lhs), Operation::Delegation(rhs)) => lhs.partial_cmp(rhs),
            (Operation::Revocation(lhs), Operation::Revocation(rhs)) => lhs.partial_cmp(rhs),
            (Operation::Delegation(_), Operation::Revocation(_)) => Some(Ordering::Less),
            (Operation::Revocation(_), Operation::Delegation(_)) => Some(Ordering::Greater),
        }
    }
}

impl<T: Serialize> Ord for Operation<T> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.partial_cmp(other).unwrap()
    }
}

impl<T: Serialize> From<Delegation<T>> for Operation<T> {
    fn from(delegation: Delegation<T>) -> Self {
        Operation::Delegation(delegation)
    }
}

impl<T: Serialize> From<Revocation<T>> for Operation<T> {
    fn from(revocation: Revocation<T>) -> Self {
        Operation::Revocation(revocation)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Error)]
pub enum AncestorError<T: Serialize> {
    #[error("Operation history is unrooted")]
    Unrooted,

    #[error("Mismatched subject: {0}")]
    MismatchedSubject(MemberedId<T>),

    #[error("Dependency not available: {0}")]
    DependencyNotAvailable(Digest<Signed<Operation<T>>>),
}

#[cfg(test)]
mod tests {
    // use super::*;

    #[test]
    fn test_topsort() {
        todo!()
    }
}
