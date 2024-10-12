pub mod delegation;
pub mod revocation;
pub mod store;

use crate::{
    crypto::{hash::Hash, signed::Signed},
    principal::membered::MemberedId,
    util::content_addressed_map::CaMap,
};
use delegation::Delegation;
use revocation::Revocation;
use std::{
    cmp::Ordering,
    collections::{BTreeMap, BTreeSet},
    fmt,
};
use thiserror::Error;
use topological_sort::TopologicalSort;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Operation<'a, T: std::hash::Hash + Clone> {
    Delegation(Delegation<'a, T>),
    Revocation(Revocation<'a, T>),
}

impl<'a, T: std::hash::Hash + Clone> Operation<'a, T> {
    pub fn is_delegation(&self) -> bool {
        match self {
            Operation::Delegation(_) => true,
            Operation::Revocation(_) => false,
        }
    }

    pub fn is_revocation(&self) -> bool {
        !self.is_delegation()
    }

    pub fn after_auth(&self) -> &[Hash<Signed<Operation<'a, T>>>] {
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

    pub fn ancestors(
        &'a self,
        ops: &'a CaMap<Signed<Operation<'a, T>>>,
    ) -> Result<(CaMap<Signed<Operation<'a, T>>>, usize), AncestorError<'a, T>> {
        if self.after_auth().is_empty() {
            return Ok((CaMap::new(), 0));
        }

        let mut ancestors = BTreeSet::new();
        let mut head_hashes: Vec<(&Hash<Signed<Operation>>, usize)> =
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
        mut heads: Vec<Hash<Signed<Operation<'a, T>>>>,
        ops: &CaMap<Signed<Operation<'a, T>>>,
    ) -> Result<Vec<Signed<Operation<'a, T>>>, AncestorError<'a, T>> {
        let mut ops_with_ancestors: BTreeMap<
            Hash<Signed<Operation>>,
            (
                &Signed<Operation<'a, T>>,
                CaMap<Signed<Operation<'a, T>>>,
                usize,
            ),
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
        let mut adjacencies: TopologicalSort<Signed<Operation<'a, T>>> =
            topological_sort::TopologicalSort::new();

        for (hash, (op, op_ancestors, longest_path)) in ops_with_ancestors.iter() {
            seen.insert(hash);

            for (other_hash, other_op) in op_ancestors.iter() {
                if let Some((_, other_ancestors, other_longest_path)) =
                    ops_with_ancestors.get(other_hash)
                {
                    let ancestor_set: BTreeSet<Signed<Operation>> =
                        op_ancestors.clone().into_values().collect();

                    let other_ancestor_set: BTreeSet<Signed<Operation>> =
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

impl<'a, T: std::hash::Hash + Clone> fmt::Display for Operation<'a, T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Operation::Delegation(delegation) => write!(f, "{}", delegation),
            Operation::Revocation(_revocation) => todo!(), // write!(f, "{}", revocation),
        }
    }
}

impl<'a, T: std::hash::Hash + Clone> From<Delegation<'a, T>> for Operation<'a, T> {
    fn from(delegation: Delegation<'a, T>) -> Self {
        Operation::Delegation(delegation)
    }
}

impl<'a, T: std::hash::Hash + Clone> From<Revocation<'a, T>> for Operation<'a, T> {
    fn from(revocation: Revocation<'a, T>) -> Self {
        Operation::Revocation(revocation)
    }
}

impl<'a, T: std::hash::Hash + Clone> From<Operation<'a, T>> for Vec<u8> {
    fn from(op: Operation<'a, T>) -> Self {
        match op {
            Operation::Delegation(delegation) => delegation.clone().into(),
            Operation::Revocation(revocation) => revocation.clone().into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Error)]
pub enum AncestorError<'a, T: std::hash::Hash + Clone> {
    #[error("Operation history is unrooted")]
    Unrooted,

    #[error("Mismatched subject: {0}")]
    MismatchedSubject(MemberedId),

    #[error("Dependency not available: {0}")]
    DependencyNotAvailable(Hash<Signed<Operation<'a, T>>>),
}

#[cfg(test)]
mod tests {
    // use super::*;

    #[test]
    fn test_topsort() {
        todo!()
    }
}
