pub mod delegation;
pub mod revocation;
pub mod store;

use crate::{
    content::reference::ContentRef,
    crypto::{digest::Digest, signed::Signed},
    principal::{document::Document, identifier::Identifier},
    util::content_addressed_map::CaMap,
};
use delegation::Delegation;
use revocation::Revocation;
use serde::Serialize;
use std::{
    cmp::Ordering,
    collections::{BTreeMap, HashMap, HashSet},
    hash::Hash,
};
use thiserror::Error;
use topological_sort::TopologicalSort;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Hash, Serialize)]
pub enum Operation<'a, T: ContentRef> {
    Delegation(Signed<Delegation<'a, T>>),
    Revocation(Signed<Revocation<'a, T>>),
}

impl<'a, T: ContentRef> Operation<'a, T> {
    pub fn subject(&'a self) -> Identifier {
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

    pub fn after(
        &'a self,
    ) -> (
        Vec<&'a Signed<Delegation<'a, T>>>,
        Vec<&'a Signed<Revocation<'a, T>>>,
        &'a BTreeMap<&'a Document<'a, T>, Vec<T>>,
    ) {
        match self {
            Operation::Delegation(delegation) => delegation.payload.after(),
            Operation::Revocation(revocation) => revocation.payload.after(),
        }
    }

    pub fn after_auth(&self) -> Vec<&'a Operation<'a, T>> {
        let (_dlgs, _revs) = match self {
            Operation::Delegation(delegation) => delegation.payload.after_auth(),
            Operation::Revocation(revocation) => revocation.payload.after_auth(),
        };

        todo!()

        // dlgs.into_iter()
        //     .map(|dlg| dlg.into())
        //     .chain(revs.into_iter().map(|rev| &rev.clone().into()))
        //     .collect()
    }

    pub fn ancestors(
        &self,
        ops: &CaMap<Operation<'a, T>>,
    ) -> Result<(CaMap<Operation<'a, T>>, usize), AncestorError> {
        if self.after_auth().is_empty() {
            return Ok((CaMap::new(), 0));
        }

        let mut ancestors = HashSet::new();
        let mut head_hashes: Vec<(&Operation<'a, T>, usize)> =
            self.after_auth().iter().map(|op| (*op, 0)).collect();

        let mut touched_root = false;

        while let Some((op, longest_known_path)) = head_hashes.pop() {
            if ops.contains_key(&head_hash) {
                continue;
            }

            if op.subject() != self.subject() {
                return Err(AncestorError::MismatchedSubject(op.subject()));
            }

            ancestors.insert((op.clone(), longest_known_path + 1));

            let after_auth = op.after_auth();

            if after_auth.is_empty() {
                touched_root = true;
            }

            for parent in after_auth {
                head_hashes.push((parent, longest_known_path + 1));
            }
        }

        // FIXME not possible anymore?
        // if !touched_root {
        //     return Err(AncestorError::Unrooted);
        // }

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

    pub fn topsort(
        mut heads: Vec<&'a Operation<'a, T>>,
        ops: &CaMap<Operation<'a, T>>,
    ) -> Result<Vec<Operation<'a, T>>, AncestorError> {
        let mut ops_with_ancestors: HashMap<
            Digest<Operation<'a, T>>,
            (&Operation<'a, T>, CaMap<Operation<'a, T>>, usize),
        > = HashMap::new();

        while let Some(op) = heads.pop() {
            let digest = Digest::hash(op);
            if ops_with_ancestors.contains_key(&digest) {
                continue;
            }

            let ancestors = op.ancestors(ops)?;
            ops_with_ancestors.insert(digest, (op, ancestors.0, ancestors.1));
        }

        let mut seen = HashSet::new();
        // FIXME use pointers?
        let mut adjacencies: TopologicalSort<Operation<'a, T>> =
            topological_sort::TopologicalSort::new();

        for (hash, (op, op_ancestors, longest_path)) in ops_with_ancestors.iter() {
            seen.insert(hash);

            for (other_hash, other_op) in op_ancestors.iter() {
                if let Some((_, other_ancestors, other_longest_path)) =
                    ops_with_ancestors.get(other_hash)
                {
                    let ancestor_set: HashSet<Operation<'a, T>> =
                        op_ancestors.clone().into_values().collect();

                    let other_ancestor_set: HashSet<Operation<'a, T>> =
                        other_ancestors.clone().into_values().collect();

                    if ancestor_set.is_subset(&other_ancestor_set) {
                        adjacencies.add_dependency(other_op.clone(), (*op).clone());
                    }

                    if ancestor_set.is_superset(&other_ancestor_set) {
                        adjacencies.add_dependency((*op).clone(), other_op.clone());
                    }

                    // Concurrent, so check revocations
                    if op.is_revocation() {
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
                    todo!("FIXME I think we can assume that the dependency is in the index")
                    // return Err(AncestorError::DependencyNotAvailable(other_hash.clone()));
                }
            }
        }

        Ok(adjacencies.into_iter().collect())
    }
}

impl<'a, T: ContentRef> From<Signed<Delegation<'a, T>>> for Operation<'a, T> {
    fn from(delegation: Signed<Delegation<'a, T>>) -> Self {
        Operation::Delegation(delegation)
    }
}

impl<'a, T: ContentRef> From<Signed<Revocation<'a, T>>> for Operation<'a, T> {
    fn from(revocation: Signed<Revocation<'a, T>>) -> Self {
        Operation::Revocation(revocation)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Error)]
pub enum AncestorError {
    // #[error("Operation history is unrooted")]
    // Unrooted,
    #[error("Mismatched subject: {0}")]
    MismatchedSubject(Identifier),
    // #[error("Dependency not available: {0}")]
    // DependencyNotAvailable(Digest<Operation<'a, T>>),
}

#[cfg(test)]
mod tests {
    // use super::*;

    #[test]
    fn test_topsort() {
        todo!()
    }
}
