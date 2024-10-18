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

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Hash, Serialize)]
pub enum Operation<'a, T: ContentRef> {
    Delegation(&'a Signed<Delegation<'a, T>>),
    Revocation(&'a Signed<Revocation<'a, T>>),
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

    pub fn after_auth(&'a self) -> Vec<Operation<'a, T>> {
        let (dlgs, revs, _) = self.after();
        dlgs.into_iter()
            .map(|d| d.into())
            .chain(revs.into_iter().map(|r| r.into()))
            .collect()
    }

    pub fn after(
        &'a self,
    ) -> (
        Vec<&'a Signed<Delegation<'a, T>>>,
        Vec<&'a Signed<Revocation<'a, T>>>,
        &'a BTreeMap<&'a Document<'a, T>, Vec<T>>,
    ) {
        match self {
            Operation::Delegation(delegation) => {
                let (dlgs, revs, content) = delegation.payload.after();
                (dlgs, revs.to_vec(), content)
            }
            Operation::Revocation(revocation) => {
                let (dlg, revs, content) = revocation.payload.after();
                (dlg.to_vec(), revs, content)
            }
        }
    }

    pub fn after_content(&self) -> &'a BTreeMap<&'a Document<'a, T>, Vec<T>> {
        match self {
            Operation::Delegation(delegation) => &delegation.payload.after_content,
            Operation::Revocation(revocation) => &revocation.payload.after_content,
        }
    }

    pub fn is_root(&self) -> bool {
        match self {
            Operation::Delegation(delegation) => delegation.payload.is_root(),
            Operation::Revocation(_) => false,
        }
    }

    pub fn ancestors(&'a self) -> Result<(CaMap<Operation<'a, T>>, usize), AncestorError> {
        if self.is_root() {
            return Ok((CaMap::new(), 0));
        }

        let mut ancestors = HashMap::new();
        let mut heads = vec![];

        let after_auth = &self.after_auth();
        for op in after_auth.iter() {
            heads.push((op, 0));
        }

        while let Some(head) = heads.pop() {
            let (op, longest_known_path) = head;

            match ancestors.get(&op) {
                None => continue,
                Some(&count) if count > longest_known_path + 1 => continue,
                _ => {
                    if op.subject() != self.subject() {
                        return Err(AncestorError::MismatchedSubject(op.subject()));
                    }

                    for parent_op in after_auth.iter() {
                        heads.push((parent_op, longest_known_path + 1));
                    }

                    ancestors.insert(op, longest_known_path + 1)
                }
            };
        }

        Ok(ancestors.into_iter().fold(
            (CaMap::new(), 0),
            |(mut acc_set, acc_count), (op, count)| {
                acc_set.insert(op.clone());

                if count > acc_count {
                    (acc_set, count)
                } else {
                    (acc_set, acc_count)
                }
            },
        ))
    }

    pub fn topsort(
        heads: &'a [(Digest<Operation<'a, T>>, Operation<'a, T>)],
    ) -> Result<Vec<(Digest<Operation<'a, T>>, Operation<'a, T>)>, AncestorError> {
        let ops_with_ancestors: HashMap<
            Digest<Operation<'a, T>>,
            (&'a Operation<'a, T>, CaMap<Operation<'a, T>>, usize),
        > = HashMap::from_iter(
            heads
                .iter()
                .map(|(digest, op)| (*digest, (op, CaMap::new(), 0))),
        );

        let mut seen = HashSet::new();
        let mut adjacencies: TopologicalSort<(Digest<Operation<'a, T>>, &Operation<'a, T>)> =
            topological_sort::TopologicalSort::new();

        for (hash, (op, op_ancestors, longest_path)) in ops_with_ancestors.iter() {
            seen.insert(hash);

            for (other_hash, other_op) in op_ancestors.iter() {
                let (_, other_ancestors, other_longest_path) = ops_with_ancestors
                    .get(&other_hash.coerce())
                    .expect("values that we just put there to be there");

                let ancestor_set: HashSet<&Operation<'a, T>> = op_ancestors.values().collect();

                let other_ancestor_set: HashSet<&Operation<'a, T>> =
                    other_ancestors.values().collect();

                if ancestor_set.is_subset(&other_ancestor_set) {
                    adjacencies.add_dependency((*other_hash, other_op), (*hash, *op));
                }

                if ancestor_set.is_superset(&other_ancestor_set) {
                    adjacencies.add_dependency((*hash, *op), (*other_hash, other_op));
                }

                // Concurrent, so check revocations
                if op.is_revocation() {
                    match longest_path.cmp(&other_longest_path) {
                        Ordering::Less => {
                            adjacencies.add_dependency((*hash, *op), (*other_hash, other_op))
                        }
                        Ordering::Greater => {
                            adjacencies.add_dependency((*other_hash, other_op), (*hash, *op))
                        }
                        Ordering::Equal => {
                            match other_hash.cmp(&hash.coerce()) {
                                Ordering::Less => adjacencies
                                    .add_dependency((*hash, *op), (*other_hash, other_op)),
                                Ordering::Greater => adjacencies
                                    .add_dependency((*other_hash, other_op), (*hash, *op)),
                                Ordering::Equal => {}
                            }
                        }
                    }
                }
            }
        }

        let mut acc = vec![];
        for (digest, op) in adjacencies.into_iter() {
            acc.push((digest, op.clone()));
        }

        Ok(acc)
    }
}

impl<'a, T: ContentRef> From<&'a Signed<Delegation<'a, T>>> for Operation<'a, T> {
    fn from(delegation: &'a Signed<Delegation<'a, T>>) -> Self {
        Operation::Delegation(delegation)
    }
}

impl<'a, T: ContentRef> From<&'a Signed<Revocation<'a, T>>> for Operation<'a, T> {
    fn from(revocation: &'a Signed<Revocation<'a, T>>) -> Self {
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
