pub mod delegation;
pub mod revocation;
pub mod store;

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
use revocation::Revocation;
use serde::Serialize;
use std::{
    cmp::Ordering,
    collections::{BTreeMap, HashMap, HashSet},
    hash::Hash,
    rc::Rc,
};
use thiserror::Error;
use topological_sort::TopologicalSort;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Hash)]
pub enum Operation<'a, T: ContentRef> {
    Delegation(Rc<Signed<Delegation<'a, T>>>),
    Revocation(Rc<Signed<Revocation<'a, T>>>),
}

impl<'a, T: ContentRef + Serialize> Serialize for Operation<'a, T> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Operation::Delegation(delegation) => delegation.serialize(serializer),
            Operation::Revocation(revocation) => revocation.serialize(serializer),
        }
    }
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
        Vec<Rc<Signed<Delegation<'a, T>>>>,
        Vec<Rc<Signed<Revocation<'a, T>>>>,
        &'a BTreeMap<DocumentId, (&'a Document<'a, T>, Vec<T>)>,
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

    pub fn after_content(&'a self) -> &'a BTreeMap<DocumentId, (&'a Document<'a, T>, Vec<T>)> {
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
                        return Err(AncestorError::MismatchedSubject(op.subject().into()));
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
                acc_set.insert(Rc::new(op.clone())); // FIXME move RCs out of CaMap

                if count > acc_count {
                    (acc_set, count)
                } else {
                    (acc_set, acc_count)
                }
            },
        ))
    }

    pub fn topsort(
        heads: &[(Digest<Operation<'a, T>>, Operation<'a, T>)],
    ) -> Result<Vec<(Digest<Operation<'a, T>>, Operation<'a, T>)>, AncestorError> {
        let ops_with_ancestors: Rc<
            HashMap<
                Digest<Operation<'a, T>>,
                (&'a Operation<'a, T>, CaMap<Operation<'a, T>>, usize),
            >,
        > = HashMap::from_iter(
            heads
                .iter()
                .map(|(digest, op)| (*digest, (op, CaMap::new(), 0))),
        );

        let mut seen = HashSet::new();
        let mut adjacencies: TopologicalSort<(Digest<Operation<'a, T>>, &Operation<'a, T>)> =
            topological_sort::TopologicalSort::new();

        for (digest, (op, op_ancestors, longest_path)) in ops_with_ancestors.iter() {
            seen.insert(digest);

            for (other_digest, other_op) in op_ancestors.iter() {
                let (_, other_ancestors, other_longest_path) = ops_with_ancestors
                    .get(&other_digest.coerce())
                    .expect("values that we just put there to be there");

                let ancestor_set: HashSet<&Operation<'a, T>> =
                    op_ancestors.values().map(|op| op.as_ref()).collect();

                let other_ancestor_set: HashSet<&Operation<'a, T>> =
                    other_ancestors.values().map(|op| op.as_ref()).collect();

                if ancestor_set.is_subset(&other_ancestor_set) {
                    adjacencies.add_dependency((*other_digest, other_op.as_ref()), (*digest, *op));
                }

                if ancestor_set.is_superset(&other_ancestor_set) {
                    adjacencies.add_dependency((*digest, *op), (*other_digest, other_op.as_ref()));
                }

                // Concurrent, so check revocations
                if op.is_revocation() {
                    match longest_path.cmp(&other_longest_path) {
                        Ordering::Less => adjacencies
                            .add_dependency((*digest, *op), (*other_digest, other_op.as_ref())),
                        Ordering::Greater => adjacencies
                            .add_dependency((*other_digest, other_op.as_ref()), (*digest, *op)),
                        Ordering::Equal => match other_digest.cmp(&digest.coerce()) {
                            Ordering::Less => adjacencies
                                .add_dependency((*digest, *op), (*other_digest, other_op.as_ref())),
                            Ordering::Greater => adjacencies
                                .add_dependency((*other_digest, other_op.as_ref()), (*digest, *op)),
                            Ordering::Equal => {}
                        },
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

impl<'a, T: ContentRef> From<Rc<Signed<Delegation<'a, T>>>> for Operation<'a, T> {
    fn from(delegation: Rc<Signed<Delegation<'a, T>>>) -> Self {
        Operation::Delegation(delegation)
    }
}

impl<'a, T: ContentRef> From<Rc<Signed<Revocation<'a, T>>>> for Operation<'a, T> {
    fn from(revocation: Rc<Signed<Revocation<'a, T>>>) -> Self {
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
