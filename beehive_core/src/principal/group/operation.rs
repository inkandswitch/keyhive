use crate::crypto::hash::Hash;
use crate::crypto::signed::Signed;
use crate::principal::membered::MemberedId;
use crate::util::content_addressed_map::CaMap;
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
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
            Operation::Delegation(delegation) => delegation.into(),
            Operation::Revocation(revocation) => revocation.into(), // revocation.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Error)]
pub enum AncestorError {
    #[error("Operation history is unrooted")]
    Unrooted,

    #[error("Mismatched subject: {0}")]
    MismatchedSubject(MemberedId),

    #[error("Dependency not available: {0}")]
    DependencyNotAvailable(Hash<Signed<Operation>>),
}

impl Operation {
    pub fn is_delegation(&self) -> bool {
        match self {
            Operation::Delegation(_) => true,
            Operation::Revocation(_) => false,
        }
    }

    pub fn is_revocation(&self) -> bool {
        !self.is_delegation()
    }

    pub fn after_revocations(&self) -> &[Hash<Signed<Operation>>] {
        match self {
            Operation::Delegation(delegation) => delegation.after_revocations.as_slice(),
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
        ops: &'a CaMap<Signed<Operation>>,
    ) -> Result<(CaMap<Signed<Operation>>, usize), AncestorError> {
        if self.after_revocations().is_empty() {
            return Ok((CaMap::new(), 0));
        }

        let mut ancestors = BTreeSet::new();
        let mut head_hashes: Vec<(&Hash<Signed<Operation>>, usize)> = self
            .after_revocations()
            .iter()
            .map(|hash| (hash, 0))
            .collect();

        let mut touched_root = false;

        while let Some((head_hash, longest_known_path)) = head_hashes.pop() {
            if !ops.contains_key(&head_hash) {
                continue;
            }

            let op = ops
                .get(&head_hash)
                .ok_or(AncestorError::DependencyNotAvailable(*head_hash))?;

            if op.payload.subject() != self.subject() {
                return Err(AncestorError::MismatchedSubject(self.subject().clone()));
            }

            ancestors.insert((op.clone(), longest_known_path + 1));

            if op.payload.after_revocations().is_empty() {
                touched_root = true;
            }

            for parent in op.payload.after_revocations() {
                head_hashes.push((parent, longest_known_path + 1));
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
        mut heads: Vec<Hash<Signed<Operation>>>,
        ops: &CaMap<Signed<Operation>>,
    ) -> Result<Vec<Signed<Operation>>, AncestorError> {
        let mut ops_with_ancestors: BTreeMap<
            Hash<Signed<Operation>>,
            (&Signed<Operation>, CaMap<Signed<Operation>>, usize),
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
        let mut adjacencies: TopologicalSort<Signed<Operation>> =
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::hash::Hash;
    use crate::crypto::signed::Signed;
    use crate::principal::agent::Agent;
    use crate::principal::membered::Membered;
    use crate::principal::membered::MemberedId;

    #[test]
    fn test_topsort() {
        // todo!()
    }
}
