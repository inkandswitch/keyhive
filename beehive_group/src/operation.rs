use crate::crypto::hash::{CAStore, Hash};
use crate::crypto::signed::Signed;
use crate::principal::agent::Agent;
use crate::principal::membered::Membered;
use crate::principal::membered::MemberedId;
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;
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

pub enum AncestorError<'a> {
    MismatchedSubject(&'a MemberedId),
    Unrooted(BTreeSet<&'a Signed<Operation>>),
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
    ) -> Result<BTreeSet<&'a Signed<Operation>>, AncestorError<'a>> {
        if self.after_auth().is_empty() {
            return Ok(BTreeSet::new());
        }

        let mut ancestors = BTreeSet::new();
        let mut head_hashes: Vec<Hash<Signed<Operation>>> = self.after_auth().to_vec();
        let mut touched_root = false;

        while !head_hashes.is_empty() {
            if let Some(head_hash) = head_hashes.pop() {
                if let Some(op) = ops.get(&head_hash) {
                    if op.payload.subject() != self.subject() {
                        return Err(AncestorError::MismatchedSubject(&self.subject()));
                    }

                    ancestors.insert(op);

                    if op.payload.after_auth().is_empty() {
                        touched_root = true;
                    }

                    for parent in op.payload.after_auth() {
                        head_hashes.push(parent.clone());
                    }
                } else {
                    return Err(AncestorError::DependencyNotAvailable(head_hash));
                }
            }
        }

        if !touched_root {
            return Err(AncestorError::Unrooted(ancestors));
        }

        Ok(ancestors)
    }
}
