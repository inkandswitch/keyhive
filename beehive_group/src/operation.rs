use std::collections::BTreeMap;
use topological_sort::{DependencyLink, TopologicalSort};

use crate::capability::Capability;
use crate::hash::Hash;
use crate::principal::agent::Agent;

pub mod delegation;
pub mod revocation;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Operation {
    Delegation(delegation::Delegation),
    Revocation(revocation::Revocation),
}

impl Operation {
    // FIXME replace topoligical_sort with our own conflict resolution mechanism?
    pub fn to_auth_dependencies(
        &self,
        store: &BTreeMap<Hash, Operation>,
    ) -> Vec<DependencyLink<Operation>> {
        match self {
            Operation::Delegation(delegation) => delegation.to_auth_dependencies(store),
            Operation::Revocation(_revocation) => todo!(), // revocation.to_auth_dependencies(),
        }
    }
}

pub fn materialize(
    heads: Vec<Operation>,
    store: BTreeMap<Hash, Operation>,
) -> BTreeMap<Agent, Vec<Capability>> {
    // FIXME use custom linearizer
    let mut linearized = heads
        .into_iter()
        .fold(TopologicalSort::new(), |mut acc, op| {
            let links = op.to_auth_dependencies(&store);
            for link in links {
                acc.add_link(link.clone())
            }

            acc
        });

    let mut materialized: BTreeMap<Agent, Vec<Capability>> = BTreeMap::new();

    while let Some(op) = linearized.next() {
        match op {
            Operation::Delegation(delegation) => {
                materialized.insert(delegation.to.into(), vec![delegation.capability]);
            }
            Operation::Revocation(_revocation) => {
                // FIXME
                todo!();
            }
        }
    }

    materialized
}
