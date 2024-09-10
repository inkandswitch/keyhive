use std::collections::BTreeMap;
use topological_sort::DependencyLink;

use crate::agent::document::Document;
use crate::agent::stateful::Stateful;
use crate::agent::stateless::Stateless;
use crate::capability::Capability;
use crate::hash::Hash;

use super::Operation;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Hash)]
pub struct Delegation {
    pub from: Stateless,
    pub to: Stateful, // FIXME or doc
    pub capability: Capability,
    pub after_auth: Vec<Hash>, // FIXME newtype auth hash vs doc hash?
    pub after_content: Vec<(Document, Hash)>,
}

impl Delegation {
    pub fn to_auth_dependencies(
        &self,
        _store: &BTreeMap<Hash, Operation>,
    ) -> Vec<DependencyLink<Operation>> {
        todo!()
        // self.after_auth
        //     .into_iter()
        //     .fold(vec![], |&mut acc, link| {
        //         for link in link {
        //             acc.push(link.clone())
        //         }

        //         acc
        //     })
        //     .into()
    }
}
