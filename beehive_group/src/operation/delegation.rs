use crate::capability::Capability;
use crate::hash::{CAStore, Hash};
use crate::principal::{document::Document, stateful::Stateful, stateless::Stateless};
use topological_sort::DependencyLink;

use super::Operation;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Hash)]
pub struct Delegation {
    pub from: Stateless,
    pub to: Stateful, // FIXME or doc
    pub capability: Capability,
    pub after_auth: Vec<Hash<Operation>>,
    pub after_content: Vec<(Document, Hash<()>)>, // FIXME
}

impl Delegation {
    pub fn to_auth_dependencies(
        &self,
        _store: &CAStore<Operation>,
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
