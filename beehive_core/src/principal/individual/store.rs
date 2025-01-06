// FIXME move stores to crate/principal/store/_store.rs?

use super::{id::IndividualId, Individual};
use dupe::OptionDupedExt;
use std::{cell::RefCell, collections::BTreeMap, rc::Rc};

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct IndividualStore(BTreeMap<IndividualId, Rc<RefCell<Individual>>>);

impl IndividualStore {
    pub fn new() -> Self {
        IndividualStore(BTreeMap::new())
    }

    pub fn insert(&mut self, individual: Rc<RefCell<Individual>>) {
        let id = individual.borrow().id();
        self.0.insert(id, individual);
    }

    pub fn get(&self, id: &IndividualId) -> Option<Rc<RefCell<Individual>>> {
        self.0.get(id).duped()
    }

    pub(crate) fn remove(&mut self, id: &IndividualId) {
        self.0.remove(id);
    }
}
