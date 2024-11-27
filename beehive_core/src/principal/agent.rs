pub mod id;

use super::{
    active::Active,
    document::Document,
    group::Group,
    identifier::Identifier,
    individual::{id::IndividualId, Individual},
    verifiable::Verifiable,
};
use crate::{content::reference::ContentRef, crypto::share_key::ShareKey};
use dupe::Dupe;
use ed25519_dalek::VerifyingKey;
use id::AgentId;
use std::{cell::RefCell, collections::HashMap, rc::Rc};

/// Immutable union over all agent types.
///
/// This type is very lightweight to clone, since it only contains immutable references to the actual agents.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Agent<T: ContentRef> {
    Active(Rc<RefCell<Active>>),
    Individual(Rc<RefCell<Individual>>),
    Group(Rc<RefCell<Group<T>>>),
    Document(Rc<RefCell<Document<T>>>),
}

impl<T: ContentRef> Agent<T> {
    pub fn id(&self) -> Identifier {
        match self {
            Agent::Active(a) => a.borrow().id().into(),
            Agent::Individual(i) => i.borrow().id().into(),
            Agent::Group(g) => (*g).borrow().group_id().into(),
            Agent::Document(d) => d.borrow().doc_id().into(),
        }
    }

    pub fn agent_id(&self) -> AgentId {
        match self {
            Agent::Active(a) => a.borrow().agent_id(),
            Agent::Individual(i) => i.borrow().agent_id(),
            Agent::Group(g) => (*g).borrow().agent_id(),
            Agent::Document(d) => d.borrow().agent_id(),
        }
    }

    // FIXME: Rename
    pub fn individual_ids_with_sampled_prekeys(&self) -> HashMap<IndividualId, ShareKey> {
        match self {
            Agent::Active(a) => {
                let mut m = HashMap::new();
                m.insert(a.borrow().id(), a.borrow().sample_prekey());
                m
            }
            Agent::Individual(i) => {
                let mut m = HashMap::new();
                m.insert(i.borrow().id(), i.borrow().sample_prekey());
                m
            }
            Agent::Group(g) => g.borrow().individual_ids_with_sampled_prekeys(),
            Agent::Document(d) => d.borrow().group.individual_ids_with_sampled_prekeys(),
        }
    }
}

impl<T: ContentRef> Dupe for Agent<T> {
    fn dupe(&self) -> Self {
        match self {
            Agent::Active(a) => Agent::Active(a.dupe()),
            Agent::Individual(i) => Agent::Individual(i.dupe()),
            Agent::Group(g) => Agent::Group(g.dupe()),
            Agent::Document(d) => Agent::Document(d.dupe()),
        }
    }
}

impl<T: ContentRef> From<Active> for Agent<T> {
    fn from(a: Active) -> Self {
        Agent::Active(Rc::new(RefCell::new(a)))
    }
}

impl<T: ContentRef> From<Rc<RefCell<Active>>> for Agent<T> {
    fn from(a: Rc<RefCell<Active>>) -> Self {
        Agent::Active(a)
    }
}

impl<T: ContentRef> From<Individual> for Agent<T> {
    fn from(i: Individual) -> Self {
        Agent::Individual(Rc::new(RefCell::new(i)))
    }
}

impl<T: ContentRef> From<Rc<RefCell<Individual>>> for Agent<T> {
    fn from(i: Rc<RefCell<Individual>>) -> Self {
        Agent::Individual(i)
    }
}

impl<T: ContentRef> From<Group<T>> for Agent<T> {
    fn from(g: Group<T>) -> Self {
        Agent::Group(Rc::new(RefCell::new(g)))
    }
}

impl<T: ContentRef> From<Rc<RefCell<Group<T>>>> for Agent<T> {
    fn from(g: Rc<RefCell<Group<T>>>) -> Self {
        Agent::Group(g)
    }
}

impl<T: ContentRef> From<Document<T>> for Agent<T> {
    fn from(d: Document<T>) -> Self {
        Agent::Document(Rc::new(RefCell::new(d)))
    }
}

impl<T: ContentRef> From<Rc<RefCell<Document<T>>>> for Agent<T> {
    fn from(d: Rc<RefCell<Document<T>>>) -> Self {
        Agent::Document(d)
    }
}

impl<T: ContentRef> From<Agent<T>> for AgentId {
    fn from(a: Agent<T>) -> Self {
        a.agent_id()
    }
}

impl<T: ContentRef> From<&Agent<T>> for AgentId {
    fn from(a: &Agent<T>) -> Self {
        a.agent_id()
    }
}

impl<T: ContentRef> Verifiable for Agent<T> {
    fn verifying_key(&self) -> VerifyingKey {
        match self {
            Agent::Active(a) => a.borrow().verifying_key(),
            Agent::Individual(i) => i.borrow().verifying_key(),
            Agent::Group(g) => (*g).borrow().verifying_key(),
            Agent::Document(d) => d.borrow().group.verifying_key(),
        }
    }
}
