pub mod id;

use super::{
    active::Active,
    document::{id::DocumentId, Document},
    group::Group,
    identifier::Identifier,
    individual::{id::IndividualId, Individual},
    membered::Membered,
    verifiable::Verifiable,
};
use crate::{content::reference::ContentRef, crypto::share_key::ShareKey};
use derive_more::From;
use dupe::Dupe;
use ed25519_dalek::VerifyingKey;
use std::{
    cell::RefCell,
    collections::{HashMap, HashSet},
    fmt::{Display, Formatter},
    rc::Rc,
};

/// Immutable union over all agent types.
///
/// This type is very lightweight to clone, since it only contains immutable references to the actual agents.
#[derive(Debug, Clone, PartialEq, Eq, From)]
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

    pub fn agent_id(&self) -> id::AgentId {
        match self {
            Agent::Active(a) => a.borrow().agent_id(),
            Agent::Individual(i) => i.borrow().agent_id(),
            Agent::Group(g) => (*g).borrow().agent_id(),
            Agent::Document(d) => d.borrow().agent_id(),
        }
    }

    pub fn individual_ids(&self) -> HashSet<IndividualId> {
        match self {
            Agent::Active(a) => HashSet::from_iter([a.borrow().id()]),
            Agent::Individual(i) => HashSet::from_iter([i.borrow().id()]),
            Agent::Group(g) => g.borrow().individual_ids(),
            Agent::Document(d) => d.borrow().group.individual_ids(),
        }
    }

    pub fn pick_individual_prekeys(&self, doc_id: DocumentId) -> HashMap<IndividualId, ShareKey> {
        match self {
            Agent::Active(a) => {
                HashMap::from_iter([(a.borrow().id(), a.borrow().pick_prekey(doc_id))])
            }
            Agent::Individual(i) => {
                HashMap::from_iter([(i.borrow().id(), i.borrow().pick_prekey(doc_id))])
            }
            Agent::Group(g) => g.borrow().pick_individual_prekeys(doc_id),
            Agent::Document(d) => d.borrow().group.pick_individual_prekeys(doc_id),
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

impl<T: ContentRef> From<Individual> for Agent<T> {
    fn from(i: Individual) -> Self {
        Agent::Individual(Rc::new(RefCell::new(i)))
    }
}

impl<T: ContentRef> From<Group<T>> for Agent<T> {
    fn from(g: Group<T>) -> Self {
        Agent::Group(Rc::new(RefCell::new(g)))
    }
}

impl<T: ContentRef> From<Membered<T>> for Agent<T> {
    fn from(m: Membered<T>) -> Self {
        match m {
            Membered::Group(g) => g.into(),
            Membered::Document(d) => d.into(),
        }
    }
}

impl<T: ContentRef> From<Document<T>> for Agent<T> {
    fn from(d: Document<T>) -> Self {
        Agent::Document(Rc::new(RefCell::new(d)))
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

impl<T: ContentRef> Display for Agent<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.id())
    }
}
