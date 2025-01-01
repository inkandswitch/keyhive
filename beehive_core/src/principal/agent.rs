use super::{
    active::Active,
    document::{id::DocumentId, Document},
    group::{id::GroupId, Group},
    identifier::Identifier,
    individual::{id::IndividualId, Individual},
    verifiable::Verifiable,
};
use crate::{
    content::reference::ContentRef,
    crypto::{share_key::ShareKey, signer::ed_signer::EdSigner},
};
use dupe::Dupe;
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use std::{
    cell::RefCell,
    collections::{HashMap, HashSet},
    rc::Rc,
};

/// Immutable union over all agent types.
///
/// This type is very lightweight to clone, since it only contains immutable references to the actual agents.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Agent<T: ContentRef, S: EdSigner> {
    Active(Rc<RefCell<Active<S>>>),
    Individual(Rc<RefCell<Individual>>),
    Group(Rc<RefCell<Group<T, S>>>),
    Document(Rc<RefCell<Document<T, S>>>),
}

impl<T: ContentRef, S: EdSigner> Agent<T, S> {
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

    pub fn individual_ids(&self) -> HashSet<IndividualId> {
        match self {
            Agent::Active(a) => {
                let mut ids = HashSet::new();
                ids.insert(a.borrow().id());
                ids
            }
            Agent::Individual(i) => {
                let mut ids = HashSet::new();
                ids.insert(i.borrow().id());
                ids
            }
            Agent::Group(g) => g.borrow().individual_ids(),
            Agent::Document(d) => d.borrow().group.individual_ids(),
        }
    }

    pub fn pick_individual_prekeys(&self, doc_id: DocumentId) -> HashMap<IndividualId, ShareKey> {
        match self {
            Agent::Active(a) => {
                let mut m = HashMap::new();
                m.insert(a.borrow().id(), a.borrow().pick_prekey(doc_id));
                m
            }
            Agent::Individual(i) => {
                let mut m = HashMap::new();
                m.insert(i.borrow().id(), i.borrow().pick_prekey(doc_id));
                m
            }
            Agent::Group(g) => g.borrow().pick_individual_prekeys(doc_id),
            Agent::Document(d) => d.borrow().group.pick_individual_prekeys(doc_id),
        }
    }
}

impl<T: ContentRef, S: EdSigner> Dupe for Agent<T, S> {
    fn dupe(&self) -> Self {
        match self {
            Agent::Active(a) => Agent::Active(a.dupe()),
            Agent::Individual(i) => Agent::Individual(i.dupe()),
            Agent::Group(g) => Agent::Group(g.dupe()),
            Agent::Document(d) => Agent::Document(d.dupe()),
        }
    }
}

impl<T: ContentRef, S: EdSigner> From<Active<S>> for Agent<T, S> {
    fn from(a: Active<S>) -> Self {
        Agent::Active(Rc::new(RefCell::new(a)))
    }
}

impl<T: ContentRef, S: EdSigner> From<Rc<RefCell<Active<S>>>> for Agent<T, S> {
    fn from(a: Rc<RefCell<Active<S>>>) -> Self {
        Agent::Active(a)
    }
}

impl<T: ContentRef, S: EdSigner> From<Individual> for Agent<T, S> {
    fn from(i: Individual) -> Self {
        Agent::Individual(Rc::new(RefCell::new(i)))
    }
}

impl<T: ContentRef, S: EdSigner> From<Rc<RefCell<Individual>>> for Agent<T, S> {
    fn from(i: Rc<RefCell<Individual>>) -> Self {
        Agent::Individual(i)
    }
}

impl<T: ContentRef, S: EdSigner> From<Group<T, S>> for Agent<T, S> {
    fn from(g: Group<T, S>) -> Self {
        Agent::Group(Rc::new(RefCell::new(g)))
    }
}

impl<T: ContentRef, S: EdSigner> From<Rc<RefCell<Group<T, S>>>> for Agent<T, S> {
    fn from(g: Rc<RefCell<Group<T, S>>>) -> Self {
        Agent::Group(g)
    }
}

impl<T: ContentRef, S: EdSigner> From<Document<T, S>> for Agent<T, S> {
    fn from(d: Document<T, S>) -> Self {
        Agent::Document(Rc::new(RefCell::new(d)))
    }
}

impl<T: ContentRef, S: EdSigner> From<Rc<RefCell<Document<T, S>>>> for Agent<T, S> {
    fn from(d: Rc<RefCell<Document<T, S>>>) -> Self {
        Agent::Document(d)
    }
}

impl<T: ContentRef, S: EdSigner> Verifiable for Agent<T, S> {
    fn verifying_key(&self) -> VerifyingKey {
        match self {
            Agent::Active(a) => a.borrow().verifying_key(),
            Agent::Individual(i) => i.borrow().verifying_key(),
            Agent::Group(g) => (*g).borrow().verifying_key(),
            Agent::Document(d) => d.borrow().group.verifying_key(),
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum AgentId {
    ActiveId(IndividualId),
    IndividualId(IndividualId),
    GroupId(GroupId),
    DocumentId(DocumentId),
}

impl AgentId {
    pub fn as_bytes(&self) -> [u8; 32] {
        match self {
            AgentId::ActiveId(i) => i.to_bytes(),
            AgentId::IndividualId(i) => i.to_bytes(),
            AgentId::GroupId(i) => i.to_bytes(),
            AgentId::DocumentId(i) => i.to_bytes(),
        }
    }

    pub fn as_slice(&self) -> &[u8] {
        match self {
            AgentId::ActiveId(i) => i.as_bytes(),
            AgentId::IndividualId(i) => i.as_bytes(),
            AgentId::GroupId(i) => i.as_bytes(),
            AgentId::DocumentId(i) => i.as_bytes(),
        }
    }
}

impl<T: ContentRef, S: EdSigner> From<Agent<T, S>> for AgentId {
    fn from(a: Agent<T, S>) -> Self {
        a.agent_id()
    }
}

impl<T: ContentRef, S: EdSigner> From<&Agent<T, S>> for AgentId {
    fn from(a: &Agent<T, S>) -> Self {
        a.agent_id()
    }
}

impl From<IndividualId> for AgentId {
    fn from(id: IndividualId) -> Self {
        AgentId::IndividualId(id)
    }
}

impl From<GroupId> for AgentId {
    fn from(id: GroupId) -> Self {
        AgentId::GroupId(id)
    }
}

impl From<DocumentId> for AgentId {
    fn from(id: DocumentId) -> Self {
        AgentId::DocumentId(id)
    }
}

impl From<AgentId> for Identifier {
    fn from(id: AgentId) -> Self {
        match id {
            AgentId::ActiveId(i) => i.into(),
            AgentId::IndividualId(i) => i.into(),
            AgentId::GroupId(i) => i.into(),
            AgentId::DocumentId(i) => i.into(),
        }
    }
}
