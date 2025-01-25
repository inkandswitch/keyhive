use super::{
    agent::{id::AgentId, Agent},
    document::{id::DocumentId, Document},
    group::Group,
    identifier::Identifier,
    individual::{id::IndividualId, Individual},
};
use crate::{
    content::reference::ContentRef,
    crypto::share_key::ShareKey,
    listener::{membership::MembershipListener, no_listener::NoListener},
};
use derive_more::{From, TryInto};
use dupe::Dupe;
use std::{
    cell::RefCell,
    collections::{HashMap, HashSet},
    fmt::{Display, Formatter},
    rc::Rc,
};
use thiserror::Error;

/// An [`Agent`] minus the current user.
#[derive(Debug, Clone, Dupe, PartialEq, Eq, From, TryInto)]
pub enum Peer<T: ContentRef = [u8; 32], L: MembershipListener<T> = NoListener> {
    Individual(Rc<RefCell<Individual>>),
    Group(Rc<RefCell<Group<T, L>>>),
    Document(Rc<RefCell<Document<T, L>>>),
}

impl<T: ContentRef, L: MembershipListener<T>> Peer<T, L> {
    pub fn id(&self) -> Identifier {
        match self {
            Peer::Individual(i) => i.borrow().id().into(),
            Peer::Group(g) => (*g).borrow().group_id().into(),
            Peer::Document(d) => d.borrow().doc_id().into(),
        }
    }

    pub fn agent_id(&self) -> AgentId {
        match self {
            Peer::Individual(i) => i.borrow().agent_id(),
            Peer::Group(g) => (*g).borrow().agent_id(),
            Peer::Document(d) => d.borrow().agent_id(),
        }
    }

    pub fn individual_ids(&self) -> HashSet<IndividualId> {
        match self {
            Peer::Individual(i) => HashSet::from_iter([i.borrow().id()]),
            Peer::Group(g) => g.borrow().individual_ids(),
            Peer::Document(d) => d.borrow().group.individual_ids(),
        }
    }

    pub fn pick_individual_prekeys(&self, doc_id: DocumentId) -> HashMap<IndividualId, ShareKey> {
        match self {
            Peer::Individual(i) => {
                if let Some(prekey) = i.borrow().pick_prekey(doc_id) {
                    HashMap::from_iter([(i.borrow().id(), prekey)])
                } else {
                    HashMap::new()
                }
            }
            Peer::Group(g) => g.borrow().pick_individual_prekeys(doc_id),
            Peer::Document(d) => d.borrow().group.pick_individual_prekeys(doc_id),
        }
    }
}

impl<T: ContentRef, L: MembershipListener<T>> Display for Peer<T, L> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        self.id().fmt(f)
    }
}

impl<T: ContentRef, L: MembershipListener<T>> From<Peer<T, L>> for Agent<T, L> {
    fn from(peer: Peer<T, L>) -> Self {
        match peer {
            Peer::Individual(individual) => Agent::Individual(individual),
            Peer::Group(group) => Agent::Group(group),
            Peer::Document(document) => Agent::Document(document),
        }
    }
}

impl<T: ContentRef, L: MembershipListener<T>> TryFrom<Agent<T, L>> for Peer<T, L> {
    type Error = ActiveUserIsNotAPeer;

    fn try_from(agent: Agent<T, L>) -> Result<Self, Self::Error> {
        match agent {
            Agent::Individual(individual) => Ok(Peer::Individual(individual)),
            Agent::Group(group) => Ok(Peer::Group(group)),
            Agent::Document(document) => Ok(Peer::Document(document)),
            Agent::Active(_) => Err(ActiveUserIsNotAPeer),
        }
    }
}

#[derive(Debug, Error)]
#[error("The active user is not a peer")]
pub struct ActiveUserIsNotAPeer;
