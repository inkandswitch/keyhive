use super::{
    agent::{id::AgentId, Agent},
    document::{id::DocumentId, Document},
    group::Group,
    identifier::Identifier,
    individual::{id::IndividualId, Individual},
};
use crate::{
    content::reference::ContentRef,
    crypto::{
        share_key::{ShareKey, ShareSecretStore},
        signer::async_signer::AsyncSigner,
    },
    listener::{membership::MembershipListener, no_listener::NoListener},
};
use derive_more::{From, TryInto};
use derive_where::derive_where;
use dupe::Dupe;
use std::{
    cell::RefCell,
    collections::{HashMap, HashSet},
    fmt::{Display, Formatter},
    rc::Rc,
};
use thiserror::Error;

/// An [`Agent`] minus the current user.
#[derive(From, TryInto)]
#[derive_where(PartialEq, Debug; T)]
pub enum Peer<
    S: AsyncSigner,
    K: ShareSecretStore,
    T: ContentRef = [u8; 32],
    L: MembershipListener<S, K, T> = NoListener,
> {
    Individual(Rc<RefCell<Individual>>),
    Group(Rc<RefCell<Group<S, K, T, L>>>),
    Document(Rc<RefCell<Document<S, K, T, L>>>),
}

impl<S: AsyncSigner, K: ShareSecretStore, T: ContentRef, L: MembershipListener<S, K, T>>
    Peer<S, K, T, L>
{
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
                let prekey = *i.borrow().pick_prekey(doc_id);
                HashMap::from_iter([(i.borrow().id(), prekey)])
            }
            Peer::Group(g) => g.borrow().pick_individual_prekeys(doc_id),
            Peer::Document(d) => d.borrow().group.pick_individual_prekeys(doc_id),
        }
    }
}

impl<S: AsyncSigner, K: ShareSecretStore, T: ContentRef, L: MembershipListener<S, K, T>> Dupe
    for Peer<S, K, T, L>
{
    fn dupe(&self) -> Self {
        self.clone()
    }
}

impl<S: AsyncSigner, K: ShareSecretStore, T: ContentRef, L: MembershipListener<S, K, T>> Clone
    for Peer<S, K, T, L>
{
    fn clone(&self) -> Self {
        match self {
            Peer::Individual(i) => Peer::Individual(i.dupe()),
            Peer::Group(g) => Peer::Group(g.dupe()),
            Peer::Document(d) => Peer::Document(d.dupe()),
        }
    }
}

impl<S: AsyncSigner, K: ShareSecretStore, T: ContentRef, L: MembershipListener<S, K, T>> Display
    for Peer<S, K, T, L>
{
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        self.id().fmt(f)
    }
}

impl<S: AsyncSigner, K: ShareSecretStore, T: ContentRef, L: MembershipListener<S, K, T>>
    From<Peer<S, K, T, L>> for Agent<S, K, T, L>
{
    fn from(peer: Peer<S, K, T, L>) -> Self {
        match peer {
            Peer::Individual(individual) => Agent::Individual(individual),
            Peer::Group(group) => Agent::Group(group),
            Peer::Document(document) => Agent::Document(document),
        }
    }
}

impl<S: AsyncSigner, K: ShareSecretStore, T: ContentRef, L: MembershipListener<S, K, T>>
    TryFrom<Agent<S, K, T, L>> for Peer<S, K, T, L>
{
    type Error = ActiveUserIsNotAPeer;

    fn try_from(agent: Agent<S, K, T, L>) -> Result<Self, Self::Error> {
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
