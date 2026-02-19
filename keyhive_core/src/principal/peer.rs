use super::{
    agent::{id::AgentId, Agent},
    document::{id::DocumentId, Document},
    group::{id::GroupId, Group},
    identifier::Identifier,
    individual::{id::IndividualId, Individual},
};
use crate::{
    content::reference::ContentRef,
    crypto::{share_key::ShareKey, signer::async_signer::AsyncSigner},
    listener::{membership::MembershipListener, no_listener::NoListener},
};
use derive_more::{From, TryInto};
use dupe::Dupe;
use futures::lock::Mutex;
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};
use thiserror::Error;

/// An [`Agent`] minus the current user.
#[derive(Debug, From, TryInto)]
pub enum Peer<S: AsyncSigner, T: ContentRef = [u8; 32], L: MembershipListener<S, T> = NoListener> {
    Individual(IndividualId, Arc<Mutex<Individual>>),
    Group(GroupId, Arc<Mutex<Group<S, T, L>>>),
    Document(DocumentId, Arc<Mutex<Document<S, T, L>>>),
}

impl<S: AsyncSigner, T: ContentRef, L: MembershipListener<S, T>> Peer<S, T, L> {
    pub fn id(&self) -> Identifier {
        match self {
            Peer::Individual(id, _) => (*id).into(),
            Peer::Group(id, _) => (*id).into(),
            Peer::Document(id, _) => (*id).into(),
        }
    }

    pub fn agent_id(&self) -> AgentId {
        match self {
            Peer::Individual(id, _) => (*id).into(),
            Peer::Group(id, _) => (*id).into(),
            Peer::Document(id, _) => (*id).into(),
        }
    }

    pub async fn individual_ids(&self) -> HashSet<IndividualId> {
        match self {
            Peer::Individual(id, _) => HashSet::from_iter([*id]),
            Peer::Group(_, g) => g.lock().await.individual_ids().await,
            Peer::Document(_, d) => d.lock().await.group.individual_ids().await,
        }
    }

    pub async fn pick_individual_prekeys(
        &self,
        doc_id: DocumentId,
    ) -> HashMap<IndividualId, ShareKey> {
        match self {
            Peer::Individual(id, i) => {
                let locked = i.lock().await;
                let prekey = locked.pick_prekey(doc_id);
                HashMap::from_iter([(*id, *prekey)])
            }
            Peer::Group(_, g) => g.lock().await.pick_individual_prekeys(doc_id).await,
            Peer::Document(_, d) => d.lock().await.group.pick_individual_prekeys(doc_id).await,
        }
    }
}

impl<S: AsyncSigner, T: ContentRef, L: MembershipListener<S, T>> Dupe for Peer<S, T, L> {
    fn dupe(&self) -> Self {
        self.clone()
    }
}

impl<S: AsyncSigner, T: ContentRef, L: MembershipListener<S, T>> Clone for Peer<S, T, L> {
    fn clone(&self) -> Self {
        match self {
            Peer::Individual(id, i) => Peer::Individual(*id, i.dupe()),
            Peer::Group(id, g) => Peer::Group(*id, g.dupe()),
            Peer::Document(id, d) => Peer::Document(*id, d.dupe()),
        }
    }
}

impl<S: AsyncSigner, T: ContentRef, L: MembershipListener<S, T>> From<Peer<S, T, L>>
    for Agent<S, T, L>
{
    fn from(peer: Peer<S, T, L>) -> Self {
        match peer {
            Peer::Individual(id, individual) => Agent::Individual(id, individual),
            Peer::Group(id, group) => Agent::Group(id, group),
            Peer::Document(id, document) => Agent::Document(id, document),
        }
    }
}

impl<S: AsyncSigner, T: ContentRef, L: MembershipListener<S, T>> TryFrom<Agent<S, T, L>>
    for Peer<S, T, L>
{
    type Error = ActiveUserIsNotAPeer;

    fn try_from(agent: Agent<S, T, L>) -> Result<Self, Self::Error> {
        match agent {
            Agent::Individual(id, individual) => Ok(Peer::Individual(id, individual)),
            Agent::Group(id, group) => Ok(Peer::Group(id, group)),
            Agent::Document(id, document) => Ok(Peer::Document(id, document)),
            Agent::Active(_, _) => Err(ActiveUserIsNotAPeer),
        }
    }
}

#[derive(Debug, Error)]
#[error("The active user is not a peer")]
pub struct ActiveUserIsNotAPeer;
