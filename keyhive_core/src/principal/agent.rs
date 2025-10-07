pub mod id;

use super::{
    active::Active,
    document::{id::DocumentId, Document},
    group::{Group, IdOrIndividual},
    identifier::Identifier,
    individual::{id::IndividualId, op::KeyOp, Individual},
    membered::Membered,
};
use crate::{
    content::reference::ContentRef,
    crypto::{share_key::ShareKey, signer::async_signer::AsyncSigner, verifiable::Verifiable},
    listener::{membership::MembershipListener, no_listener::NoListener},
};
use derivative::Derivative;
use derive_more::{From, TryInto};
use derive_where::derive_where;
use dupe::Dupe;
use ed25519_dalek::VerifyingKey;
use futures::lock::Mutex;
use std::{
    collections::{HashMap, HashSet},
    fmt::{Display, Formatter},
    sync::Arc,
};

/// Immutable union over all agent types.
///
/// This type is very lightweight to clone, since it only contains immutable references to the actual agents.
#[derive_where(Clone, Debug; T)]
#[derive(From, TryInto, Derivative)]
pub enum Agent<S: AsyncSigner, T: ContentRef = [u8; 32], L: MembershipListener<S, T> = NoListener> {
    Active(Arc<Mutex<Active<S, T, L>>>),
    Individual(Arc<Mutex<Individual>>),
    Group(Arc<Mutex<Group<S, T, L>>>),
    Document(Arc<Mutex<Document<S, T, L>>>),
}

impl<S: AsyncSigner, T: ContentRef, L: MembershipListener<S, T>> PartialEq for Agent<S, T, L> {
    fn eq(&self, other: &Self) -> bool {
        todo!("FIXME");
        // match (self, other) {
        //     (Agent::Active(a), Agent::Active(b)) => a.borrow().id() == b.borrow().id(),
        //     (Agent::Individual(a), Agent::Individual(b)) => a.borrow().id() == b.borrow().id(),
        //     (Agent::Group(a), Agent::Group(b)) => a.borrow().group_id() == b.borrow().group_id(),
        //     (Agent::Document(a), Agent::Document(b)) => a.borrow().doc_id() == b.borrow().doc_id(),
        //     _ => false,
        // }
    }
}

impl<S: AsyncSigner, T: ContentRef, L: MembershipListener<S, T>> Agent<S, T, L> {
    pub async fn id(&self) -> Identifier {
        match self {
            Agent::Active(a) => a.lock().await.id().into(),
            Agent::Individual(i) => i.lock().await.id().into(),
            Agent::Group(g) => (*g).lock().await.group_id().into(),
            Agent::Document(d) => d.lock().await.doc_id().into(),
        }
    }

    pub async fn agent_id(&self) -> id::AgentId {
        match self {
            Agent::Active(a) => a.lock().await.agent_id(),
            Agent::Individual(i) => i.lock().await.agent_id(),
            Agent::Group(g) => (*g).lock().await.agent_id(),
            Agent::Document(d) => d.lock().await.agent_id(),
        }
    }

    pub async fn individual_ids(&self) -> HashSet<IndividualId> {
        match self {
            Agent::Active(a) => HashSet::from_iter([a.lock().await.id()]),
            Agent::Individual(i) => HashSet::from_iter([i.lock().await.id()]),
            Agent::Group(g) => g.lock().await.individual_ids().await,
            Agent::Document(d) => d.lock().await.group.individual_ids().await,
        }
    }

    pub async fn pick_individual_prekeys(
        &self,
        doc_id: DocumentId,
    ) -> HashMap<IndividualId, ShareKey> {
        match self {
            Agent::Active(a) => {
                let prekey = *a.lock().await.pick_prekey(doc_id);
                HashMap::from_iter([(a.lock().await.id(), prekey)])
            }
            Agent::Individual(i) => {
                let prekey = *i.lock().await.pick_prekey(doc_id);
                HashMap::from_iter([(i.lock().await.id(), prekey)])
            }
            Agent::Group(g) => g.lock().await.pick_individual_prekeys(doc_id).await,
            Agent::Document(d) => d.lock().await.group.pick_individual_prekeys(doc_id).await,
        }
    }

    pub async fn key_ops(&self) -> HashSet<Arc<KeyOp>> {
        match self {
            Agent::Active(a) => a
                .lock()
                .await
                .individual
                .prekey_ops()
                .values()
                .cloned()
                .collect(),
            Agent::Individual(i) => i.lock().await.prekey_ops().values().cloned().collect(),
            Agent::Group(g) => {
                if let IdOrIndividual::Individual(indie) = &g.lock().await.id_or_indie {
                    indie.prekey_ops().values().cloned().collect()
                } else {
                    Default::default()
                }
            }
            Agent::Document(d) => {
                if let IdOrIndividual::Individual(indie) = &d.lock().await.group.id_or_indie {
                    indie.prekey_ops().values().cloned().collect()
                } else {
                    Default::default()
                }
            }
        }
    }
}

impl<S: AsyncSigner, T: ContentRef, L: MembershipListener<S, T>> From<Active<S, T, L>>
    for Agent<S, T, L>
{
    fn from(a: Active<S, T, L>) -> Self {
        Agent::Active(Arc::new(Mutex::new(a)))
    }
}

impl<S: AsyncSigner, T: ContentRef, L: MembershipListener<S, T>> From<Individual>
    for Agent<S, T, L>
{
    fn from(i: Individual) -> Self {
        Agent::Individual(Arc::new(Mutex::new(i)))
    }
}

impl<S: AsyncSigner, T: ContentRef, L: MembershipListener<S, T>> From<Group<S, T, L>>
    for Agent<S, T, L>
{
    fn from(g: Group<S, T, L>) -> Self {
        Agent::Group(Arc::new(Mutex::new(g)))
    }
}

impl<S: AsyncSigner, T: ContentRef, L: MembershipListener<S, T>> From<Membered<S, T, L>>
    for Agent<S, T, L>
{
    fn from(m: Membered<S, T, L>) -> Self {
        match m {
            Membered::Group(g) => g.into(),
            Membered::Document(d) => d.into(),
        }
    }
}

impl<S: AsyncSigner, T: ContentRef, L: MembershipListener<S, T>> From<Document<S, T, L>>
    for Agent<S, T, L>
{
    fn from(d: Document<S, T, L>) -> Self {
        Agent::Document(Arc::new(Mutex::new(d)))
    }
}
impl<S: AsyncSigner, T: ContentRef, L: MembershipListener<S, T>> Verifiable for Agent<S, T, L> {
    fn verifying_key(&self) -> VerifyingKey {
        todo!("FIXME");
        // match self {
        //     Agent::Active(a) => a.borrow().verifying_key(),
        //     Agent::Individual(i) => i.borrow().verifying_key(),
        //     Agent::Group(g) => (*g).borrow().verifying_key(),
        //     Agent::Document(d) => d.borrow().group.verifying_key(),
        // }
    }
}

impl<S: AsyncSigner, T: ContentRef, L: MembershipListener<S, T>> Display for Agent<S, T, L> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        todo!("FIXME") // write!(f, "{}", self.id())
    }
}

impl<S: AsyncSigner, T: ContentRef, L: MembershipListener<S, T>> Dupe for Agent<S, T, L> {
    fn dupe(&self) -> Self {
        match self {
            Agent::Active(a) => a.dupe().into(),
            Agent::Individual(i) => i.dupe().into(),
            Agent::Group(g) => g.dupe().into(),
            Agent::Document(d) => d.dupe().into(),
        }
    }
}
