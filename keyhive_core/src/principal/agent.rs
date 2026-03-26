pub mod id;

use super::{
    active::Active,
    document::{id::DocumentId, Document},
    group::{id::GroupId, Group, IdOrIndividual},
    identifier::Identifier,
    individual::{id::IndividualId, op::KeyOp, Individual},
    membered::Membered,
};
use crate::{
    listener::{membership::MembershipListener, no_listener::NoListener},
    util::content_addressed_map::CaMap,
};
use derivative::Derivative;
use derive_more::{From, TryInto};
use derive_where::derive_where;
use dupe::Dupe;
use ed25519_dalek::VerifyingKey;
use future_form::FutureForm;
use futures::lock::Mutex;
use keyhive_crypto::{
    content::reference::ContentRef, share_key::ShareKey, signer::async_signer::AsyncSigner,
    verifiable::Verifiable,
};
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
pub enum Agent<
    F: FutureForm,
    S: AsyncSigner<F>,
    T: ContentRef = [u8; 32],
    L: MembershipListener<F, S, T> = NoListener,
> {
    Active(IndividualId, Arc<Mutex<Active<F, S, T, L>>>),
    Individual(IndividualId, Arc<Mutex<Individual>>),
    Group(GroupId, Arc<Mutex<Group<F, S, T, L>>>),
    Document(DocumentId, Arc<Mutex<Document<F, S, T, L>>>),
}

impl<F: FutureForm, S: AsyncSigner<F>, T: ContentRef, L: MembershipListener<F, S, T>> PartialEq
    for Agent<F, S, T, L>
{
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Agent::Active(a, _), Agent::Active(b, _)) => a == b,
            (Agent::Individual(a, _), Agent::Individual(b, _)) => a == b,
            (Agent::Group(a, _), Agent::Group(b, _)) => a == b,
            (Agent::Document(a, _), Agent::Document(b, _)) => a == b,
            _ => false,
        }
    }
}

impl<F: FutureForm, S: AsyncSigner<F>, T: ContentRef, L: MembershipListener<F, S, T>>
    Agent<F, S, T, L>
{
    pub fn id(&self) -> Identifier {
        match self {
            Agent::Active(id, _) => (*id).into(),
            Agent::Individual(id, _) => (*id).into(),
            Agent::Group(id, _) => (*id).into(),
            Agent::Document(id, _) => (*id).into(),
        }
    }

    pub fn agent_id(&self) -> id::AgentId {
        match self {
            Agent::Active(id, _) => (*id).into(),
            Agent::Individual(id, _) => (*id).into(),
            Agent::Group(id, _) => (*id).into(),
            Agent::Document(id, _) => (*id).into(),
        }
    }

    pub async fn individual_ids(&self) -> HashSet<IndividualId> {
        let mut ids = HashSet::new();

        let mut stack: Vec<Self> = vec![self.dupe()];

        while let Some(node) = stack.pop() {
            match node {
                Agent::Active(a_id, _) => {
                    ids.insert(a_id);
                }
                Agent::Individual(i_id, _) => {
                    ids.insert(i_id);
                }
                Agent::Group(_, g) => {
                    let locked_group = g.lock().await;
                    for ms in locked_group.members().values() {
                        for m in ms {
                            stack.push(m.payload.delegate.dupe());
                        }
                    }
                }
                Agent::Document(_, d) => {
                    let locked_doc = d.lock().await;
                    for ms in locked_doc.members().values() {
                        for m in ms {
                            stack.push(m.payload.delegate.dupe());
                        }
                    }
                }
            }
        }

        ids
    }

    pub async fn pick_individual_prekeys(
        &self,
        doc_id: DocumentId,
    ) -> HashMap<IndividualId, ShareKey> {
        let mut result = HashMap::new();
        let mut stack: Vec<Self> = vec![self.dupe()];

        while let Some(agent) = stack.pop() {
            match agent {
                Agent::Active(_, a) => {
                    let (id, prekey) = {
                        let locked = a.lock().await;
                        let id = locked.id();
                        let prekey = locked.pick_prekey(doc_id).await;
                        (id, prekey)
                    };
                    result.insert(id, prekey);
                }
                Agent::Individual(_, i) => {
                    let (id, prekey) = {
                        let guard = i.lock().await;
                        (guard.id(), *guard.pick_prekey(doc_id))
                    };
                    result.insert(id, prekey);
                }
                Agent::Group(_, g) => {
                    let locked_group = g.lock().await;
                    for ms in locked_group.members().values() {
                        for m in ms {
                            stack.push(m.payload.delegate.dupe());
                        }
                    }
                }
                Agent::Document(_, d) => {
                    let locked_doc = d.lock().await;
                    for ms in locked_doc.members().values() {
                        for m in ms {
                            stack.push(m.payload.delegate.dupe());
                        }
                    }
                }
            }
        }

        result
    }

    pub async fn key_ops(&self) -> CaMap<KeyOp> {
        match self {
            Agent::Active(_, a) => a.lock().await.individual.lock().await.prekey_ops().clone(),
            Agent::Individual(_, i) => i.lock().await.prekey_ops().clone(),
            Agent::Group(_, g) => {
                if let IdOrIndividual::Individual(indie) = &g.lock().await.id_or_indie {
                    indie.prekey_ops().clone()
                } else {
                    Default::default()
                }
            }
            Agent::Document(_, d) => {
                if let IdOrIndividual::Individual(indie) = &d.lock().await.group.id_or_indie {
                    indie.prekey_ops().clone()
                } else {
                    Default::default()
                }
            }
        }
    }
}

impl<F: FutureForm, S: AsyncSigner<F>, T: ContentRef, L: MembershipListener<F, S, T>>
    From<Active<F, S, T, L>> for Agent<F, S, T, L>
{
    fn from(a: Active<F, S, T, L>) -> Self {
        Agent::Active(a.id(), Arc::new(Mutex::new(a)))
    }
}

impl<F: FutureForm, S: AsyncSigner<F>, T: ContentRef, L: MembershipListener<F, S, T>>
    From<Individual> for Agent<F, S, T, L>
{
    fn from(i: Individual) -> Self {
        Agent::Individual(i.id(), Arc::new(Mutex::new(i)))
    }
}

impl<F: FutureForm, S: AsyncSigner<F>, T: ContentRef, L: MembershipListener<F, S, T>>
    From<Group<F, S, T, L>> for Agent<F, S, T, L>
{
    fn from(g: Group<F, S, T, L>) -> Self {
        Agent::Group(g.group_id(), Arc::new(Mutex::new(g)))
    }
}

impl<F: FutureForm, S: AsyncSigner<F>, T: ContentRef, L: MembershipListener<F, S, T>>
    From<Membered<F, S, T, L>> for Agent<F, S, T, L>
{
    fn from(m: Membered<F, S, T, L>) -> Self {
        match m {
            Membered::Group(id, g) => Agent::Group(id, g),
            Membered::Document(id, d) => Agent::Document(id, d),
        }
    }
}

impl<F: FutureForm, S: AsyncSigner<F>, T: ContentRef, L: MembershipListener<F, S, T>>
    From<Document<F, S, T, L>> for Agent<F, S, T, L>
{
    fn from(d: Document<F, S, T, L>) -> Self {
        Agent::Document(d.doc_id(), Arc::new(Mutex::new(d)))
    }
}
impl<F: FutureForm, S: AsyncSigner<F>, T: ContentRef, L: MembershipListener<F, S, T>> Verifiable
    for Agent<F, S, T, L>
{
    fn verifying_key(&self) -> VerifyingKey {
        self.id().verifying_key()
    }
}

impl<F: FutureForm, S: AsyncSigner<F>, T: ContentRef, L: MembershipListener<F, S, T>> Dupe
    for Agent<F, S, T, L>
{
    fn dupe(&self) -> Self {
        self.clone()
    }
}

impl<F: FutureForm, S: AsyncSigner<F>, T: ContentRef, L: MembershipListener<F, S, T>> Display
    for Agent<F, S, T, L>
{
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Agent::Active(id, _) => write!(f, "Active({id})"),
            Agent::Individual(id, _) => write!(f, "Individual({id})"),
            Agent::Group(id, _) => write!(f, "Group({id})"),
            Agent::Document(id, _) => write!(f, "Document({id})"),
        }
    }
}
