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
use std::{
    cell::RefCell,
    collections::{HashMap, HashSet},
    fmt::{Display, Formatter},
    rc::Rc,
};

/// Immutable union over all agent types.
///
/// This type is very lightweight to clone, since it only contains immutable references to the actual agents.
#[derive(From, TryInto, Derivative)]
#[derive_where(Clone, Debug; T)]
pub enum Agent<S: AsyncSigner, T: ContentRef = [u8; 32], L: MembershipListener<S, T> = NoListener> {
    Active(Rc<RefCell<Active<S, L>>>),
    Individual(Rc<RefCell<Individual>>),
    Group(Rc<RefCell<Group<S, T, L>>>),
    Document(Rc<RefCell<Document<S, T, L>>>),
}

impl<S: AsyncSigner, T: ContentRef, L: MembershipListener<S, T>> PartialEq for Agent<S, T, L> {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Agent::Active(a), Agent::Active(b)) => a.borrow().id() == b.borrow().id(),
            (Agent::Individual(a), Agent::Individual(b)) => a.borrow().id() == b.borrow().id(),
            (Agent::Group(a), Agent::Group(b)) => a.borrow().group_id() == b.borrow().group_id(),
            (Agent::Document(a), Agent::Document(b)) => a.borrow().doc_id() == b.borrow().doc_id(),
            _ => false,
        }
    }
}

impl<S: AsyncSigner, T: ContentRef, L: MembershipListener<S, T>> Agent<S, T, L> {
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
                let prekey = *a.borrow().pick_prekey(doc_id);
                HashMap::from_iter([(a.borrow().id(), prekey)])
            }
            Agent::Individual(i) => {
                let prekey = *i.borrow().pick_prekey(doc_id);
                HashMap::from_iter([(i.borrow().id(), prekey)])
            }
            Agent::Group(g) => g.borrow().pick_individual_prekeys(doc_id),
            Agent::Document(d) => d.borrow().group.pick_individual_prekeys(doc_id),
        }
    }

    pub fn key_ops(&self) -> HashSet<Rc<KeyOp>> {
        match self {
            Agent::Active(a) => a
                .borrow()
                .individual
                .prekey_ops()
                .values()
                .cloned()
                .collect(),
            Agent::Individual(i) => i.borrow().prekey_ops().values().cloned().collect(),
            Agent::Group(g) => {
                if let IdOrIndividual::Individual(indie) = &g.borrow().id_or_indie {
                    indie.prekey_ops().values().cloned().collect()
                } else {
                    Default::default()
                }
            }
            Agent::Document(d) => {
                if let IdOrIndividual::Individual(indie) = &d.borrow().group.id_or_indie {
                    indie.prekey_ops().values().cloned().collect()
                } else {
                    Default::default()
                }
            }
        }
    }
}

impl<S: AsyncSigner, T: ContentRef, L: MembershipListener<S, T>> From<Active<S, L>>
    for Agent<S, T, L>
{
    fn from(a: Active<S, L>) -> Self {
        Agent::Active(Rc::new(RefCell::new(a)))
    }
}

impl<S: AsyncSigner, T: ContentRef, L: MembershipListener<S, T>> From<Individual>
    for Agent<S, T, L>
{
    fn from(i: Individual) -> Self {
        Agent::Individual(Rc::new(RefCell::new(i)))
    }
}

impl<S: AsyncSigner, T: ContentRef, L: MembershipListener<S, T>> From<Group<S, T, L>>
    for Agent<S, T, L>
{
    fn from(g: Group<S, T, L>) -> Self {
        Agent::Group(Rc::new(RefCell::new(g)))
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
        Agent::Document(Rc::new(RefCell::new(d)))
    }
}
impl<S: AsyncSigner, T: ContentRef, L: MembershipListener<S, T>> Verifiable for Agent<S, T, L> {
    fn verifying_key(&self) -> VerifyingKey {
        match self {
            Agent::Active(a) => a.borrow().verifying_key(),
            Agent::Individual(i) => i.borrow().verifying_key(),
            Agent::Group(g) => (*g).borrow().verifying_key(),
            Agent::Document(d) => d.borrow().group.verifying_key(),
        }
    }
}

impl<S: AsyncSigner, T: ContentRef, L: MembershipListener<S, T>> Display for Agent<S, T, L> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.id())
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
