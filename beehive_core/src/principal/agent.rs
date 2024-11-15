pub mod id;

use super::{
    active::Active,
    document::{id::DocumentId, Document},
    group::Group,
    identifier::Identifier,
    individual::{id::IndividualId, op::KeyOp, Individual},
    membered::Membered,
    verifiable::Verifiable,
};
use crate::{
    content::reference::ContentRef,
    crypto::share_key::ShareKey,
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
#[derive(Debug, Clone, Eq, From, TryInto, Derivative)]
#[derive_where(PartialEq ;T)]
pub enum Agent<T: ContentRef = [u8; 32], L: MembershipListener<T> = NoListener> {
    Active(Rc<RefCell<Active<L>>>),
    Individual(Rc<RefCell<Individual>>),
    Group(Rc<RefCell<Group<T, L>>>),
    Document(Rc<RefCell<Document<T, L>>>),
}

impl<T: ContentRef, L: MembershipListener<T>> Agent<T, L> {
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
                if let Some(prekey) = a.borrow().pick_prekey(doc_id) {
                    HashMap::from_iter([(a.borrow().id(), prekey)])
                } else {
                    HashMap::new()
                }
            }
            Agent::Individual(i) => {
                if let Some(prekey) = i.borrow().pick_prekey(doc_id) {
                    HashMap::from_iter([(i.borrow().id(), prekey)])
                } else {
                    HashMap::new()
                }
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
                .prekey_state
                .ops
                .values()
                .cloned()
                .collect(),
            Agent::Individual(i) => i.borrow().prekey_state.ops.values().cloned().collect(),
            Agent::Group(g) => g
                .borrow()
                .individual
                .prekey_state
                .ops
                .values()
                .cloned()
                .collect(),
            Agent::Document(d) => d
                .borrow()
                .group
                .individual
                .prekey_state
                .ops
                .values()
                .cloned()
                .collect(),
        }
    }
}

impl<T: ContentRef, L: MembershipListener<T>> From<Active<L>> for Agent<T, L> {
    fn from(a: Active<L>) -> Self {
        Agent::Active(Rc::new(RefCell::new(a)))
    }
}

impl<T: ContentRef, L: MembershipListener<T>> From<Individual> for Agent<T, L> {
    fn from(i: Individual) -> Self {
        Agent::Individual(Rc::new(RefCell::new(i)))
    }
}

impl<T: ContentRef, L: MembershipListener<T>> From<Group<T, L>> for Agent<T, L> {
    fn from(g: Group<T, L>) -> Self {
        Agent::Group(Rc::new(RefCell::new(g)))
    }
}

impl<T: ContentRef, L: MembershipListener<T>> From<Membered<T, L>> for Agent<T, L> {
    fn from(m: Membered<T, L>) -> Self {
        match m {
            Membered::Group(g) => g.into(),
            Membered::Document(d) => d.into(),
        }
    }
}

impl<T: ContentRef, L: MembershipListener<T>> From<Document<T, L>> for Agent<T, L> {
    fn from(d: Document<T, L>) -> Self {
        Agent::Document(Rc::new(RefCell::new(d)))
    }
}
impl<T: ContentRef, L: MembershipListener<T>> Verifiable for Agent<T, L> {
    fn verifying_key(&self) -> VerifyingKey {
        match self {
            Agent::Active(a) => a.borrow().verifying_key(),
            Agent::Individual(i) => i.borrow().verifying_key(),
            Agent::Group(g) => (*g).borrow().verifying_key(),
            Agent::Document(d) => d.borrow().group.verifying_key(),
        }
    }
}

impl<T: ContentRef, L: MembershipListener<T>> Display for Agent<T, L> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.id())
    }
}

impl<T: ContentRef, L: MembershipListener<T>> Dupe for Agent<T, L> {
    fn dupe(&self) -> Self {
        match self {
            Agent::Active(a) => a.dupe().into(),
            Agent::Individual(i) => i.dupe().into(),
            Agent::Group(g) => g.dupe().into(),
            Agent::Document(d) => d.dupe().into(),
        }
    }
}
