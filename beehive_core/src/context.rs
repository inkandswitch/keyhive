//! The primary API for the library.

use crate::{
    access::Access,
    content::reference::ContentRef,
    crypto::signed::{Signed, SigningError},
    principal::{
        active::Active,
        agent::{Agent, AgentId},
        document::{id::DocumentId, store::DocumentStore, Document},
        group::{operation::delegation::DelegationError, store::GroupStore, Group},
        individual::{id::IndividualId, Individual},
        membered::Membered,
        verifiable::Verifiable,
    },
};
use dupe::Dupe;
use nonempty::NonEmpty;
use serde::Serialize;
use std::{
    cell::RefCell,
    collections::{BTreeMap, HashSet},
    rc::Rc,
};

/// The main object for a user agent & top-level owned stores.
#[derive(Debug, Clone)]
pub struct Context<T: ContentRef> {
    /// The [`Active`] user agent.
    pub active: Rc<Active>,

    /// The [`Individual`]s that are known to this agent.
    pub individuals: BTreeMap<IndividualId, Individual>,

    /// The [`Group`]s that are known to this agent.
    pub groups: GroupStore<T>,

    /// The [`Document`]s that are known to this agent.
    pub docs: DocumentStore<T>,
}

impl<T: ContentRef> Context<T> {
    pub fn generate(signing_key: ed25519_dalek::SigningKey) -> Result<Self, SigningError> {
        Ok(Self {
            active: Rc::new(Active::generate(signing_key)?),
            individuals: Default::default(),
            groups: GroupStore::new(),
            docs: DocumentStore::new(),
        })
    }

    pub fn generate_group(
        &mut self,
        coparents: Vec<Agent<T>>,
    ) -> Result<Rc<RefCell<Group<T>>>, SigningError> {
        self.groups.generate_group(NonEmpty {
            head: self.active.dupe().into(),
            tail: coparents,
        })
    }

    pub fn generate_doc(
        &mut self,
        coparents: Vec<Agent<T>>,
    ) -> Result<DocumentId, DelegationError> {
        let parents = NonEmpty {
            head: self.active.dupe().into(),
            tail: coparents,
        };
        self.docs.generate_document(parents)
    }

    pub fn id(&self) -> IndividualId {
        self.active.id()
    }

    pub fn agent_id(&self) -> AgentId {
        self.active.agent_id()
    }

    pub fn try_sign<U: Serialize>(&self, data: U) -> Result<Signed<U>, SigningError> {
        self.active.try_sign(data)
    }

    pub fn revoke_member(
        &mut self,
        to_revoke: &AgentId,
        resource: &mut Membered<T>,
        relevant_docs: &[&Rc<Document<T>>],
    ) -> Result<(), SigningError> {
        // FIXME check which docs are reachable from this group and include them automatically
        resource.revoke_member(to_revoke, &self.active.signer, relevant_docs)
    }

    pub fn accessible_docs(&self) -> BTreeMap<DocumentId, (&Document<T>, Access)> {
        let mut explore: Vec<(Rc<RefCell<Group<T>>>, Access)> = vec![];
        let mut caps: BTreeMap<DocumentId, (&Document<T>, Access)> = BTreeMap::new();
        let mut seen: HashSet<AgentId> = HashSet::new();

        let agent_id = self.active.agent_id();

        for doc in self.docs.docs.values() {
            seen.insert(doc.agent_id());

            let doc_id = doc.doc_id();

            if let Some(proofs) = doc.members().get(&agent_id) {
                for proof in proofs {
                    caps.insert(doc_id, (doc, proof.payload().can));
                }
            }
        }

        for group in self.groups.values() {
            seen.insert(group.borrow().agent_id());

            if let Some(proofs) = group.borrow().members().get(&agent_id) {
                for proof in proofs {
                    explore.push((group.dupe(), proof.payload().can));
                }
            }
        }

        while let Some((group, _access)) = explore.pop() {
            for doc in self.docs.docs.values() {
                if seen.contains(&doc.agent_id()) {
                    continue;
                }

                let doc_id = doc.doc_id();

                if let Some(proofs) = doc.members().get(&agent_id) {
                    for proof in proofs {
                        caps.insert(doc_id, (doc, proof.payload().can));
                    }
                }
            }

            for (group_id, focus_group) in self.groups.iter() {
                if seen.contains(&focus_group.borrow().agent_id()) {
                    continue;
                }

                if group.borrow().id() == (*group_id).into() {
                    continue;
                }

                if let Some(proofs) = focus_group.borrow().members().get(&agent_id) {
                    for proof in proofs {
                        explore.push((focus_group.dupe(), proof.payload().can));
                    }
                }
            }
        }

        caps
    }

    pub fn transitive_members(
        &self,
        membered: &Membered<T>,
    ) -> BTreeMap<AgentId, (Agent<T>, Access)> {
        match membered {
            Membered::Group(group) => self.groups.transitive_members(group),
            Membered::Document(doc) => self.docs.transitive_members(doc),
        }
    }
}

impl<T: ContentRef> Verifiable for Context<T> {
    fn verifying_key(&self) -> ed25519_dalek::VerifyingKey {
        self.active.verifying_key()
    }
}

impl<T: ContentRef> From<&Context<T>> for Agent<T> {
    fn from(context: &Context<T>) -> Self {
        context.active.dupe().into()
    }
}
