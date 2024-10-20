//! The primary API for the library.

use crate::{
    access::Access,
    content::reference::ContentRef,
    crypto::signed::Signed,
    principal::{
        active::Active,
        agent::{Agent, AgentId},
        document::{id::DocumentId, store::DocumentStore, Document},
        group::{id::GroupId, store::GroupStore, Group},
        identifier::Identifier,
        individual::{id::IndividualId, Individual},
        membered::Membered,
        verifiable::Verifiable,
    },
};
use nonempty::NonEmpty;
use serde::Serialize;
use std::collections::{BTreeMap, HashSet};

/// The main object for a user agent & top-level owned stores.
#[derive(Clone)]
pub struct Context<'a, T: ContentRef> {
    /// The [`Active`] user agent.
    pub active: Active,

    /// The [`Individual`]s that are known to this agent.
    pub individuals: BTreeMap<IndividualId, Individual>,

    /// The [`Group`]s that are known to this agent.
    pub groups: GroupStore<'a, T>,

    /// The [`Document`]s that are known to this agent.
    pub docs: DocumentStore<'a, T>,
}

impl<'a, T: ContentRef> Context<'a, T> {
    pub fn generate(signing_key: ed25519_dalek::SigningKey) -> Self {
        Self {
            active: Active::generate(signing_key),
            individuals: Default::default(),
            groups: GroupStore::new(),
            docs: DocumentStore::new(),
        }
    }

    pub fn generate_group(&'a mut self, coparents: Vec<Agent<'a, T>>) -> GroupId {
        let head = Agent::Active(&self.active);
        self.groups.generate_group(NonEmpty {
            head,
            tail: coparents,
        })
    }

    pub fn generate_doc(&'a mut self, coparents: Vec<Agent<'a, T>>) -> DocumentId {
        let parents = NonEmpty {
            head: (&self.active).into(),
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

    pub fn sign<U: Serialize>(&self, data: U) -> Signed<U> {
        self.active.sign(data)
    }

    // pub fn encrypt(
    //     &self,
    //     data: Vec<u8>,
    //     public_keys: HashSet<&ShareKey>,
    // ) -> (
    //     Encrypted<Vec<u8>>,
    //     Encrypted<chacha20poly1305::XChaChaPoly1305>,
    // ) {
    //     let symmetric_key: [u8; 32] = rand::thread_rng();
    //     dcgka_2m_broadcast(key, data, public_keys)
    // }

    pub fn revoke_member(
        &'a mut self,
        to_revoke: &AgentId,
        resource: &'a mut Membered<'a, T>,
        relevant_docs: &[&'a Document<'a, T>],
    ) {
        // FIXME check which docs are reachable from this group and include them automatically
        resource.revoke_member(to_revoke, &self.active.signer, relevant_docs);
    }

    pub fn accessible_docs(&'a self) -> BTreeMap<DocumentId, (&'a Document<'a, T>, Access)> {
        enum Focus<'b, U: ContentRef> {
            Group(&'b Group<'b, U>),
            Document(&'b Document<'b, U>),
        }

        impl<'b, U: ContentRef> Focus<'b, U> {
            fn id(&self) -> Identifier {
                match self {
                    Focus::Group(group) => group.id(),
                    Focus::Document(doc) => doc.id(),
                }
            }
        }

        let mut explore: Vec<(Focus<'a, T>, Access)> = vec![];
        let mut caps: BTreeMap<DocumentId, (&'a Document<'a, T>, Access)> = BTreeMap::new();
        let mut seen: HashSet<AgentId> = HashSet::new();

        let agent_id = self.active.agent_id();

        for doc in self.docs.docs.values() {
            seen.insert(doc.agent_id());

            let doc_id = doc.doc_id();

            if let Some(proofs) = doc.get_member_refs().get(&agent_id) {
                for proof in proofs {
                    caps.insert(doc_id, (doc, proof.payload().can));
                }
            }
        }

        for group in self.groups.values() {
            seen.insert(group.agent_id());

            if let Some(proofs) = group.get_member_refs().get(&agent_id) {
                for proof in proofs {
                    explore.push((Focus::Group(group), proof.payload().can));
                }
            }
        }

        while let Some((group, _access)) = explore.pop() {
            for doc in self.docs.docs.values() {
                if seen.contains(&doc.agent_id()) {
                    continue;
                }

                let doc_id = doc.doc_id();

                if let Some(proofs) = doc.get_member_refs().get(&agent_id) {
                    for proof in proofs {
                        caps.insert(doc_id, (doc, proof.payload().can));
                    }
                }
            }

            for (group_id, focus_group) in self.groups.iter() {
                if seen.contains(&focus_group.agent_id()) {
                    continue;
                }

                if group.id() == (*group_id).into() {
                    continue;
                }

                if let Some(proofs) = focus_group.get_member_refs().get(&agent_id) {
                    for proof in proofs {
                        explore.push((Focus::Group(focus_group), proof.payload().can));
                    }
                }
            }
        }

        caps
    }

    pub fn transitive_members(
        &'a self,
        membered: &'a Membered<'a, T>,
    ) -> BTreeMap<AgentId, (Agent<'a, T>, Access)> {
        match membered {
            Membered::Group(group) => self.groups.transitive_members(group),
            Membered::Document(doc) => self.docs.transitive_members(doc),
        }
    }
}

impl<'a, T: ContentRef> Verifiable for Context<'a, T> {
    fn verifying_key(&self) -> ed25519_dalek::VerifyingKey {
        self.active.verifying_key()
    }
}

impl<'a, T: ContentRef> From<&'a Context<'a, T>> for Agent<'a, T> {
    fn from(context: &'a Context<T>) -> Self {
        (&context.active).into()
    }
}
