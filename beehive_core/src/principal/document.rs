pub mod id;
pub mod store;

use super::{individual::id::IndividualId, verifiable::Verifiable};
use crate::{
    access::Access,
    content::reference::ContentRef,
    crypto::{share_key::ShareKey, signed::Signed},
    principal::{
        agent::{Agent, AgentId},
        group::{operation::delegation::Delegation, Group},
        identifier::Identifier,
        individual::Individual,
    },
    util::content_addressed_map::CaMap,
};
use ed25519_dalek::VerifyingKey;
use id::DocumentId;
use nonempty::NonEmpty;
use serde::Serialize;
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    rc::Rc,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Document<'a, T: ContentRef> {
    pub(crate) group: Group<'a, T>,
    pub(crate) reader_keys: HashMap<IndividualId, (&'a Individual, ShareKey)>, // FIXME May remove when BeeKEM, also FIXME Individual ID

    pub(crate) content_heads: HashSet<&'a T>,
    pub(crate) content_state: HashSet<T>,
}

impl<'a, T: ContentRef> Document<'a, T> {
    pub fn id(&self) -> Identifier {
        self.group.id()
    }

    pub fn doc_id(&self) -> DocumentId {
        DocumentId(self.group.id())
    }

    pub fn agent_id(&self) -> AgentId {
        self.doc_id().into()
    }

    pub fn members(&self) -> &HashMap<AgentId, Vec<Rc<Signed<Delegation<'a, T>>>>> {
        &self.group.members()
    }

    pub fn delegations(&self) -> &CaMap<Signed<Delegation<'a, T>>> {
        &self.group.delegations()
    }

    pub fn get_capabilty(&'a self, member_id: &AgentId) -> Option<&Rc<Signed<Delegation<'a, T>>>> {
        self.group.get_capability(member_id)
    }

    pub fn generate(parents: NonEmpty<Agent<'a, T>>) -> Self {
        let doc_signer = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());

        let mut doc = Document {
            group: Group::generate(parents.clone()),
            reader_keys: HashMap::new(), // FIXME
            content_state: HashSet::new(),
            content_heads: HashSet::new(),
        };

        for parent in parents.iter() {
            let dlg = Signed::sign(
                Delegation {
                    delegate: *parent,
                    can: Access::Admin,
                    proof: None,
                    after_revocations: vec![],
                    after_content: BTreeMap::new(),
                },
                &doc_signer,
            );

            let rc = Rc::new(dlg);
            doc.group.state.delegations.insert(rc.clone());
            doc.group.state.delegation_heads.insert(rc.clone());
            doc.group.members.insert(parent.agent_id(), vec![rc]);
        }

        doc
    }

    pub fn add_member(&'a mut self, signed_delegation: Signed<Delegation<'a, T>>) {
        // FIXME check subject, signature, find dependencies or quarantine
        // ...look at the quarantine and see if any of them depend on this one
        // ...etc etc
        // FIXME check that delegation is authorized
        let id = signed_delegation.payload().delegate.agent_id();
        let rc = Rc::new(signed_delegation);

        match self.group.members.get_mut(&id) {
            Some(caps) => {
                caps.push(rc);
            }
            None => {
                self.group.members.insert(id, vec![rc]);
            }
        }
    }

    pub fn revoke_member(
        &'a mut self,
        member_id: &AgentId,
        signing_key: &ed25519_dalek::SigningKey,
        relevant_docs: &[&'a Document<'a, T>],
    ) {
        self.group
            .revoke_member(member_id, signing_key, relevant_docs);
    }

    pub fn materialize(&'a mut self) {
        self.group.materialize();
    }
}

// FIXME test
impl<'a, T: ContentRef> std::hash::Hash for Document<'a, T> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.group.hash(state);

        for key in self.reader_keys.keys() {
            key.hash(state);
        }

        for c in self.content_state.iter() {
            c.hash(state);
        }
    }
}

impl<'a, T: ContentRef> Verifiable for Document<'a, T> {
    fn verifying_key(&self) -> VerifyingKey {
        self.group.verifying_key()
    }
}
