pub mod id;
pub mod store;

use super::individual::id::IndividualId;
use crate::{
    access::Access,
    content::reference::ContentRef,
    crypto::{
        share_key::ShareKey,
        signed::{Signed, SigningError},
        signing_key::SigningKey,
        verifiable::Verifiable,
        verifying_key::VerifyingKey,
    },
    principal::{
        agent::{Agent, AgentId},
        group::{
            operation::{
                delegation::{Delegation, DelegationError},
                revocation::Revocation,
                AncestorError,
            },
            Group,
        },
        identifier::Identifier,
        individual::Individual,
    },
    util::{
        content_addressed_map::CaMap, hash_map::WrappedHashMap, hash_set::WrappedHashSet,
        rc::WrappedRc,
    },
};
use dupe::Dupe;
use id::DocumentId;
use nonempty::NonEmpty;
use serde::Serialize;
use std::{
    cell::RefCell,
    collections::{BTreeMap, HashMap},
    rc::Rc,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Document<T: ContentRef> {
    pub(crate) group: Group<T>,
    pub(crate) reader_keys: WrappedHashMap<IndividualId, (WrappedRc<Individual>, ShareKey)>,

    pub(crate) content_heads: WrappedHashSet<T>,
    pub(crate) content_state: WrappedHashSet<T>,
}

impl<T: ContentRef> Document<T> {
    pub fn id(&self) -> Identifier {
        self.group.id()
    }

    pub fn doc_id(&self) -> DocumentId {
        DocumentId(self.group.id())
    }

    pub fn agent_id(&self) -> AgentId {
        self.doc_id().into()
    }

    pub fn members(&self) -> &HashMap<AgentId, Vec<WrappedRc<Signed<Delegation<T>>>>> {
        self.group.members()
    }

    pub fn delegations(&self) -> &CaMap<Signed<Delegation<T>>> {
        self.group.delegations()
    }

    pub fn get_capabilty(&self, member_id: &AgentId) -> Option<Rc<Signed<Delegation<T>>>> {
        self.group.get_capability(member_id)
    }

    pub fn generate<R: rand::RngCore + rand::CryptoRng>(
        parents: NonEmpty<Agent<T>>,
        csprng: &mut R,
    ) -> Result<Self, DelegationError> {
        let doc_signer = SigningKey::generate(csprng);

        parents.iter().try_fold(
            Document {
                group: Group::generate(parents.clone())?,
                reader_keys: WrappedHashMap::new(), // FIXME
                content_state: WrappedHashSet::new(),
                content_heads: WrappedHashSet::new(),
            },
            |mut acc, parent| {
                let dlg = Signed::try_sign(
                    Delegation {
                        delegate: parent.dupe(),
                        can: Access::Admin,
                        proof: None,
                        after_revocations: vec![],
                        after_content: BTreeMap::new(),
                    },
                    &doc_signer,
                )?;

                let wrc = WrappedRc::new(dlg);
                acc.group.state.delegations.insert(wrc.dupe().0);
                acc.group.state.delegation_heads.insert(wrc.dupe());
                acc.group.members.insert(parent.agent_id(), vec![wrc]);

                Ok(acc)
            },
        )
    }

    pub fn add_member(&mut self, signed_delegation: Signed<Delegation<T>>) {
        // FIXME check subject, signature, find dependencies or quarantine
        // ...look at the quarantine and see if any of them depend on this one
        // ...etc etc
        // FIXME check that delegation is authorized
        let id = signed_delegation.payload().delegate.agent_id();
        let wrc = WrappedRc::new(signed_delegation);

        match self.group.members.get_mut(&id) {
            Some(caps) => {
                caps.push(wrc);
            }
            None => {
                self.group.members.insert(id, vec![wrc]);
            }
        }
    }

    pub fn revoke_member(
        &mut self,
        member_id: AgentId,
        signing_key: &SigningKey,
        relevant_docs: &[&Rc<RefCell<Document<T>>>],
    ) -> Result<(), SigningError> {
        self.group
            .revoke_member(member_id, signing_key, relevant_docs)
    }

    pub fn get_agent_revocations(&self, agent: &Agent<T>) -> Vec<Rc<Signed<Revocation<T>>>> {
        self.group.get_agent_revocations(agent)
    }

    pub fn materialize(&mut self) -> Result<(), AncestorError> {
        self.group.materialize()
    }
}

// // FIXME test
// impl<T: ContentRef> std::hash::Hash for Document<T> {
//     fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
//         self.group.hash(state);
//
//         for key in self.reader_keys.keys() {
//             key.hash(state);
//         }
//
//         for c in self.content_state.iter() {
//             c.hash(state);
//         }
//     }
// }

impl<T: ContentRef> Verifiable for Document<T> {
    fn verifying_key(&self) -> VerifyingKey {
        self.group.verifying_key()
    }
}
