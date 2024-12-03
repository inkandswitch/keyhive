//! The primary API for the library.

use crate::{
    access::Access,
    content::reference::ContentRef,
    crypto::{
        encrypted::Encrypted,
        share_key::ShareKey,
        signed::{Signed, SigningError},
    },
    principal::{
        active::Active,
        agent::{Agent, AgentId},
        document::{id::DocumentId, store::DocumentStore, DecryptError, Document, EncryptError},
        group::{
            id::GroupId,
            operation::delegation::{Delegation, DelegationError},
            store::GroupStore,
            Group,
        },
        identifier::Identifier,
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
#[derive(Debug)]
pub struct Context<T: ContentRef, R: rand::CryptoRng + rand::RngCore> {
    /// The [`Active`] user agent.
    pub active: Rc<RefCell<Active>>,

    /// The [`Individual`]s that are known to this agent.
    pub individuals: BTreeMap<IndividualId, Rc<RefCell<Individual>>>,

    /// The [`Group`]s that are known to this agent.
    pub groups: GroupStore<T>,

    /// The [`Document`]s that are known to this agent.
    pub docs: DocumentStore<T>,

    /// Cryptographically secure (pseudo)random number generator.
    pub csprng: R,
}

impl<T: ContentRef, R: rand::CryptoRng + rand::RngCore> Context<T, R> {
    pub fn id(&self) -> IndividualId {
        self.active.borrow().id()
    }

    pub fn agent_id(&self) -> AgentId {
        self.active.borrow().agent_id()
    }

    pub fn generate(
        signing_key: ed25519_dalek::SigningKey,
        mut csprng: R,
    ) -> Result<Self, SigningError> {
        Ok(Self {
            active: Rc::new(RefCell::new(Active::generate(signing_key, &mut csprng)?)),
            individuals: Default::default(),
            groups: GroupStore::new(),
            docs: DocumentStore::new(),
            csprng,
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
        self.docs.generate_document(parents, &mut self.csprng)
    }

    pub fn rotate_prekey(&mut self, prekey: ShareKey) -> Result<ShareKey, SigningError> {
        self.active
            .borrow_mut()
            .rotate_prekey(prekey, &mut self.csprng)
    }

    pub fn expand_prekeys(&mut self) -> Result<ShareKey, SigningError> {
        self.active.borrow_mut().expand_prekeys(&mut self.csprng)
    }

    pub fn try_sign<U: Serialize>(&self, data: U) -> Result<Signed<U>, SigningError> {
        self.active.borrow().try_sign(data)
    }

    pub fn register_individual(&mut self, individual: Individual) {
        self.individuals
            .insert(individual.id().into(), Rc::new(RefCell::new(individual)));
    }

    pub fn add_member(
        &mut self,
        to_add: Agent<T>,
        resource: &mut Membered<T>,
        can: Access,
        after_content: BTreeMap<DocumentId, (Rc<RefCell<Document<T>>>, Vec<T>)>,
    ) -> Result<(), DelegationError> {
        let proof = resource
            .get_capability(&self.active.borrow().agent_id())
            .ok_or(DelegationError::Escalation)?;

        if can > proof.payload().can {
            return Err(DelegationError::Escalation);
        }

        let after_revocations = resource.get_agent_revocations(&to_add);

        let dlg = self.try_sign(Delegation {
            delegate: to_add,
            proof: Some(proof),
            can,
            after_revocations,
            after_content,
        })?;

        Ok(resource.add_member(dlg, &mut self.csprng))
    }

    pub fn revoke_member(
        &mut self,
        to_revoke: AgentId,
        resource: &mut Membered<T>,
    ) -> Result<(), SigningError> {
        let relevant_docs = vec![]; // FIXME calculate reachable for revoked or just all known docs

        resource.revoke_member(
            to_revoke,
            &self.active.borrow().signer,
            relevant_docs.as_slice(),
        )
    }

    pub fn try_encrypt_content(
        &mut self,
        doc: Rc<RefCell<Document<T>>>,
        content_ref: &T,
        pred_refs: &Vec<T>,
        content: &[u8],
    ) -> Result<Encrypted<Vec<u8>, T>, EncryptError> {
        doc.borrow_mut()
            .try_encrypt_content(content_ref, content, pred_refs, &mut self.csprng)
    }

    pub fn try_decrypt_content(
        &mut self,
        doc: Rc<RefCell<Document<T>>>,
        encrypted: &Encrypted<Vec<u8>, T>,
    ) -> Result<Vec<u8>, DecryptError> {
        doc.borrow_mut().try_decrypt_content(encrypted)
    }

    pub fn force_pcs_update(&mut self, doc: Rc<RefCell<Document<T>>>) -> Result<(), EncryptError> {
        doc.borrow_mut().pcs_update(&mut self.csprng)
    }

    pub fn reachable_docs(&self) -> BTreeMap<DocumentId, (&Rc<RefCell<Document<T>>>, Access)> {
        self.docs_reachable_by_agent(self.active.dupe().into())
    }

    pub fn reachable_members(
        &self,
        membered: Membered<T>,
    ) -> BTreeMap<AgentId, (Agent<T>, Access)> {
        match membered {
            Membered::Group(group) => self.groups.transitive_members(&group.borrow()),
            Membered::Document(doc) => self.docs.transitive_members(&doc.borrow()),
        }
    }

    pub fn docs_reachable_by_agent(
        &self,
        agent: Agent<T>,
    ) -> BTreeMap<DocumentId, (&Rc<RefCell<Document<T>>>, Access)> {
        let mut explore: Vec<(Rc<RefCell<Group<T>>>, Access)> = vec![];
        let mut caps: BTreeMap<DocumentId, (&Rc<RefCell<Document<T>>>, Access)> = BTreeMap::new();
        let mut seen: HashSet<AgentId> = HashSet::new();

        let agent_id = agent.agent_id();

        for doc in self.docs.docs.values() {
            seen.insert(doc.clone().borrow().agent_id());

            let doc_id = doc.borrow().doc_id();

            if let Some(proofs) = doc.borrow().members().get(&agent_id) {
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
                if seen.contains(&doc.borrow().agent_id()) {
                    continue;
                }

                let doc_id = doc.borrow().doc_id();

                if let Some(proofs) = doc.borrow().members().get(&agent_id) {
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

    pub fn get_agent(&self, id: Identifier) -> Option<Agent<T>> {
        if let Some(doc) = self.docs.get(&DocumentId(id)) {
            return Some(doc.into());
        }

        if let Some(group) = self.groups.get(&GroupId::new(id)) {
            return Some(group.into());
        }

        if let Some(indie) = self.individuals.get(&id.into()) {
            return Some(indie.clone().into());
        }

        None
    }
}

impl<T: ContentRef, R: rand::CryptoRng + rand::RngCore> Verifiable for Context<T, R> {
    fn verifying_key(&self) -> ed25519_dalek::VerifyingKey {
        self.active.borrow().verifying_key()
    }
}

impl<T: ContentRef, R: rand::CryptoRng + rand::RngCore> From<&Context<T, R>> for Agent<T> {
    fn from(context: &Context<T, R>) -> Self {
        context.active.dupe().into()
    }
}
