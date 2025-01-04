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
            operation::{
                delegation::{Delegation, DelegationError},
                revocation::Revocation,
            },
            store::GroupStore,
            Group,
        },
        identifier::Identifier,
        individual::{id::IndividualId, Individual},
        membered::Membered,
        verifiable::Verifiable,
    },
    util::content_addressed_map::CaMap,
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
pub struct Beehive<T: ContentRef, R: rand::CryptoRng + rand::RngCore> {
    /// The [`Active`] user agent.
    pub active: Rc<RefCell<Active>>,

    /// The [`Individual`]s that are known to this agent.
    pub individuals: BTreeMap<IndividualId, Rc<RefCell<Individual>>>,

    /// The [`Group`]s that are known to this agent.
    pub groups: GroupStore<T>,

    /// The [`Document`]s that are known to this agent.
    pub docs: DocumentStore<T>,

    /// All applied [`Delegation`]s
    pub delegations: Rc<RefCell<CaMap<Signed<Delegation<T>>>>>,

    /// All applied [`Revocation`]s
    pub revocations: Rc<RefCell<CaMap<Signed<Revocation<T>>>>>,

    /// Cryptographically secure (pseudo)random number generator.
    pub csprng: R,
}

impl<T: ContentRef, R: rand::CryptoRng + rand::RngCore> Beehive<T, R> {
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
            delegations: Rc::new(RefCell::new(CaMap::new())),
            revocations: Rc::new(RefCell::new(CaMap::new())),
            csprng,
        })
    }

    pub fn generate_group(
        &mut self,
        coparents: Vec<Agent<T>>,
    ) -> Result<Rc<RefCell<Group<T>>>, SigningError> {
        Ok(self.groups.generate_group(
            NonEmpty {
                head: self.active.dupe().into(),
                tail: coparents,
            },
            &mut self.csprng,
        )?)
    }

    pub fn generate_doc(
        &mut self,
        coparents: Vec<Agent<T>>,
    ) -> Result<Rc<RefCell<Document<T>>>, DelegationError> {
        let parents = NonEmpty {
            head: self.active.dupe().into(),
            tail: coparents,
        };

        let new_doc = self.docs.generate_document(parents, &mut self.csprng)?;

        for head in new_doc.borrow().delegation_heads() {
            self.delegations.insert(head.dupe());

            for dep in head.payload().proof_lineage() {
                self.delegations.insert(dep);
            }

            // FIXME also content and revs?
        }

        Ok(new_doc)
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

        Ok(resource.add_member(dlg))
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
        let (encrypted, _maybe_update_op) = doc.borrow_mut().try_encrypt_content(
            content_ref,
            content,
            pred_refs,
            &mut self.csprng,
        )?;
        // FIXME: We need to handle the optional op as well
        Ok(encrypted)
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

    pub fn receive_delegation(
        &mut self,
        static_dlg: Signed<StaticDelegation<T>>,
    ) -> Result<(), ()> {
        static_dlg.try_verify()?;

        if let Some(proof) = self
            .delegations
            .borrow()
            .get(&static_dlg.payload().proof.coerce())
        {
            let subject_id = proof.subject();

            let subject: Membered<T> = if let Some(group) = self.groups.get(&GroupId(subject_id)) {
                Ok(group.into())
            } else if let Some(doc) = self.docs.get(&DocumentId(subject_id)) {
                Ok(doc.into())
            } else if subject_id == static_dlg.verifying_key().into() {
                todo!("FIXME register group or doc");
            } else {
                todo!("FIXME");
            }?;

            let after_content = BTreeMap::from_iter([/* FIXME */]);

            let proof = static_dlg.payload().proof.map(|proof_hash| {
                let p = self
                    .delegations
                    .borrow()
                    .get(proof_hash)
                    .ok_or(todo!("FIXME"))?;

                // FIXME any other checks, too
                if p.subject() != revoke.subject() {
                    return Err(todo!());
                }

                Ok(p)
            })?;

            // FIXME break out
            let delegate_id = static_dlg.delegate;
            let delegate: Agent<T> = if let Some(group) = self.groups.get(delegate_id) {
                group.into()
            } else if let Some(doc) = self.docs.get(delegate_id) {
                doc.into()
            } else if let Some(indie) = self.individuals.get(delegate_id) {
                indie.dupe().into()
            } else if delegate_id == self.id() {
                self.active.into()
            } else {
                let indie = Rc::new(RefCell::new(Individual::new(delegate_id)));
                self.individuals.insert(delegate_id, indie);
                indie.into()
            };

            let mut after_revocations = vec![];
            let revs = self.revocations.borrow();
            for rev_hash in static_dlg.payload().revocations.iter() {
                let resolved_rev = revs.get(rev_hash).ok_or("FIXME")?;
                after_revocations.push(resolved_rev.dupe());
            }

            let dlg: Signed<Delegation<T>> = static_dlg.map(|_| Delegation {
                delegate,
                proof,
                can: static_dlg.payaod().can,
                after_revocations,
                after_content: static_dlg.payload().after_content,
            });

            subject.receive_delegation(d);
            Ok(())
        } else {
            todo!("FIXME missing dep");
        }
    }
}

impl<T: ContentRef, R: rand::CryptoRng + rand::RngCore> Verifiable for Beehive<T, R> {
    fn verifying_key(&self) -> ed25519_dalek::VerifyingKey {
        self.active.borrow().verifying_key()
    }
}

impl<T: ContentRef, R: rand::CryptoRng + rand::RngCore> From<&Beehive<T, R>> for Agent<T> {
    fn from(context: &Beehive<T, R>) -> Self {
        context.active.dupe().into()
    }
}
