//! The primary API for the library.

use crate::{
    access::Access,
    cgka::error::CgkaError,
    content::reference::ContentRef,
    crypto::{
        digest::Digest,
        encrypted::EncryptedContent,
        share_key::ShareKey,
        signed::{Signed, SigningError, VerificationError},
    },
    error::missing_dependency::MissingDependency,
    principal::{
        active::Active,
        agent::{id::AgentId, Agent},
        document::{id::DocumentId, DecryptError, Document, EncryptError},
        group::{
            self,
            error::AddError,
            id::GroupId,
            operation::{
                delegation::{Delegation, DelegationError, StaticDelegation},
                revocation::{Revocation, StaticRevocation},
                Operation, StaticOperation,
            },
            Group, RevokeMemberError,
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
    collections::{BTreeMap, HashMap, HashSet},
    rc::Rc,
};
use thiserror::Error;

/// The main object for a user agent & top-level owned stores.
#[derive(Debug)]
pub struct Beehive<T: ContentRef, R: rand::CryptoRng + rand::RngCore> {
    /// The [`Active`] user agent.
    active: Rc<RefCell<Active>>,

    /// The [`Individual`]s that are known to this agent.
    individuals: HashMap<IndividualId, Rc<RefCell<Individual>>>,

    /// The [`Group`]s that are known to this agent.
    groups: HashMap<GroupId, Rc<RefCell<Group<T>>>>,

    /// The [`Document`]s that are known to this agent.
    docs: HashMap<DocumentId, Rc<RefCell<Document<T>>>>,

    /// All applied [`Delegation`]s
    delegations: Rc<RefCell<CaMap<Signed<Delegation<T>>>>>,

    /// All applied [`Revocation`]s
    revocations: Rc<RefCell<CaMap<Signed<Revocation<T>>>>>,

    /// Cryptographically secure (pseudo)random number generator.
    csprng: R,
}

impl<T: ContentRef, R: rand::CryptoRng + rand::RngCore> Beehive<T, R> {
    pub fn id(&self) -> IndividualId {
        self.active.borrow().id()
    }

    pub fn agent_id(&self) -> AgentId {
        self.active.borrow().agent_id()
    }

    pub fn generate_device_group() -> Self {
        todo!()
    }

    pub fn generate(
        signing_key: ed25519_dalek::SigningKey,
        mut csprng: R,
    ) -> Result<Self, SigningError> {
        Ok(Self {
            active: Rc::new(RefCell::new(Active::generate(signing_key, &mut csprng)?)),
            individuals: Default::default(),
            groups: HashMap::new(),
            docs: HashMap::new(),
            delegations: Rc::new(RefCell::new(CaMap::new())),
            revocations: Rc::new(RefCell::new(CaMap::new())),
            csprng,
        })
    }

    pub fn active(&self) -> &Rc<RefCell<Active>> {
        &self.active
    }

    pub fn groups(&self) -> &HashMap<GroupId, Rc<RefCell<Group<T>>>> {
        &self.groups
    }

    pub fn documents(&self) -> &HashMap<DocumentId, Rc<RefCell<Document<T>>>> {
        &self.docs
    }

    pub fn generate_group(
        &mut self,
        coparents: Vec<Agent<T>>,
    ) -> Result<Rc<RefCell<Group<T>>>, SigningError> {
        let g = Rc::new(RefCell::new(Group::generate(
            NonEmpty {
                head: self.active.dupe().into(),
                tail: coparents,
            },
            self.delegations.dupe(),
            self.revocations.dupe(),
            &mut self.csprng,
        )?));

        self.groups.insert(g.borrow().group_id(), g.dupe());

        Ok(g)
    }

    pub fn generate_doc(
        &mut self,
        coparents: Vec<Agent<T>>,
    ) -> Result<Rc<RefCell<Document<T>>>, DelegationError> {
        let parents = NonEmpty {
            head: self.active.dupe().into(),
            tail: coparents,
        };

        let new_doc = Document::generate(
            parents,
            self.delegations.dupe(),
            self.revocations.dupe(),
            &mut self.csprng,
        )?;

        for head in new_doc.delegation_heads().values() {
            self.delegations.borrow_mut().insert(head.dupe());

            for dep in head.payload().proof_lineage() {
                self.delegations.borrow_mut().insert(dep);
            }
        }

        Ok(Rc::new(RefCell::new(new_doc)))
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
            .insert(individual.id(), Rc::new(RefCell::new(individual)));
    }

    pub fn register_group(&mut self, root_delegation: Signed<Delegation<T>>) {
        let group = Group::from_individual(
            Individual::new(root_delegation.issuer.into()),
            Rc::new(root_delegation),
            self.delegations.dupe(),
            self.revocations.dupe(),
        );
        self.groups
            .insert(group.group_id(), Rc::new(RefCell::new(group)));
    }

    pub fn get_operation(&self, digest: &Digest<Operation<T>>) -> Option<Operation<T>> {
        self.delegations
            .borrow()
            .get(&digest.into())
            .map(|d| d.dupe().into())
            .or_else(|| {
                self.revocations
                    .borrow()
                    .get(&digest.into())
                    .map(|r| r.dupe().into())
            })
    }

    pub fn add_member(
        &mut self,
        to_add: Agent<T>,
        resource: &mut Membered<T>,
        can: Access,
        after_content: BTreeMap<DocumentId, Vec<T>>,
    ) -> Result<Rc<Signed<Delegation<T>>>, AddMemberError> {
        let proof = resource
            .get_capability(&self.active.borrow().agent_id())
            .ok_or(DelegationError::Escalation)?;

        if can > proof.payload().can {
            Err(DelegationError::Escalation)?;
        }

        let after_revocations = resource.get_agent_revocations(&to_add);

        let dlg = self.try_sign(Delegation {
            delegate: to_add,
            proof: Some(proof),
            can,
            after_revocations,
            after_content,
        })?;

        let rc = Rc::new(dlg);
        resource.receive_delegation(rc.dupe())?;
        Ok(rc)
    }

    pub fn revoke_member(
        &mut self,
        to_revoke: AgentId,
        resource: &mut Membered<T>,
    ) -> Result<Vec<Rc<Signed<Revocation<T>>>>, RevokeMemberError> {
        let mut relevant_docs = BTreeMap::new();
        for (doc_id, (doc, _)) in self.reachable_docs() {
            relevant_docs.insert(doc_id, doc.borrow().content_heads.iter().cloned().collect());
        }

        let (revs, _cgka_ops) = resource.revoke_member(
            to_revoke,
            &self.active.borrow().signing_key,
            &mut relevant_docs,
        )?;

        Ok(revs)
    }

    pub fn try_encrypt_content(
        &mut self,
        doc: Rc<RefCell<Document<T>>>,
        content_ref: &T,
        pred_refs: &Vec<T>,
        content: &[u8],
    ) -> Result<EncryptedContent<Vec<u8>, T>, EncryptError> {
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
        encrypted: &EncryptedContent<Vec<u8>, T>,
    ) -> Result<Vec<u8>, DecryptError> {
        doc.borrow_mut().try_decrypt_content(encrypted)
    }

    pub fn force_pcs_update(&mut self, doc: Rc<RefCell<Document<T>>>) -> Result<(), EncryptError> {
        doc.borrow_mut().pcs_update(&mut self.csprng)
    }

    pub fn reachable_docs(&self) -> BTreeMap<DocumentId, (&Rc<RefCell<Document<T>>>, Access)> {
        self.docs_reachable_by_agent(self.active.dupe().into())
    }

    pub fn reachable_members(&self, membered: Membered<T>) -> HashMap<AgentId, (Agent<T>, Access)> {
        match membered {
            Membered::Group(group) => group.borrow().transitive_members(),
            Membered::Document(doc) => doc.borrow().transitive_members(),
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

        for doc in self.docs.values() {
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
            for doc in self.docs.values() {
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

    pub fn ops_for_agent(&self, agent: Agent<T>) -> HashMap<Digest<Operation<T>>, Operation<T>> {
        let mut ops = HashMap::new();
        let mut visited_hashes = HashSet::new();
        let mut heads: Vec<(Digest<Operation<T>>, Operation<T>)> = vec![];

        for (doc_rc, _max_acces) in self.docs_reachable_by_agent(agent).values() {
            for (hash, dlg_head) in doc_rc.borrow().delegation_heads().iter() {
                heads.push((hash.into(), dlg_head.dupe().into()));
            }

            for (hash, rev_head) in doc_rc.borrow().revocation_heads().iter() {
                heads.push((hash.into(), rev_head.dupe().into()));
            }
        }

        while let Some((hash, op)) = heads.pop() {
            if visited_hashes.contains(&hash) {
                continue;
            }

            visited_hashes.insert(hash);
            ops.insert(hash, op.clone());

            match op {
                Operation::Delegation(dlg) => {
                    if let Some(proof) = &dlg.payload.proof {
                        heads.push((Digest::hash(proof.as_ref()).into(), proof.dupe().into()));
                    }

                    for rev in dlg.payload.after_revocations.iter() {
                        heads.push((Digest::hash(rev.as_ref()).into(), rev.dupe().into()));
                    }
                }
                Operation::Revocation(rev) => {
                    if let Some(proof) = &rev.payload.proof {
                        heads.push((Digest::hash(proof.as_ref()).into(), proof.dupe().into()));
                    }

                    heads.push((
                        Digest::hash(rev.as_ref()).into(),
                        rev.payload.revoke.dupe().into(),
                    ));
                }
            }
        }

        ops
    }

    pub fn get_agent(&self, id: Identifier) -> Option<Agent<T>> {
        let indie_id = id.into();

        if indie_id == self.active.borrow().id() {
            return Some(self.active.dupe().into());
        }

        if let Some(doc) = self.docs.get(&DocumentId(id)) {
            return Some(doc.dupe().into());
        }

        if let Some(group) = self.groups.get(&GroupId::new(id)) {
            return Some(group.dupe().into());
        }

        if let Some(indie) = self.individuals.get(&indie_id) {
            return Some(indie.dupe().into());
        }

        None
    }

    pub fn receive_delegation(
        &mut self,
        static_dlg: &Signed<StaticDelegation<T>>,
    ) -> Result<(), ReceieveStaticDelegationError<T>> {
        if self
            .delegations
            .borrow()
            .contains_key(&Digest::hash(static_dlg).into())
        {
            return Ok(());
        }

        // NOTE: this is the only place this gets parsed and this verification ONLY happens here
        static_dlg.try_verify()?;

        let signed_by = static_dlg.issuer;
        let proof: Option<Rc<Signed<Delegation<T>>>> = static_dlg
            .payload()
            .proof
            .map(|proof_hash| {
                let hash = proof_hash.into();
                self.delegations
                    .borrow()
                    .get(&hash)
                    .ok_or(MissingDependency(hash))
                    .map(Dupe::dupe)
            })
            .transpose()?;

        let delegate_id = static_dlg.payload().delegate;
        let delegate: Agent<T> = self.get_agent(delegate_id).unwrap_or_else(|| {
            let indie_id = IndividualId(delegate_id);
            let indie = Rc::new(RefCell::new(Individual::new(indie_id)));
            self.individuals.insert(indie_id, indie.dupe());
            indie.into()
        });

        let after_revocations = static_dlg.payload().after_revocations.iter().try_fold(
            vec![],
            |mut acc, static_rev_hash| {
                let rev_hash = static_rev_hash.into();
                let revs = self.revocations.borrow();
                let resolved_rev = revs.get(&rev_hash).ok_or(MissingDependency(rev_hash))?;
                acc.push(resolved_rev.dupe());
                Ok::<_, ReceieveStaticDelegationError<T>>(acc)
            },
        )?;

        let delegation = Signed {
            issuer: static_dlg.issuer,
            signature: static_dlg.signature,
            payload: Delegation {
                delegate,
                proof: proof.clone(),
                can: static_dlg.payload().can,
                after_revocations,
                after_content: static_dlg.payload.after_content.clone(),
            },
        };

        let subject_id = proof.map(|prf| prf.issuer).unwrap_or(signed_by).into();

        if let Some(group) = self.groups.get(&GroupId(subject_id)) {
            group.borrow_mut().receive_delegation(Rc::new(delegation))?;
        } else if let Some(doc) = self.docs.get(&DocumentId(subject_id)) {
            doc.borrow_mut().receive_delegation(Rc::new(delegation))?;
        } else if let Some(indie) = self.individuals.remove(&IndividualId(subject_id)) {
            self.promote_individual_to_group(indie, Rc::new(delegation));
        } else {
            let group = Group::from_individual(
                Individual::new(IndividualId(subject_id)),
                Rc::new(delegation),
                self.delegations.dupe(),
                self.revocations.dupe(),
            );
            self.groups
                .insert(group.group_id(), Rc::new(RefCell::new(group)));
        };

        Ok(())
    }

    pub fn receive_revocation(
        &mut self,
        static_rev: &Signed<StaticRevocation<T>>,
    ) -> Result<(), ReceieveStaticDelegationError<T>> {
        if self
            .revocations
            .borrow()
            .contains_key(&Digest::hash(static_rev).into())
        {
            return Ok(());
        }

        // NOTE: this is the only place this gets parsed and this verification ONLY happens here
        static_rev.try_verify()?;

        let revoke_hash = static_rev.payload.revoke.into();
        let revoke: Rc<Signed<Delegation<T>>> = self
            .delegations
            .borrow()
            .get(&revoke_hash)
            .map(Dupe::dupe)
            .ok_or(MissingDependency(revoke_hash))?;

        let proof: Option<Rc<Signed<Delegation<T>>>> = static_rev
            .payload()
            .proof
            .map(|proof_hash| {
                let hash = proof_hash.into();
                self.delegations
                    .borrow()
                    .get(&hash)
                    .ok_or(MissingDependency(hash))
                    .map(Dupe::dupe)
            })
            .transpose()?;

        let revocation = Signed {
            issuer: static_rev.issuer,
            signature: static_rev.signature,
            payload: Revocation {
                revoke,
                proof,
                after_content: static_rev.payload.after_content.clone(),
            },
        };

        let id = revocation.subject();
        if let Some(group) = self.groups.get(&GroupId(id)) {
            group.borrow_mut().receive_revocation(Rc::new(revocation))?;
        } else if let Some(doc) = self.docs.get(&DocumentId(id)) {
            doc.borrow_mut().receive_revocation(Rc::new(revocation))?;
        } else if let Some(indie) = self.individuals.remove(&IndividualId(id)) {
            let group = self.promote_individual_to_group(indie, revocation.payload.revoke.dupe());
            group.borrow_mut().receive_revocation(Rc::new(revocation))?;
        } else {
            let mut group = Group::from_individual(
                Individual::new(static_rev.issuer.into()),
                revocation.payload.revoke.dupe(),
                self.delegations.dupe(),
                self.revocations.dupe(),
            );

            group.receive_revocation(Rc::new(revocation))?;
            self.groups
                .insert(group.group_id(), Rc::new(RefCell::new(group)));
        }

        Ok(())
    }

    pub fn receive_op(
        &mut self,
        static_op: &StaticOperation<T>,
    ) -> Result<(), ReceieveStaticDelegationError<T>> {
        match static_op {
            StaticOperation::Delegation(d) => self.receive_delegation(d),
            StaticOperation::Revocation(r) => self.receive_revocation(r),
        }
    }

    pub fn promote_individual_to_group(
        &mut self,
        individual: Rc<RefCell<Individual>>,
        head: Rc<Signed<Delegation<T>>>,
    ) -> Rc<RefCell<Group<T>>> {
        let group = Rc::new(RefCell::new(Group::from_individual(
            individual.borrow().clone(),
            head,
            self.delegations.dupe(),
            self.revocations.dupe(),
        )));

        let agent = Agent::from(group.dupe());

        for (digest, dlg) in self.delegations.clone().borrow().iter() {
            if dlg.payload.delegate == agent {
                self.delegations.borrow_mut().0.insert(
                    *digest,
                    Rc::new(Signed {
                        issuer: dlg.issuer,
                        signature: dlg.signature,
                        payload: Delegation {
                            delegate: agent.dupe(),
                            can: dlg.payload.can,
                            proof: dlg.payload.proof.clone(),
                            after_revocations: dlg.payload.after_revocations.clone(),
                            after_content: dlg.payload.after_content.clone(),
                        },
                    }),
                );
            }
        }

        for (digest, rev) in self.revocations.clone().borrow().iter() {
            if rev.payload.subject() == group.borrow().id() {
                self.revocations.borrow_mut().0.insert(
                    *digest,
                    Rc::new(Signed {
                        issuer: rev.issuer,
                        signature: rev.signature,
                        payload: Revocation {
                            revoke: self
                                .delegations
                                .borrow()
                                .get(&Digest::hash(&rev.payload.revoke))
                                .expect("revoked delegation to be available")
                                .dupe(),
                            proof: rev.payload.proof.dupe().map(|proof| {
                                self.delegations
                                    .borrow()
                                    .get(&Digest::hash(&proof))
                                    .cloned()
                                    .expect("revoked delegation to be available")
                            }),
                            after_content: rev.payload.after_content.clone(),
                        },
                    }),
                );
            }
        }

        group
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

#[derive(Debug, Error)]
pub enum AddMemberError {
    #[error(transparent)]
    DelegationError(#[from] DelegationError),

    #[error(transparent)]
    AddError(#[from] AddError),

    #[error(transparent)]
    SigningError(#[from] SigningError),
}

#[derive(Debug, Error)]
pub enum ReceieveStaticDelegationError<T: ContentRef> {
    #[error(transparent)]
    VerificationError(#[from] VerificationError),

    #[error("Missing proof: {0}")]
    MissingProof(#[from] MissingDependency<Digest<Signed<Delegation<T>>>>),

    #[error("Missing revocation dependency: {0}")]
    MissingRevocationDependency(#[from] MissingDependency<Digest<Signed<Revocation<T>>>>),

    #[error("Cgka init error: {0}")]
    CgkaInitError(#[from] CgkaError),

    #[error(transparent)]
    GroupReceiveError(#[from] group::error::AddError),
}
