//! The primary API for the library.

use crate::{
    ability::Ability,
    access::Access,
    archive::Archive,
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
        document::{
            id::DocumentId, AddMemberError, AddMemberUpdate, DecryptError, Document, EncryptError,
            EncryptedContentWithUpdate, MissingIndividualError, RevokeMemberUpdate,
        },
        group::{
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
        membered::{id::MemberedId, Membered},
        peer::Peer,
        public::Public,
        verifiable::Verifiable,
    },
    util::content_addressed_map::CaMap,
};
use derivative::Derivative;
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
#[derive(Debug, Derivative)]
#[derivative(PartialEq, Eq)]
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
    #[derivative(PartialEq = "ignore")]
    csprng: R,
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
            individuals: HashMap::from_iter([(
                Public.id().into(),
                Rc::new(RefCell::new(Public.individual())),
            )]),
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
        coparents: Vec<Peer<T>>,
    ) -> Result<Rc<RefCell<Group<T>>>, SigningError> {
        let g = Rc::new(RefCell::new(Group::generate(
            NonEmpty {
                head: self.active.dupe().into(),
                tail: coparents.into_iter().map(Into::into).collect(),
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
        coparents: Vec<Peer<T>>,
        initial_content_heads: NonEmpty<T>,
    ) -> Result<Rc<RefCell<Document<T>>>, DelegationError> {
        for peer in coparents.iter() {
            if self.get_agent(peer.id()).is_none() {
                self.register_peer(peer.clone());
            }
        }

        let new_doc = Document::generate(
            NonEmpty {
                head: self.active.dupe().into(),
                tail: coparents.into_iter().map(Into::into).collect(),
            },
            initial_content_heads,
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

        let doc_id = new_doc.doc_id();
        let doc = Rc::new(RefCell::new(new_doc));
        self.docs.insert(doc_id, doc.dupe());

        Ok(doc)
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

    // FIXME collsion
    pub fn register_peer(&mut self, peer: Peer<T>) -> Option<()> {
        let id = peer.id();

        if self.get_peer(id).is_some() {
            return None;
        }

        match peer {
            Peer::Individual(indie) => {
                self.individuals.insert(id.into(), indie);
            }
            Peer::Group(group) => {
                self.groups.insert(GroupId(id), group);
            }
            Peer::Document(doc) => {
                self.docs.insert(DocumentId(id), doc);
            }
        }

        Some(())
    }

    pub fn register_individual(&mut self, individual: Rc<RefCell<Individual>>) -> Option<()> {
        let id = individual.borrow().id();

        if self.individuals.contains_key(&id) {
            return None;
        }

        self.individuals.insert(id, individual);
        Some(())
    }

    pub fn register_group(&mut self, root_delegation: Signed<Delegation<T>>) -> Option<()> {
        if self
            .groups
            .contains_key(&GroupId(root_delegation.subject_id()))
        {
            return None;
        }

        let group = Group::from_individual(
            Individual::new(root_delegation.issuer.into()),
            Rc::new(root_delegation),
            self.delegations.dupe(),
            self.revocations.dupe(),
        );

        self.groups
            .insert(group.group_id(), Rc::new(RefCell::new(group)));

        Some(())
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
        other_relevant_docs: &[&Document<T>], // FIXME make this automatic
    ) -> Result<Rc<Signed<Delegation<T>>>, AddMemberError> {
        match resource {
            Membered::Group(group) => {
                let dlg = group.borrow_mut().add_member(
                    to_add,
                    can,
                    &self.active.borrow().signing_key,
                    other_relevant_docs,
                )?;

                Ok(dlg)
            }
            Membered::Document(doc) => {
                let AddMemberUpdate { delegation, .. } = doc.borrow_mut().add_member(
                    to_add,
                    can,
                    &self.active.borrow().signing_key,
                    other_relevant_docs,
                )?;

                Ok(delegation)
            }
        }
    }

    pub fn revoke_member(
        &mut self,
        to_revoke: Identifier,
        resource: &mut Membered<T>,
    ) -> Result<Vec<Rc<Signed<Revocation<T>>>>, RevokeMemberError> {
        let mut relevant_docs = BTreeMap::new();
        for (doc_id, Ability { doc, .. }) in self.reachable_docs() {
            relevant_docs.insert(doc_id, doc.borrow().content_heads.iter().cloned().collect());
        }

        let RevokeMemberUpdate { revocations, .. } = resource.revoke_member(
            to_revoke,
            &self.active.borrow().signing_key,
            &mut relevant_docs,
        )?;

        Ok(revocations)
    }

    pub fn try_encrypt_content(
        &mut self,
        doc: Rc<RefCell<Document<T>>>,
        content_ref: &T,
        pred_refs: &Vec<T>,
        content: &[u8],
    ) -> Result<EncryptedContent<Vec<u8>, T>, EncryptError> {
        let EncryptedContentWithUpdate {
            encrypted_content, ..
            // FIXME: We need to handle the optional op as well
        } = doc.borrow_mut().try_encrypt_content(
            content_ref,
            content,
            pred_refs,
            &mut self.csprng,
        )?;

        Ok(encrypted_content)
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

    pub fn reachable_docs(&self) -> BTreeMap<DocumentId, Ability<T>> {
        self.docs_reachable_by_agent(self.active.dupe().into())
    }

    pub fn reachable_members(
        &self,
        membered: Membered<T>,
    ) -> HashMap<Identifier, (Agent<T>, Access)> {
        match membered {
            Membered::Group(group) => group.borrow().transitive_members(),
            Membered::Document(doc) => doc.borrow().transitive_members(),
        }
    }

    pub fn docs_reachable_by_agent(&self, agent: Agent<T>) -> BTreeMap<DocumentId, Ability<T>> {
        let mut explore: Vec<(Rc<RefCell<Group<T>>>, Access)> = vec![];
        let mut caps: BTreeMap<DocumentId, Ability<T>> = BTreeMap::new();
        let mut seen: HashSet<AgentId> = HashSet::new();

        for doc in self.docs.values() {
            seen.insert(doc.clone().borrow().agent_id());

            let doc_id = doc.borrow().doc_id();

            if let Some(proofs) = doc.borrow().members().get(&agent.id()) {
                for proof in proofs {
                    caps.insert(
                        doc_id,
                        Ability {
                            doc,
                            can: proof.payload().can,
                        },
                    );
                }
            }
        }

        for group in self.groups.values() {
            seen.insert(group.borrow().agent_id());

            if let Some(proofs) = group.borrow().members().get(&agent.id()) {
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

                if let Some(proofs) = doc.borrow().members().get(&agent.id()) {
                    for proof in proofs {
                        caps.insert(
                            doc_id,
                            Ability {
                                doc,
                                can: proof.payload.can,
                            },
                        );
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

                if let Some(proofs) = focus_group.borrow().members().get(&agent.id()) {
                    for proof in proofs {
                        explore.push((focus_group.dupe(), proof.payload.can));
                    }
                }
            }
        }

        caps
    }

    pub fn membered_reachable_by_agent(
        &self,
        agent: Agent<T>,
    ) -> HashMap<MemberedId, (Membered<T>, Access)> {
        let mut caps = HashMap::new();

        for group in self.groups.values() {
            if let Some((_, can)) = group.borrow().transitive_members().get(&agent.id()) {
                caps.insert(
                    group.borrow().group_id().into(),
                    (group.dupe().into(), *can),
                );
            }
        }

        for doc in self.docs.values() {
            if let Some((_, can)) = doc.borrow().transitive_members().get(&agent.id()) {
                caps.insert(doc.borrow().doc_id().into(), (doc.dupe().into(), *can));
            }
        }

        caps
    }

    pub fn ops_for_agent(&self, agent: Agent<T>) -> HashMap<Digest<Operation<T>>, Operation<T>> {
        let mut ops = HashMap::new();
        let mut visited_hashes = HashSet::new();
        let mut heads: Vec<(Digest<Operation<T>>, Operation<T>)> = vec![];

        for (mem_rc, _max_acces) in self.membered_reachable_by_agent(agent).values() {
            for (hash, dlg_head) in mem_rc.delegation_heads().iter() {
                heads.push((hash.into(), dlg_head.dupe().into()));
            }

            for (hash, rev_head) in mem_rc.revocation_heads().iter() {
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

                    let r = rev.payload.revoke.dupe();
                    heads.push((Digest::hash(r.as_ref()).into(), r.into()));
                }
            }
        }

        ops
    }

    pub fn get_individual(&self, id: IndividualId) -> Option<&Rc<RefCell<Individual>>> {
        self.individuals.get(&id)
    }

    pub fn get_group(&self, id: GroupId) -> Option<&Rc<RefCell<Group<T>>>> {
        self.groups.get(&id)
    }

    pub fn get_document(&self, id: DocumentId) -> Option<&Rc<RefCell<Document<T>>>> {
        self.docs.get(&id)
    }

    pub fn get_peer(&self, id: Identifier) -> Option<Peer<T>> {
        let indie_id = IndividualId(id);

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

        let subject_id = delegation.subject_id();
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

            if let Some(content_heads) = static_dlg
                .payload
                .after_content
                .get(&subject_id.into())
                .and_then(|content_heads| NonEmpty::collect(content_heads.iter().cloned()))
            {
                let doc = Document::from_group(group, &self.active.borrow(), content_heads)?;
                self.docs.insert(doc.doc_id(), Rc::new(RefCell::new(doc)));
            } else {
                self.groups
                    .insert(group.group_id(), Rc::new(RefCell::new(group)));
            }
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

        let id = revocation.subject_id();
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
            if rev.payload.subject_id() == group.borrow().id() {
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

    pub fn into_archive(&self) -> Archive<T> {
        Archive {
            active: self.active.borrow().clone(),
            topsorted_ops: Operation::<T>::topsort(
                &self.delegations.borrow(),
                &self.revocations.borrow(),
            )
            .into_iter()
            .map(|(k, v)| (k.into(), v.into()))
            .collect(),
            individuals: self
                .individuals
                .iter()
                .map(|(k, rc_v)| (*k, rc_v.borrow().clone()))
                .collect(),
            groups: self
                .groups
                .iter()
                .map(|(k, rc_v)| (*k, rc_v.borrow().clone().into()))
                .collect(),
            docs: self
                .docs
                .iter()
                .map(|(k, rc_v)| (*k, rc_v.borrow().clone().into()))
                .collect(),
        }
    }

    pub fn try_from_archive(
        archive: &Archive<T>,
        csprng: R,
    ) -> Result<Self, TryFromArchiveError<T>> {
        let active = Rc::new(RefCell::new(archive.active.clone()));

        let delegations: Rc<RefCell<CaMap<Signed<Delegation<T>>>>> = Default::default();
        let revocations: Rc<RefCell<CaMap<Signed<Revocation<T>>>>> = Default::default();

        let mut individuals = HashMap::new();
        for (k, v) in archive.individuals.iter() {
            individuals.insert(*k, Rc::new(RefCell::new(v.clone())));
        }

        let mut groups = HashMap::new();
        for (group_id, group_archive) in archive.groups.iter() {
            groups.insert(
                *group_id,
                Rc::new(RefCell::new(Group::<T>::dummy_from_archive(
                    group_archive.clone(),
                    delegations.dupe(),
                    revocations.dupe(),
                ))),
            );
        }

        let mut docs = HashMap::new();
        for (doc_id, doc_archive) in archive.docs.iter() {
            docs.insert(
                *doc_id,
                Rc::new(RefCell::new(Document::<T>::dummy_from_archive(
                    doc_archive.clone(),
                    &individuals,
                    delegations.dupe(),
                    revocations.dupe(),
                )?)),
            );
        }

        for (digest, static_op) in archive.topsorted_ops.iter() {
            match static_op {
                StaticOperation::Delegation(sd) => {
                    let proof: Option<Rc<Signed<Delegation<T>>>> = sd
                        .payload
                        .proof
                        .map(|proof_digest| {
                            delegations
                                .borrow()
                                .get(&proof_digest.into())
                                .ok_or(TryFromArchiveError::MissingDelegation(proof_digest.into()))
                                .cloned()
                        })
                        .transpose()?;

                    let mut after_revocations = vec![];
                    for rev_digest in sd.payload.after_revocations.iter() {
                        let r: Rc<Signed<Revocation<T>>> = revocations
                            .borrow()
                            .get(&rev_digest.into())
                            .ok_or(TryFromArchiveError::MissingRevocation(rev_digest.into()))?
                            .dupe();

                        after_revocations.push(r);
                    }

                    let id = sd.payload.delegate;
                    let delegate: Agent<T> = if id == archive.active.id().into() {
                        active.dupe().into()
                    } else {
                        individuals
                            .get(&IndividualId(id))
                            .map(|i| i.dupe().into())
                            .or_else(|| groups.get(&GroupId(id)).map(|g| g.dupe().into()))
                            .or_else(|| docs.get(&DocumentId(id)).map(|d| d.dupe().into()))
                            .ok_or(TryFromArchiveError::MissingAgent(Box::new(id)))?
                    };

                    delegations.borrow_mut().0.insert(
                        (*digest).into(),
                        Rc::new(Signed {
                            signature: sd.signature,
                            issuer: sd.issuer,
                            payload: Delegation {
                                delegate,
                                proof,
                                can: sd.payload.can,
                                after_revocations,
                                after_content: sd.payload.after_content.clone(),
                            },
                        }),
                    );
                }
                StaticOperation::Revocation(sr) => {
                    revocations.borrow_mut().0.insert(
                        (*digest).into(),
                        Rc::new(Signed {
                            issuer: sr.issuer,
                            signature: sr.signature,
                            payload: Revocation {
                                revoke: delegations
                                    .borrow()
                                    .get(&sr.payload.revoke.into())
                                    .ok_or(TryFromArchiveError::MissingDelegation(
                                        sr.payload.revoke.into(),
                                    ))
                                    .cloned()?,
                                proof: sr
                                    .payload
                                    .proof
                                    .map(|proof_digest| {
                                        delegations
                                            .borrow()
                                            .get(&proof_digest.into())
                                            .ok_or(TryFromArchiveError::MissingDelegation(
                                                proof_digest.into(),
                                            ))
                                            .cloned()
                                    })
                                    .transpose()?,
                                after_content: sr.payload.after_content.clone(),
                            },
                        }),
                    );
                }
            };
        }

        fn reify_ops<U: ContentRef>(
            group: &mut Group<U>,
            dlg_store: Rc<RefCell<CaMap<Signed<Delegation<U>>>>>,
            rev_store: Rc<RefCell<CaMap<Signed<Revocation<U>>>>>,
            dlg_head_hashes: &HashSet<Digest<Signed<Delegation<U>>>>,
            rev_head_hashes: &HashSet<Digest<Signed<Revocation<U>>>>,
            members: HashMap<Identifier, NonEmpty<Digest<Signed<Delegation<U>>>>>,
        ) -> Result<(), TryFromArchiveError<U>> {
            let read_dlgs = dlg_store.borrow();
            let read_revs = rev_store.borrow();

            for dlg_hash in dlg_head_hashes.iter() {
                let actual_dlg = read_dlgs
                    .get(dlg_hash)
                    .ok_or(TryFromArchiveError::MissingDelegation(*dlg_hash))?;
                group.state.delegation_heads.insert(actual_dlg.dupe());
            }

            for rev_hash in rev_head_hashes.iter() {
                let actual_rev = read_revs
                    .get(rev_hash)
                    .ok_or(TryFromArchiveError::MissingRevocation(*rev_hash))?;
                group.state.revocation_heads.insert(actual_rev.dupe());
            }

            for (agent_id, proof_hashes) in members.iter() {
                let mut proofs = vec![];
                for proof_hash in proof_hashes.iter() {
                    let actual_dlg = read_dlgs
                        .get(proof_hash)
                        .ok_or(TryFromArchiveError::MissingDelegation(*proof_hash))?;
                    proofs.push(actual_dlg.dupe());
                }
                group.members.insert(
                    *agent_id,
                    NonEmpty::try_from(proofs)
                        .expect("started from a nonempty, so this should also be nonempty"),
                );
            }

            Ok(())
        }

        for (group_id, group) in groups.iter() {
            let group_archive = archive
                .groups
                .get(group_id)
                .ok_or(TryFromArchiveError::MissingGroup(Box::new(*group_id)))?;

            reify_ops(
                &mut group.borrow_mut(),
                delegations.dupe(),
                revocations.dupe(),
                &group_archive.state.delegation_heads,
                &group_archive.state.revocation_heads,
                group_archive
                    .members
                    .iter()
                    .map(|(k, v)| ((*k).into(), v.clone()))
                    .collect(),
            )?;
        }

        for (doc_id, doc) in docs.iter() {
            let doc_archive = archive
                .docs
                .get(doc_id)
                .ok_or(TryFromArchiveError::MissingDocument(Box::new(*doc_id)))?;

            reify_ops(
                &mut doc.borrow_mut().group,
                delegations.dupe(),
                revocations.dupe(),
                &doc_archive.group.state.delegation_heads,
                &doc_archive.group.state.revocation_heads,
                doc_archive
                    .group
                    .members
                    .iter()
                    .map(|(k, v)| ((*k).into(), v.clone()))
                    .collect(),
            )?;
        }

        Ok(Self {
            active,
            individuals,
            groups,
            docs,
            delegations,
            revocations,
            csprng,
        })
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
    GroupReceiveError(#[from] AddError),
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum TryFromArchiveError<T: ContentRef> {
    #[error("Missing delegation: {0}")]
    MissingDelegation(#[from] Digest<Signed<Delegation<T>>>),

    #[error("Missing revocation: {0}")]
    MissingRevocation(#[from] Digest<Signed<Revocation<T>>>),

    #[error("Missing individual: {0}")]
    MissingIndividual(Box<IndividualId>),

    #[error("Missing group: {0}")]
    MissingGroup(Box<GroupId>),

    #[error("Missing document: {0}")]
    MissingDocument(Box<DocumentId>),

    #[error("Missing agent: {0}")]
    MissingAgent(Box<Identifier>),
}

impl<T: ContentRef> From<MissingIndividualError> for TryFromArchiveError<T> {
    fn from(e: MissingIndividualError) -> Self {
        TryFromArchiveError::MissingIndividual(e.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{access::Access, principal::public::Public};
    use nonempty::nonempty;
    use pretty_assertions::assert_eq;

    #[test]
    fn test_archival_round_trip() {
        let mut csprng = rand::thread_rng();

        let sk = ed25519_dalek::SigningKey::generate(&mut csprng);
        let mut hive = Beehive::generate(sk, rand::thread_rng()).unwrap();

        let indie_sk = ed25519_dalek::SigningKey::generate(&mut csprng);
        let indie = Rc::new(RefCell::new(
            Individual::generate(&indie_sk, &mut csprng).unwrap(),
        ));

        hive.register_individual(indie.dupe());
        hive.generate_group(vec![indie.dupe().into()]).unwrap();
        hive.generate_doc(
            vec![indie.into()],
            nonempty!["ref1".to_string(), "ref2".to_string()],
        )
        .unwrap();

        assert!(hive.active.borrow().prekey_pairs.len() > 0);
        assert_eq!(hive.individuals.len(), 2);
        assert_eq!(hive.groups.len(), 1);
        assert_eq!(hive.docs.len(), 1);
        assert_eq!(hive.delegations.borrow().len(), 4);
        assert_eq!(hive.revocations.borrow().len(), 0);

        let archive = hive.into_archive();

        assert_eq!(hive.id(), archive.active.id());
        assert_eq!(archive.individuals.len(), 2);
        assert_eq!(archive.groups.len(), 1);
        assert_eq!(archive.docs.len(), 1);
        assert_eq!(archive.topsorted_ops.len(), 4);

        let hive_from_archive = Beehive::try_from_archive(&archive, rand::thread_rng()).unwrap();

        assert_eq!(hive, hive_from_archive);
    }

    #[test]
    fn test_receive_delegations_associately() {
        let mut hive1 = make_beehive();
        let mut hive2 = make_beehive();

        let hive2_on_hive1 = Rc::new(RefCell::new(hive2.active.borrow().individual.clone()));
        hive1.register_individual(hive2_on_hive1.dupe());
        let group1_on_hive1 = hive1.generate_group(vec![hive2_on_hive1.into()]).unwrap();

        assert_eq!(hive1.delegations.borrow().len(), 2);
        assert_eq!(hive1.revocations.borrow().len(), 0);
        assert_eq!(hive1.individuals.len(), 2); // NOTE: knows about Public and Hive2
        assert_eq!(hive1.groups.len(), 1);
        assert_eq!(hive1.docs.len(), 0);

        assert_eq!(group1_on_hive1.borrow().delegation_heads().len(), 2);
        assert_eq!(group1_on_hive1.borrow().revocation_heads().len(), 0);

        for dlg in group1_on_hive1.borrow().delegation_heads().values() {
            assert_eq!(dlg.subject_id(), group1_on_hive1.borrow().group_id().into());

            let delegate_id = dlg.payload.delegate.dupe().agent_id();
            assert!(delegate_id == hive1.agent_id() || delegate_id == hive2.agent_id());
        }

        assert_eq!(hive2.delegations.borrow().len(), 0);
        assert_eq!(hive2.revocations.borrow().len(), 0);
        assert_eq!(hive2.individuals.len(), 1); // NOTE: Public only in this case
        assert_eq!(hive2.groups.len(), 0);
        assert_eq!(hive2.docs.len(), 0);

        for dlg in group1_on_hive1.borrow().delegation_heads().values() {
            let static_dlg = dlg.as_ref().clone().map(|d| d.into()); // TODO add From instance
            hive2.receive_delegation(&static_dlg).unwrap();
        }

        assert_eq!(hive2.delegations.borrow().len(), 2);
        assert_eq!(hive2.revocations.borrow().len(), 0);
        assert_eq!(hive2.individuals.len(), 2); // NOTE: Public and Hive2
        assert_eq!(hive2.groups.len(), 1);
        assert_eq!(hive2.docs.len(), 0);
    }

    #[test]
    fn test_transitive_ops_for_agent() {
        let mut left = make_beehive();
        let mut middle = make_beehive();
        let mut right = make_beehive();

        // 2 delegations (you & public)
        let left_doc = left
            .generate_doc(
                vec![Rc::new(RefCell::new(Public.individual())).into()],
                nonempty![[0u8; 32]],
            )
            .unwrap();
        // 1 delegation (you)
        let left_group = left.generate_group(vec![]).unwrap();

        assert_eq!(left.delegations.borrow().len(), 3);
        assert_eq!(left.revocations.borrow().len(), 0);

        assert_eq!(left.individuals.len(), 1);
        assert!(left.individuals.get(&IndividualId(Public.id())).is_some());

        assert_eq!(left.groups.len(), 1);
        assert_eq!(left.docs.len(), 1);

        assert!(left.docs.get(&left_doc.borrow().doc_id()).is_some());
        assert!(left.groups.get(&left_group.borrow().group_id()).is_some());

        // NOTE: *NOT* the group
        let left_membered = left.membered_reachable_by_agent(Public.individual().into());

        assert_eq!(left_membered.len(), 1);
        assert!(left_membered
            .get(&left_doc.borrow().doc_id().into())
            .is_some());
        assert!(left_membered
            .get(&left_group.borrow().group_id().into())
            .is_none()); // NOTE *not* included because Public is not a member

        let left_to_mid_ops = left.ops_for_agent(Public.individual().into());
        assert_eq!(left_to_mid_ops.len(), 2);
        for (h, op) in &left_to_mid_ops {
            middle.receive_op(&op.clone().into()).unwrap();
            assert!(middle.delegations.borrow().get(&h.into()).is_some());
        }

        // Left unchanged
        assert_eq!(left.groups.len(), 1);
        assert_eq!(left.docs.len(), 1);
        assert_eq!(left.delegations.borrow().len(), 3);
        assert_eq!(left.revocations.borrow().len(), 0);

        // Middle should now look the same
        assert!(middle.docs.get(&left_doc.borrow().doc_id()).is_some());
        assert!(middle.groups.get(&left_group.borrow().group_id()).is_none()); // NOTE: *None*

        assert_eq!(middle.individuals.len(), 2); // NOTE: includes Left
        assert_eq!(middle.groups.len(), 0);
        assert_eq!(middle.docs.len(), 1);

        assert_eq!(middle.revocations.borrow().len(), 0);
        assert_eq!(middle.delegations.borrow().len(), 2);
        assert_eq!(
            middle
                .docs
                .get(&DocumentId(left_doc.borrow().id()))
                .unwrap()
                .borrow()
                .delegation_heads()
                .len(),
            2
        );

        let mid_to_right_ops = middle.ops_for_agent(Public.individual().into());
        assert_eq!(mid_to_right_ops.len(), 2);
        for (h, op) in &mid_to_right_ops {
            right.receive_op(&op.clone().into()).unwrap();
            assert!(right.delegations.borrow().get(&h.into()).is_some());
        }

        // Left unchanged
        assert_eq!(left.groups.len(), 1);
        assert_eq!(left.docs.len(), 1);
        assert_eq!(left.delegations.borrow().len(), 3);
        assert_eq!(left.revocations.borrow().len(), 0);

        // Middle unchanged
        assert_eq!(middle.individuals.len(), 2);
        assert_eq!(middle.groups.len(), 0);
        assert_eq!(middle.docs.len(), 1);

        assert_eq!(middle.delegations.borrow().len(), 2);
        assert_eq!(middle.revocations.borrow().len(), 0);

        // Right should now look the same
        assert_eq!(right.revocations.borrow().len(), 0);
        assert_eq!(right.delegations.borrow().len(), 2);

        assert!(right.groups.len() == 1 || right.docs.len() == 1);
        assert!(right
            .docs
            .get(&DocumentId(left_doc.borrow().id()))
            .is_some());
        assert!(right.groups.get(&left_group.borrow().group_id()).is_none()); // NOTE: *None*

        assert_eq!(right.individuals.len(), 2);
        assert_eq!(right.groups.len(), 0);
        assert_eq!(right.docs.len(), 1);

        // Now, the right hand side should have the same ops as the left
        let ops_on_right = right.ops_for_agent(Public.individual().into());
        assert_eq!(left_to_mid_ops.len(), 2);

        assert_eq!(
            left_to_mid_ops.keys().collect::<HashSet<_>>(),
            mid_to_right_ops.keys().collect::<HashSet<_>>()
        );
        assert_eq!(
            mid_to_right_ops.keys().collect::<HashSet<_>>(),
            ops_on_right.keys().collect::<HashSet<_>>()
        );

        right.generate_group(vec![left_doc.dupe().into()]).unwrap();

        // Check transitivity
        let transitive_right_to_mid_ops = right.ops_for_agent(Public.individual().into());
        assert_eq!(transitive_right_to_mid_ops.len(), 4);
        for (h, op) in &transitive_right_to_mid_ops {
            middle.receive_op(&op.clone().into()).unwrap();
            assert!(middle.delegations.borrow().get(&h.into()).is_some());
        }
        assert_eq!(middle.individuals.len(), 3); // NOTE now includes Right
        assert_eq!(middle.groups.len(), 1);
        assert_eq!(middle.docs.len(), 1);
        assert_eq!(middle.delegations.borrow().len(), 4);
    }

    fn make_beehive() -> Beehive<[u8; 32], rand::rngs::OsRng> {
        let sk = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        Beehive::generate(sk, rand::rngs::OsRng).unwrap()
    }

    #[test]
    fn test_add_member() {
        let mut beehive = make_beehive();
        let doc = beehive
            .generate_doc(
                vec![Rc::new(RefCell::new(Public.individual())).into()],
                nonempty![[0u8; 32]],
            )
            .unwrap();
        let member = Public.individual().into();
        let dlg = beehive
            .add_member(member, &mut doc.clone().into(), Access::Read, &[])
            .unwrap();

        assert_eq!(dlg.subject_id(), doc.borrow().doc_id().into());
    }
}
