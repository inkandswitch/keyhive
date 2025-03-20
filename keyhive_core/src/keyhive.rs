//! The primary API for the library.

use crate::{
    ability::Ability,
    access::Access,
    archive::Archive,
    cgka::{error::CgkaError, operation::CgkaOperation},
    contact_card::ContactCard,
    content::reference::ContentRef,
    crypto::{
        digest::Digest,
        encrypted::EncryptedContent,
        share_key::ShareKey,
        signed::{Signed, SigningError, VerificationError},
        signer::async_signer::AsyncSigner,
        verifiable::Verifiable,
    },
    error::missing_dependency::MissingDependency,
    event::{static_event::StaticEvent, Event},
    listener::{
        cgka::CgkaListener, log::Log, membership::MembershipListener, no_listener::NoListener,
    },
    principal::{
        active::Active,
        agent::{id::AgentId, Agent},
        document::{
            id::DocumentId, AddMemberError, AddMemberUpdate, DecryptError, Document, EncryptError,
            EncryptedContentWithUpdate, GenerateDocError, MissingIndividualError,
            RevokeMemberUpdate,
        },
        group::{
            delegation::{Delegation, StaticDelegation},
            error::AddError,
            id::GroupId,
            membership_operation::{MembershipOperation, StaticMembershipOperation},
            revocation::{Revocation, StaticRevocation},
            Group, IdOrIndividual, RevokeMemberError,
        },
        identifier::Identifier,
        individual::{
            id::IndividualId,
            op::{add_key::AddKeyOp, rotate_key::RotateKeyOp, KeyOp},
            Individual, ReceivePrekeyOpError,
        },
        membered::{id::MemberedId, Membered},
        peer::Peer,
        public::Public,
    },
    store::{delegation::DelegationStore, revocation::RevocationStore},
    transact::{fork::Fork, merge::Merge},
};
use derivative::Derivative;
use derive_where::derive_where;
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
pub struct Keyhive<
    S: AsyncSigner,
    T: ContentRef = [u8; 32],
    L: MembershipListener<S, T> + CgkaListener = NoListener,
    R: rand::CryptoRng = rand::rngs::ThreadRng,
> {
    /// The [`Active`] user agent.
    active: Rc<RefCell<Active<S, T, L>>>,

    /// The [`Individual`]s that are known to this agent.
    individuals: HashMap<IndividualId, Rc<RefCell<Individual>>>,

    /// The [`Group`]s that are known to this agent.
    groups: HashMap<GroupId, Rc<RefCell<Group<S, T, L>>>>,

    /// The [`Document`]s that are known to this agent.
    docs: HashMap<DocumentId, Rc<RefCell<Document<S, T, L>>>>,

    /// All applied [`Delegation`]s
    delegations: DelegationStore<S, T, L>,

    /// All applied [`Revocation`]s
    revocations: RevocationStore<S, T, L>,

    /// Obsever for [`Event`]s. Intended for running live updates.
    event_listener: L,

    /// Cryptographically secure (pseudo)random number generator.
    #[derivative(PartialEq = "ignore")]
    csprng: R,
}

impl<
        S: AsyncSigner,
        T: ContentRef,
        L: MembershipListener<S, T> + CgkaListener,
        R: rand::CryptoRng + rand::RngCore,
    > Keyhive<S, T, L, R>
{
    pub fn id(&self) -> IndividualId {
        self.active.borrow().id()
    }

    pub fn agent_id(&self) -> AgentId {
        self.active.borrow().agent_id()
    }

    pub async fn generate(
        signer: S,
        event_listener: L,
        mut csprng: R,
    ) -> Result<Self, SigningError> {
        Ok(Self {
            active: Rc::new(RefCell::new(
                Active::generate(signer, event_listener.clone(), &mut csprng).await?,
            )),
            individuals: HashMap::from_iter([(
                Public.id().into(),
                Rc::new(RefCell::new(Public.individual())),
            )]),
            groups: HashMap::new(),
            docs: HashMap::new(),
            delegations: DelegationStore::new(),
            revocations: RevocationStore::new(),
            event_listener,
            csprng,
        })
    }

    /// The current [`Active`] Keyhive user.
    pub fn active(&self) -> &Rc<RefCell<Active<S, T, L>>> {
        &self.active
    }

    /// Get the [`Individual`] for the current Keyhive user.
    ///
    /// This is what you would share with a peer for them to
    /// register your identity on their system.
    ///
    /// Importantly this includes prekeys in addition to your public key.
    pub fn individual(&self) -> Individual {
        self.active.borrow().individual().clone()
    }

    pub fn groups(&self) -> &HashMap<GroupId, Rc<RefCell<Group<S, T, L>>>> {
        &self.groups
    }

    pub fn documents(&self) -> &HashMap<DocumentId, Rc<RefCell<Document<S, T, L>>>> {
        &self.docs
    }

    pub async fn generate_group(
        &mut self,
        coparents: Vec<Peer<S, T, L>>,
    ) -> Result<Rc<RefCell<Group<S, T, L>>>, SigningError> {
        let g = Rc::new(RefCell::new(
            Group::generate(
                NonEmpty {
                    head: self.active.dupe().into(),
                    tail: coparents.into_iter().map(Into::into).collect(),
                },
                self.delegations.dupe(),
                self.revocations.dupe(),
                self.event_listener.clone(),
                &mut self.csprng,
            )
            .await?,
        ));

        self.groups.insert(g.borrow().group_id(), g.dupe());

        Ok(g)
    }

    pub async fn generate_doc(
        &mut self,
        coparents: Vec<Peer<S, T, L>>,
        initial_content_heads: NonEmpty<T>,
    ) -> Result<Rc<RefCell<Document<S, T, L>>>, GenerateDocError> {
        for peer in coparents.iter() {
            if self.get_agent(peer.id()).is_none() {
                self.register_peer(peer.dupe());
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
            self.event_listener.clone(),
            &self.active.borrow().signer,
            &mut self.csprng,
        )
        .await?;

        for head in new_doc.delegation_heads().values() {
            self.delegations.insert(head.dupe());

            for dep in head.payload().proof_lineage() {
                self.delegations.insert(dep);
            }
        }

        let doc_id = new_doc.doc_id();
        let doc = Rc::new(RefCell::new(new_doc));
        self.docs.insert(doc_id, doc.dupe());

        Ok(doc)
    }

    pub async fn contact_card(&mut self) -> Result<ContactCard, SigningError> {
        let rot_key_op = self
            .active
            .borrow_mut()
            .generate_private_prekey(&mut self.csprng)
            .await?;

        Ok(ContactCard(KeyOp::Rotate(rot_key_op)))
    }

    pub async fn rotate_prekey(
        &mut self,
        prekey: ShareKey,
    ) -> Result<Rc<Signed<RotateKeyOp>>, SigningError> {
        self.active
            .borrow_mut()
            .rotate_prekey(prekey, &mut self.csprng)
            .await
    }

    pub async fn expand_prekeys(&mut self) -> Result<Rc<Signed<AddKeyOp>>, SigningError> {
        self.active
            .borrow_mut()
            .expand_prekeys(&mut self.csprng)
            .await
    }

    pub async fn try_sign<U: Serialize>(&self, data: U) -> Result<Signed<U>, SigningError> {
        self.active.borrow().try_sign_async(data).await
    }

    pub fn register_peer(&mut self, peer: Peer<S, T, L>) -> bool {
        let id = peer.id();

        if self.get_peer(id).is_some() {
            return false;
        }

        match peer {
            Peer::Individual(indie) => {
                self.individuals.insert(id.into(), indie.dupe());
            }
            Peer::Group(group) => {
                self.groups.insert(GroupId(id), group.dupe());
            }
            Peer::Document(doc) => {
                self.docs.insert(DocumentId(id), doc.dupe());
            }
        }

        true
    }

    pub fn register_individual(&mut self, individual: Rc<RefCell<Individual>>) -> bool {
        let id = individual.borrow().id();

        if self.individuals.contains_key(&id) {
            return false;
        }

        self.individuals.insert(id, individual.dupe());
        true
    }

    pub fn register_group(&mut self, root_delegation: Signed<Delegation<S, T, L>>) -> bool {
        if self
            .groups
            .contains_key(&GroupId(root_delegation.subject_id()))
        {
            return false;
        }

        let group = Rc::new(RefCell::new(Group::new(
            GroupId(root_delegation.issuer.into()),
            Rc::new(root_delegation),
            self.delegations.dupe(),
            self.revocations.dupe(),
            self.event_listener.clone(),
        )));

        self.groups.insert(group.borrow().group_id(), group.dupe());
        true
    }

    pub fn get_membership_operation(
        &self,
        digest: &Digest<MembershipOperation<S, T, L>>,
    ) -> Option<MembershipOperation<S, T, L>> {
        self.delegations
            .get(&digest.into())
            .map(|d| d.dupe().into())
            .or_else(|| {
                self.revocations
                    .get(&digest.into())
                    .map(|r| r.dupe().into())
            })
    }

    pub async fn add_member(
        &mut self,
        to_add: Agent<S, T, L>,
        resource: &mut Membered<S, T, L>,
        can: Access,
        other_relevant_docs: &[Rc<RefCell<Document<S, T, L>>>], // TODO make this automatic
    ) -> Result<AddMemberUpdate<S, T, L>, AddMemberError> {
        match resource {
            Membered::Group(group) => Ok(group
                .borrow_mut()
                .add_member(
                    to_add,
                    can,
                    &self.active.borrow().signer,
                    other_relevant_docs,
                )
                .await?),
            Membered::Document(doc) => {
                doc.borrow_mut()
                    .add_member(
                        to_add,
                        can,
                        &self.active.borrow().signer,
                        other_relevant_docs,
                    )
                    .await
            }
        }
    }

    #[allow(clippy::type_complexity)]
    pub async fn revoke_member(
        &mut self,
        to_revoke: Identifier,
        retain_all_other_members: bool,
        resource: &mut Membered<S, T, L>,
    ) -> Result<RevokeMemberUpdate<S, T, L>, RevokeMemberError> {
        let mut relevant_docs = BTreeMap::new();
        for (doc_id, Ability { doc, .. }) in self.reachable_docs() {
            relevant_docs.insert(doc_id, doc.borrow().content_heads.iter().cloned().collect());
        }

        resource
            .revoke_member(
                to_revoke,
                retain_all_other_members,
                &self.active.borrow().signer,
                &mut relevant_docs,
            )
            .await
    }

    pub async fn try_encrypt_content(
        &mut self,
        doc: Rc<RefCell<Document<S, T, L>>>,
        content_ref: &T,
        pred_refs: &Vec<T>,
        content: &[u8],
    ) -> Result<EncryptedContentWithUpdate<T>, EncryptContentError> {
        Ok(doc
            .borrow_mut()
            .try_encrypt_content(
                content_ref,
                content,
                pred_refs,
                &self.active.borrow().signer,
                &mut self.csprng,
            )
            .await?)
    }

    pub fn try_decrypt_content(
        &mut self,
        doc: Rc<RefCell<Document<S, T, L>>>,
        encrypted: &EncryptedContent<Vec<u8>, T>,
    ) -> Result<Vec<u8>, DecryptError> {
        doc.borrow_mut().try_decrypt_content(encrypted)
    }

    pub async fn force_pcs_update(
        &mut self,
        doc: Rc<RefCell<Document<S, T, L>>>,
    ) -> Result<Signed<CgkaOperation>, EncryptError> {
        doc.borrow_mut()
            .pcs_update(&self.active.borrow().signer, &mut self.csprng)
            .await
    }

    pub fn reachable_docs(&self) -> BTreeMap<DocumentId, Ability<S, T, L>> {
        self.docs_reachable_by_agent(&self.active.dupe().into())
    }

    pub fn reachable_members(
        &self,
        membered: Membered<S, T, L>,
    ) -> HashMap<Identifier, (Agent<S, T, L>, Access)> {
        match membered {
            Membered::Group(group) => group.borrow().transitive_members(),
            Membered::Document(doc) => doc.borrow().transitive_members(),
        }
    }

    pub fn docs_reachable_by_agent(
        &self,
        agent: &Agent<S, T, L>,
    ) -> BTreeMap<DocumentId, Ability<S, T, L>> {
        let mut caps: BTreeMap<DocumentId, Ability<S, T, L>> = BTreeMap::new();
        let mut seen: HashSet<AgentId> = HashSet::new();

        #[allow(clippy::type_complexity)]
        let mut explore: Vec<(Rc<RefCell<Group<S, T, L>>>, Access)> = vec![];

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
        agent: &Agent<S, T, L>,
    ) -> HashMap<MemberedId, (Membered<S, T, L>, Access)> {
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

    pub fn events_for_agent(
        &self,
        agent: &Agent<S, T, L>,
    ) -> Result<HashMap<Digest<Event<S, T, L>>, Event<S, T, L>>, CgkaError> {
        let mut ops: HashMap<_, _> = self
            .membership_ops_for_agent(agent)
            .into_iter()
            .map(|(op_digest, op)| (op_digest.into(), op.into()))
            .collect();

        for key_ops in self.reachable_prekey_ops_for_agent(agent).values() {
            for key_op in key_ops.iter() {
                let op = Event::<S, T, L>::from(key_op.as_ref().dupe());
                ops.insert(Digest::hash(&op), op);
            }
        }

        for cgka_op in self.cgka_ops_reachable_by_agent(agent)?.into_iter() {
            let op = Event::<S, T, L>::from(cgka_op);
            ops.insert(Digest::hash(&op), op);
        }

        Ok(ops)
    }

    pub fn static_events_for_agent(
        &self,
        agent: &Agent<S, T, L>,
    ) -> Result<HashMap<Digest<StaticEvent<T>>, StaticEvent<T>>, CgkaError> {
        Ok(self
            .events_for_agent(agent)?
            .into_iter()
            .map(|(k, v)| (k.into(), v.into()))
            .collect())
    }

    pub fn cgka_ops_reachable_by_agent(
        &self,
        agent: &Agent<S, T, L>,
    ) -> Result<Vec<Rc<Signed<CgkaOperation>>>, CgkaError> {
        let mut ops = vec![];
        for (_doc_id, ability) in self.docs_reachable_by_agent(agent) {
            for epoch in ability.doc.borrow().cgka_ops()?.iter() {
                ops.extend(epoch.iter().cloned());
            }
        }
        Ok(ops)
    }

    pub fn cgka_ops_for_doc(
        &self,
        doc: &DocumentId,
    ) -> Result<Option<Vec<Rc<Signed<CgkaOperation>>>>, CgkaError> {
        let Some(doc) = self.docs.get(doc) else {
            return Ok(None);
        };
        let mut ops = Vec::new();
        for epoch in doc.borrow().cgka_ops()?.iter() {
            ops.extend(epoch.iter().cloned());
        }
        Ok(Some(ops))
    }

    pub fn membership_ops_for_agent(
        &self,
        agent: &Agent<S, T, L>,
    ) -> HashMap<Digest<MembershipOperation<S, T, L>>, MembershipOperation<S, T, L>> {
        let mut ops = HashMap::new();
        let mut visited_hashes = HashSet::new();

        #[allow(clippy::type_complexity)]
        let mut heads: Vec<(
            Digest<MembershipOperation<S, T, L>>,
            MembershipOperation<S, T, L>,
        )> = vec![];

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
                MembershipOperation::Delegation(dlg) => {
                    if let Some(proof) = &dlg.payload.proof {
                        heads.push((Digest::hash(proof.as_ref()).into(), proof.dupe().into()));
                    }

                    for rev in dlg.payload.after_revocations.iter() {
                        heads.push((Digest::hash(rev.as_ref()).into(), rev.dupe().into()));
                    }
                }
                MembershipOperation::Revocation(rev) => {
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

    pub fn reachable_prekey_ops_for_agent(
        &self,
        agent: &Agent<S, T, L>,
    ) -> HashMap<Identifier, Vec<Rc<KeyOp>>> {
        fn add_many_keys(
            map: &mut HashMap<Identifier, Vec<Rc<KeyOp>>>,
            agent_id: Identifier,
            key_ops: HashSet<Rc<KeyOp>>,
        ) {
            let mut heads: Vec<Rc<KeyOp>> = vec![];
            let mut rotate_key_ops: HashMap<ShareKey, HashSet<Rc<KeyOp>>> = HashMap::new();

            for key_op in key_ops.iter() {
                match key_op.as_ref() {
                    KeyOp::Add(_add) => {
                        heads.push(key_op.dupe());
                    }
                    KeyOp::Rotate(rot) => {
                        rotate_key_ops
                            .entry(rot.payload.old)
                            .and_modify(|set| {
                                set.insert(key_op.dupe());
                            })
                            .or_insert(HashSet::from_iter([key_op.dupe()]));
                    }
                }
            }

            let mut topsorted = vec![];

            while let Some(head) = heads.pop() {
                if let Some(ops) = rotate_key_ops.get(head.new_key()) {
                    for op in ops.iter() {
                        heads.push(op.dupe());
                    }
                }

                topsorted.push(head.dupe());
            }

            map.insert(agent_id, topsorted);
        }

        let mut map = HashMap::new();

        add_many_keys(
            &mut map,
            self.active.borrow().id().into(),
            self.active
                .dupe()
                .borrow()
                .individual
                .prekey_ops()
                .values()
                .cloned()
                .collect(),
        );

        for (mem, _) in self.membered_reachable_by_agent(agent).values() {
            match mem {
                Membered::Group(group) => {
                    add_many_keys(
                        &mut map,
                        group.borrow().id(),
                        Agent::from(group.dupe()).key_ops().into_iter().collect(),
                    );

                    for (agent_id, (agent, _acess)) in group.borrow().transitive_members().iter() {
                        add_many_keys(&mut map, *agent_id, agent.key_ops().into_iter().collect());
                    }
                }
                Membered::Document(doc) => {
                    add_many_keys(
                        &mut map,
                        doc.borrow().id(),
                        Agent::from(doc.dupe()).key_ops().into_iter().collect(),
                    );

                    for (agent_id, (agent, _acess)) in doc.borrow().transitive_members().iter() {
                        add_many_keys(&mut map, *agent_id, agent.key_ops().into_iter().collect());
                    }
                }
            }
        }

        map
    }

    pub fn get_individual(&self, id: IndividualId) -> Option<&Rc<RefCell<Individual>>> {
        self.individuals.get(&id)
    }

    pub fn get_group(&self, id: GroupId) -> Option<&Rc<RefCell<Group<S, T, L>>>> {
        self.groups.get(&id)
    }

    pub fn get_document(&self, id: DocumentId) -> Option<&Rc<RefCell<Document<S, T, L>>>> {
        self.docs.get(&id)
    }

    pub fn get_peer(&self, id: Identifier) -> Option<Peer<S, T, L>> {
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

    pub fn get_agent(&self, id: Identifier) -> Option<Agent<S, T, L>> {
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

    pub fn receive_prekey_op(&mut self, key_op: &KeyOp) -> Result<(), ReceivePrekeyOpError> {
        let id = Identifier(*key_op.issuer());
        let agent = self.get_agent(id).unwrap_or_else(|| {
            let indie = Rc::new(RefCell::new(Individual::new(key_op.clone())));
            self.register_individual(indie.dupe());
            indie.into()
        });

        match agent {
            Agent::Active(active) => {
                active
                    .borrow_mut()
                    .individual
                    .receive_prekey_op(key_op.clone())?;
            }
            Agent::Individual(indie) => {
                indie.borrow_mut().receive_prekey_op(key_op.clone())?;
            }
            Agent::Group(group) => {
                if let IdOrIndividual::Individual(indie) = &mut group.borrow_mut().id_or_indie {
                    indie.receive_prekey_op(key_op.clone())?;
                } else {
                    let individual = Individual::new(key_op.dupe());
                    group.borrow_mut().id_or_indie = IdOrIndividual::Individual(individual);
                }
            }
            Agent::Document(doc) => {
                if let IdOrIndividual::Individual(indie) = &mut doc.borrow_mut().group.id_or_indie {
                    indie.receive_prekey_op(key_op.clone())?;
                } else {
                    let individual = Individual::new(key_op.dupe());
                    doc.borrow_mut().group.id_or_indie = IdOrIndividual::Individual(individual);
                }
            }
        }

        Ok(())
    }

    pub fn receive_delegation(
        &mut self,
        static_dlg: &Signed<StaticDelegation<T>>,
    ) -> Result<(), ReceieveStaticDelegationError<S, T, L>> {
        if self
            .delegations
            .contains_key(&Digest::hash(static_dlg).into())
        {
            return Ok(());
        }

        // NOTE: this is the only place this gets parsed and this verification ONLY happens here
        static_dlg.try_verify()?;

        let proof: Option<Rc<Signed<Delegation<S, T, L>>>> = static_dlg
            .payload()
            .proof
            .map(|proof_hash| {
                let hash = proof_hash.into();
                self.delegations.get(&hash).ok_or(MissingDependency(hash))
            })
            .transpose()?;

        let delegate_id = static_dlg.payload().delegate;
        let delegate: Agent<S, T, L> = self
            .get_agent(delegate_id)
            .ok_or(ReceieveStaticDelegationError::UnknownAgent(delegate_id))?;

        let after_revocations = static_dlg.payload().after_revocations.iter().try_fold(
            vec![],
            |mut acc, static_rev_hash| {
                let rev_hash = static_rev_hash.into();
                let revs = self.revocations.borrow();
                let resolved_rev = revs.get(&rev_hash).ok_or(MissingDependency(rev_hash))?;
                acc.push(resolved_rev.dupe());
                Ok::<_, ReceieveStaticDelegationError<S, T, L>>(acc)
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
            let group = Group::new(
                GroupId(subject_id),
                Rc::new(delegation),
                self.delegations.dupe(),
                self.revocations.dupe(),
                self.event_listener.clone(),
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
    ) -> Result<(), ReceieveStaticDelegationError<S, T, L>> {
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
        let revoke: Rc<Signed<Delegation<S, T, L>>> = self
            .delegations
            .get(&revoke_hash)
            .ok_or(MissingDependency(revoke_hash))?;

        let proof: Option<Rc<Signed<Delegation<S, T, L>>>> = static_rev
            .payload()
            .proof
            .map(|proof_hash| {
                let hash = proof_hash.into();
                self.delegations.get(&hash).ok_or(MissingDependency(hash))
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
            let mut group = Group::new(
                GroupId(static_rev.issuer.into()),
                revocation.payload.revoke.dupe(),
                self.delegations.dupe(),
                self.revocations.dupe(),
                self.event_listener.clone(),
            );

            group.receive_revocation(Rc::new(revocation))?;
            self.groups
                .insert(group.group_id(), Rc::new(RefCell::new(group)));
        }

        Ok(())
    }

    pub fn receive_static_event(
        &mut self,
        static_event: StaticEvent<T>,
    ) -> Result<(), ReceiveStaticEventError<S, T, L>> {
        match static_event {
            StaticEvent::PrekeysExpanded(add_op) => {
                self.receive_prekey_op(&Rc::new(add_op).into())?
            }
            StaticEvent::PrekeyRotated(rot_op) => {
                self.receive_prekey_op(&Rc::new(rot_op).into())?
            }
            StaticEvent::CgkaOperation(cgka_op) => self.receive_cgka_op(cgka_op)?,
            StaticEvent::Delegated(dlg) => self.receive_delegation(&dlg)?,
            StaticEvent::Revoked(rev) => self.receive_revocation(&rev)?,
        }

        Ok(())
    }

    pub fn receive_membership_op(
        &mut self,
        static_op: &StaticMembershipOperation<T>,
    ) -> Result<(), ReceieveStaticDelegationError<S, T, L>> {
        match static_op {
            StaticMembershipOperation::Delegation(d) => self.receive_delegation(d),
            StaticMembershipOperation::Revocation(r) => self.receive_revocation(r),
        }
    }

    pub fn receive_cgka_op(
        &mut self,
        signed_op: Signed<CgkaOperation>,
    ) -> Result<(), ReceiveCgkaOpError> {
        signed_op.try_verify()?;

        let doc_id = signed_op.payload.doc_id();
        let mut doc = self
            .docs
            .get(doc_id)
            .ok_or(ReceiveCgkaOpError::UnknownDocument(*doc_id))?
            .borrow_mut();

        if let CgkaOperation::Add { added_id, pk, .. } = signed_op.payload {
            let active = self.active.borrow();
            if active.id() == added_id {
                let sk = active
                    .prekey_pairs
                    .get(&pk)
                    .ok_or(ReceiveCgkaOpError::UnknownInvitePrekey(pk))?;
                doc.merge_cgka_invite_op(Rc::new(signed_op), sk)?;
                return Ok(());
            }
        }
        doc.merge_cgka_op(Rc::new(signed_op))?;
        Ok(())
    }

    pub fn promote_individual_to_group(
        &mut self,
        individual: Rc<RefCell<Individual>>,
        head: Rc<Signed<Delegation<S, T, L>>>,
    ) -> Rc<RefCell<Group<S, T, L>>> {
        let group = Rc::new(RefCell::new(Group::from_individual(
            individual.borrow().clone(),
            head,
            self.delegations.dupe(),
            self.revocations.dupe(),
            self.event_listener.clone(),
        )));

        let agent = Agent::from(group.dupe());

        for (digest, dlg) in self.delegations.0.borrow().iter() {
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

        for (digest, rev) in self.revocations.0.borrow().iter() {
            if rev.payload.subject_id() == group.borrow().id() {
                self.revocations.borrow_mut().0.insert(
                    *digest,
                    Rc::new(Signed {
                        issuer: rev.issuer,
                        signature: rev.signature,
                        payload: Revocation {
                            revoke: self
                                .delegations
                                .get(&Digest::hash(&rev.payload.revoke))
                                .expect("revoked delegation to be available")
                                .dupe(),
                            proof: rev.payload.proof.dupe().map(|proof| {
                                self.delegations
                                    .get(&Digest::hash(&proof))
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
            active: self.active.borrow().into_archive(),
            topsorted_ops: MembershipOperation::<S, T, L>::topsort(
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
                .map(|(k, rc_v)| (*k, rc_v.borrow().into_archive()))
                .collect(),
            docs: self
                .docs
                .iter()
                .map(|(k, rc_v)| (*k, rc_v.borrow().into_archive()))
                .collect(),
        }
    }

    pub fn try_from_archive(
        archive: &Archive<T>,
        signer: S,
        listener: L,
        csprng: R,
    ) -> Result<Self, TryFromArchiveError<S, T, L>> {
        let active = Rc::new(RefCell::new(Active::from_archive(
            &archive.active,
            signer,
            listener.clone(),
        )));

        let delegations: DelegationStore<S, T, L> = DelegationStore::new();
        let revocations: RevocationStore<S, T, L> = RevocationStore::new();

        let mut individuals = HashMap::new();
        for (k, v) in archive.individuals.iter() {
            individuals.insert(*k, Rc::new(RefCell::new(v.clone())));
        }

        let mut groups = HashMap::new();
        for (group_id, group_archive) in archive.groups.iter() {
            groups.insert(
                *group_id,
                Rc::new(RefCell::new(Group::<S, T, L>::dummy_from_archive(
                    group_archive.clone(),
                    delegations.dupe(),
                    revocations.dupe(),
                    listener.clone(),
                ))),
            );
        }

        let mut docs = HashMap::new();
        for (doc_id, doc_archive) in archive.docs.iter() {
            docs.insert(
                *doc_id,
                Rc::new(RefCell::new(Document::<S, T, L>::dummy_from_archive(
                    doc_archive.clone(),
                    delegations.dupe(),
                    revocations.dupe(),
                    listener.clone(),
                )?)),
            );
        }

        for (digest, static_op) in archive.topsorted_ops.iter() {
            match static_op {
                StaticMembershipOperation::Delegation(sd) => {
                    let proof: Option<Rc<Signed<Delegation<S, T, L>>>> = sd
                        .payload
                        .proof
                        .map(|proof_digest| {
                            delegations
                                .get(&proof_digest.into())
                                .ok_or(TryFromArchiveError::MissingDelegation(proof_digest.into()))
                        })
                        .transpose()?;

                    let mut after_revocations = vec![];
                    for rev_digest in sd.payload.after_revocations.iter() {
                        let r: Rc<Signed<Revocation<S, T, L>>> = revocations
                            .borrow()
                            .get(&rev_digest.into())
                            .ok_or(TryFromArchiveError::MissingRevocation(rev_digest.into()))?
                            .dupe();

                        after_revocations.push(r);
                    }

                    let id = sd.payload.delegate;
                    let delegate: Agent<S, T, L> = if id == archive.active.individual.id().into() {
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
                StaticMembershipOperation::Revocation(sr) => {
                    revocations.borrow_mut().0.insert(
                        (*digest).into(),
                        Rc::new(Signed {
                            issuer: sr.issuer,
                            signature: sr.signature,
                            payload: Revocation {
                                revoke: delegations.get(&sr.payload.revoke.into()).ok_or(
                                    TryFromArchiveError::MissingDelegation(
                                        sr.payload.revoke.into(),
                                    ),
                                )?,
                                proof: sr
                                    .payload
                                    .proof
                                    .map(|proof_digest| {
                                        delegations.get(&proof_digest.into()).ok_or(
                                            TryFromArchiveError::MissingDelegation(
                                                proof_digest.into(),
                                            ),
                                        )
                                    })
                                    .transpose()?,
                                after_content: sr.payload.after_content.clone(),
                            },
                        }),
                    );
                }
            };
        }

        #[allow(clippy::type_complexity)]
        fn reify_ops<Z: AsyncSigner, U: ContentRef, M: MembershipListener<Z, U>>(
            group: &mut Group<Z, U, M>,
            dlg_store: DelegationStore<Z, U, M>,
            rev_store: RevocationStore<Z, U, M>,
            dlg_head_hashes: &HashSet<Digest<Signed<StaticDelegation<U>>>>,
            rev_head_hashes: &HashSet<Digest<Signed<StaticRevocation<U>>>>,
            members: HashMap<Identifier, NonEmpty<Digest<Signed<Delegation<Z, U, M>>>>>,
        ) -> Result<(), TryFromArchiveError<Z, U, M>> {
            let read_dlgs = dlg_store.0.borrow();
            let read_revs = rev_store.0.borrow();

            for dlg_hash in dlg_head_hashes.iter() {
                let actual_dlg: Rc<Signed<Delegation<Z, U, M>>> = read_dlgs
                    .get(&dlg_hash.into())
                    .ok_or(TryFromArchiveError::MissingDelegation(dlg_hash.into()))?
                    .dupe();

                group.state.delegation_heads.insert(actual_dlg);
            }

            for rev_hash in rev_head_hashes.iter() {
                let actual_rev = read_revs
                    .get(&rev_hash.into())
                    .ok_or(TryFromArchiveError::MissingRevocation(rev_hash.into()))?;
                group.state.revocation_heads.insert(actual_rev.dupe());
            }

            for (id, proof_hashes) in members.iter() {
                let mut proofs = vec![];
                for proof_hash in proof_hashes.iter() {
                    let actual_dlg = read_dlgs
                        .get(proof_hash)
                        .ok_or(TryFromArchiveError::MissingDelegation(*proof_hash))?;
                    proofs.push(actual_dlg.dupe());
                }
                group.members.insert(
                    *id,
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
                    .map(|(k, v)| (*k, v.clone().map(|x| x.into())))
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
                    .map(|(k, v)| (*k, v.clone().map(|x| x.into())))
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
            event_listener: listener,
        })
    }

    pub fn event_listener(&self) -> &L {
        &self.event_listener
    }

    #[cfg(any(test, feature = "test_utils"))]
    pub fn ingest_unsorted_static_events(
        &mut self,
        events: Vec<StaticEvent<T>>,
    ) -> Result<(), ReceiveStaticEventError<S, T, L>> {
        let mut epoch = events;

        loop {
            let mut next_epoch = vec![];
            let mut err = None;
            let epoch_len = epoch.len();

            for event in epoch {
                if let Err(e) = self.receive_static_event(event.clone()) {
                    err = Some(e);
                    next_epoch.push(event);
                }
            }

            if next_epoch.is_empty() {
                return Ok(());
            }

            if next_epoch.len() == epoch_len {
                // Stuck on a fixed point
                return Err(err.unwrap());
            }

            epoch = next_epoch
        }
    }

    #[cfg(any(test, feature = "test_utils"))]
    pub fn ingest_event_table(
        &mut self,
        events: HashMap<Digest<Event<S, T, L>>, Event<S, T, L>>,
    ) -> Result<(), ReceiveStaticEventError<S, T, L>> {
        self.ingest_unsorted_static_events(
            events.values().cloned().map(Into::into).collect::<Vec<_>>(),
        )
    }
}

impl<
        S: AsyncSigner + Clone,
        T: ContentRef + Clone,
        L: MembershipListener<S, T> + CgkaListener,
        R: rand::CryptoRng + rand::RngCore + Clone,
    > Fork for Keyhive<S, T, L, R>
{
    type Forked = Keyhive<S, T, Log<S, T>, R>;

    fn fork(&self) -> Self::Forked {
        Keyhive::try_from_archive(
            &self.into_archive(),
            self.active.borrow().signer.clone(),
            Log::new(),
            self.csprng.clone(),
        )
        .expect("local round trip to work")
    }
}

impl<
        S: AsyncSigner + Clone,
        T: ContentRef + Clone,
        L: MembershipListener<S, T> + CgkaListener,
        R: rand::CryptoRng + rand::RngCore + Clone,
    > Merge for Keyhive<S, T, L, R>
{
    fn merge(&mut self, mut fork: Self::Forked) {
        self.active
            .borrow_mut()
            .merge(Rc::unwrap_or_clone(fork.active).into_inner());

        for (id, forked_indie) in fork.individuals.drain() {
            if let Some(og_indie) = self.individuals.remove(&id) {
                og_indie
                    .borrow_mut()
                    .merge(Rc::unwrap_or_clone(forked_indie).into_inner());
            } else {
                self.individuals.insert(id, forked_indie);
            }
        }

        for event in fork.event_listener.0.borrow().iter() {
            match event {
                Event::PrekeysExpanded(_add_op) => {
                    continue; // NOTE: handled above
                }
                Event::PrekeyRotated(_rot_op) => {
                    continue; // NOTE: handled above
                }
                _ => {}
            }

            self.receive_static_event(event.clone().into())
                .expect("prechecked events to work");
        }

        // FIXME ^^^^^^^^^^^ skip checks to speed up; this is all trusted data
    }
}

impl<
        S: AsyncSigner,
        T: ContentRef,
        L: MembershipListener<S, T> + CgkaListener,
        R: rand::CryptoRng + rand::RngCore,
    > Verifiable for Keyhive<S, T, L, R>
{
    fn verifying_key(&self) -> ed25519_dalek::VerifyingKey {
        self.active.borrow().verifying_key()
    }
}

impl<
        S: AsyncSigner,
        T: ContentRef,
        L: MembershipListener<S, T> + CgkaListener,
        R: rand::CryptoRng + rand::RngCore,
    > From<&Keyhive<S, T, L, R>> for Agent<S, T, L>
{
    fn from(context: &Keyhive<S, T, L, R>) -> Self {
        context.active.dupe().into()
    }
}

#[derive(Error)]
pub enum ReceiveStaticEventError<S: AsyncSigner, T: ContentRef, L: MembershipListener<S, T>> {
    #[error(transparent)]
    ReceivePrekeyOpError(#[from] ReceivePrekeyOpError),

    #[error(transparent)]
    ReceiveCgkaOpError(#[from] ReceiveCgkaOpError),

    #[error(transparent)]
    ReceieveStaticMembershipError(#[from] ReceieveStaticDelegationError<S, T, L>),
}

impl<S, T, L> ReceiveStaticEventError<S, T, L>
where
    S: AsyncSigner,
    T: ContentRef,
    L: MembershipListener<S, T>,
{
    pub fn is_missing_dependency(&self) -> bool {
        match self {
            Self::ReceivePrekeyOpError(_) => false,
            Self::ReceiveCgkaOpError(e) => e.is_missing_dependency(),
            Self::ReceieveStaticMembershipError(e) => e.is_missing_dependency(),
        }
    }
}

impl<S: AsyncSigner, T: ContentRef, L: MembershipListener<S, T>> std::fmt::Debug
    for ReceiveStaticEventError<S, T, L>
{
    fn fmt(&self, _f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // FIXME
        Ok(())
        // match self {
        //     Self::ReceivePrekeyOpError(e) => write!(f, "ReceivePrekeyOpError({:?})", e),
        //     Self::ReceiveCgkaOpError(e) => write!(f, "ReceiveCgkaOpError({:?})", e),
        //     Self::ReceieveStaticMembershipError(e) => {
        //         write!(f, "ReceieveStaticMembershipError({:?})", e)
        //     }
        // }
    }
}

#[derive(Debug, Error)]
pub enum ReceieveStaticDelegationError<
    S: AsyncSigner,
    T: ContentRef = [u8; 32],
    L: MembershipListener<S, T> = NoListener,
> {
    #[error(transparent)]
    VerificationError(#[from] VerificationError),

    #[error("Missing proof: {0}")]
    MissingProof(#[from] MissingDependency<Digest<Signed<Delegation<S, T, L>>>>),

    #[error("Missing revocation dependency: {0}")]
    MissingRevocationDependency(#[from] MissingDependency<Digest<Signed<Revocation<S, T, L>>>>),

    #[error("Cgka init error: {0}")]
    CgkaInitError(#[from] CgkaError),

    #[error(transparent)]
    GroupReceiveError(#[from] AddError),

    #[error("Missing agent: {0}")]
    UnknownAgent(Identifier),
}

impl<S, T, L> ReceieveStaticDelegationError<S, T, L>
where
    S: AsyncSigner,
    T: ContentRef,
    L: MembershipListener<S, T>,
{
    pub fn is_missing_dependency(&self) -> bool {
        match self {
            Self::MissingProof(_) => true,
            Self::MissingRevocationDependency(_) => true,
            Self::CgkaInitError(e) => e.is_missing_dependency(),
            Self::GroupReceiveError(_) => false,
            Self::UnknownAgent(_) => true,
            Self::VerificationError(_) => false,
        }
    }
}

#[derive(Clone, PartialEq, Eq, Error)]
#[derive_where(Debug)]
pub enum TryFromArchiveError<S: AsyncSigner, T: ContentRef, L: MembershipListener<S, T>> {
    #[error("Missing delegation: {0}")]
    MissingDelegation(#[from] Digest<Signed<Delegation<S, T, L>>>),

    #[error("Missing revocation: {0}")]
    MissingRevocation(#[from] Digest<Signed<Revocation<S, T, L>>>),

    #[error("Missing individual: {0}")]
    MissingIndividual(Box<IndividualId>),

    #[error("Missing group: {0}")]
    MissingGroup(Box<GroupId>),

    #[error("Missing document: {0}")]
    MissingDocument(Box<DocumentId>),

    #[error("Missing agent: {0}")]
    MissingAgent(Box<Identifier>),
}

#[derive(Debug, Error)]
pub enum ReceiveCgkaOpError {
    #[error(transparent)]
    CgkaError(#[from] CgkaError),

    #[error(transparent)]
    VerificationError(#[from] VerificationError),

    #[error("Unknown document recipient for recieved CGKA op: {0}")]
    UnknownDocument(DocumentId),

    #[error("Unknown invite prekey for received CGKA add op: {0}")]
    UnknownInvitePrekey(ShareKey),
}

impl ReceiveCgkaOpError {
    pub fn is_missing_dependency(&self) -> bool {
        match self {
            Self::CgkaError(e) => e.is_missing_dependency(),
            Self::VerificationError(_) => false,
            Self::UnknownDocument(_) => false,
            Self::UnknownInvitePrekey(_) => false,
        }
    }
}

impl<S: AsyncSigner, T: ContentRef, L: MembershipListener<S, T>> From<MissingIndividualError>
    for TryFromArchiveError<S, T, L>
{
    fn from(e: MissingIndividualError) -> Self {
        TryFromArchiveError::MissingIndividual(e.0)
    }
}

#[derive(Debug, Error)]
pub enum EncryptContentError {
    #[error(transparent)]
    EncryptError(#[from] EncryptError),

    #[error("Error signing Cgka op: {0}")]
    SignCgkaOpError(SigningError),
}

#[derive(Debug, Error)]
pub enum ReceiveEventError<
    S: AsyncSigner,
    T: ContentRef = [u8; 32],
    L: MembershipListener<S, T> = NoListener,
> {
    #[error(transparent)]
    ReceieveStaticDelegationError(#[from] ReceieveStaticDelegationError<S, T, L>),

    #[error(transparent)]
    ReceivePrekeyOpError(#[from] ReceivePrekeyOpError),

    #[error(transparent)]
    ReceiveCgkaOpError(#[from] ReceiveCgkaOpError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        access::Access,
        crypto::signer::memory::MemorySigner,
        principal::public::Public,
        transact::{fork::ForkAsync, merge::MergeAsync, transact_nonblocking},
    };
    use nonempty::nonempty;
    use pretty_assertions::assert_eq;
    use std::sync::{Arc, Mutex};

    async fn make_keyhive() -> Keyhive<MemorySigner> {
        let sk = MemorySigner::generate(&mut rand::thread_rng());
        Keyhive::generate(sk, NoListener, rand::thread_rng())
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn test_archival_round_trip() {
        let mut csprng = rand::thread_rng();

        let sk = MemorySigner::generate(&mut csprng);
        let mut hive = Keyhive::generate(sk.clone(), NoListener, rand::thread_rng())
            .await
            .unwrap();

        let indie_sk = MemorySigner::generate(&mut csprng);
        let indie = Rc::new(RefCell::new(
            Individual::generate(&indie_sk, &mut csprng).await.unwrap(),
        ));

        hive.register_individual(indie.dupe());
        hive.generate_group(vec![indie.dupe().into()])
            .await
            .unwrap();
        hive.generate_doc(
            vec![indie.into()],
            nonempty!["ref1".to_string(), "ref2".to_string()],
        )
        .await
        .unwrap();

        assert!(hive.active.borrow().prekey_pairs.len() > 0);
        assert_eq!(hive.individuals.len(), 2);
        assert_eq!(hive.groups.len(), 1);
        assert_eq!(hive.docs.len(), 1);
        assert_eq!(hive.delegations.borrow().len(), 4);
        assert_eq!(hive.revocations.borrow().len(), 0);

        let archive = hive.into_archive();

        assert_eq!(hive.id(), archive.id());
        assert_eq!(archive.individuals.len(), 2);
        assert_eq!(archive.groups.len(), 1);
        assert_eq!(archive.docs.len(), 1);
        assert_eq!(archive.topsorted_ops.len(), 4);

        let hive_from_archive =
            Keyhive::try_from_archive(&archive, sk, NoListener, rand::thread_rng()).unwrap();

        assert_eq!(hive, hive_from_archive);
    }

    #[tokio::test]
    async fn test_receive_delegations_associately() {
        let mut hive1 = make_keyhive().await;
        let mut hive2 = make_keyhive().await;

        let hive2_on_hive1 = Rc::new(RefCell::new(hive2.active.borrow().individual.clone()));
        hive1.register_individual(hive2_on_hive1.dupe());
        let hive1_on_hive2 = Rc::new(RefCell::new(hive1.active.borrow().individual.clone()));
        hive2.register_individual(hive1_on_hive2.dupe());
        let group1_on_hive1 = hive1
            .generate_group(vec![hive2_on_hive1.into()])
            .await
            .unwrap();

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
        assert_eq!(hive2.individuals.len(), 2);
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

    #[tokio::test]
    async fn test_transitive_ops_for_agent() {
        let mut left = make_keyhive().await;
        let mut middle = make_keyhive().await;
        let mut right = make_keyhive().await;

        // 2 delegations (you & public)
        let left_doc = left
            .generate_doc(
                vec![Rc::new(RefCell::new(Public.individual())).into()],
                nonempty![[0u8; 32]],
            )
            .await
            .unwrap();
        // 1 delegation (you)
        let left_group = left.generate_group(vec![]).await.unwrap();

        assert_eq!(left.delegations.borrow().len(), 3);
        assert_eq!(left.revocations.borrow().len(), 0);

        assert_eq!(left.individuals.len(), 1);
        assert!(left.individuals.get(&IndividualId(Public.id())).is_some());

        assert_eq!(left.groups.len(), 1);
        assert_eq!(left.docs.len(), 1);

        assert!(left.docs.get(&left_doc.borrow().doc_id()).is_some());
        assert!(left.groups.get(&left_group.borrow().group_id()).is_some());

        // NOTE: *NOT* the group
        let left_membered = left.membered_reachable_by_agent(&Public.individual().into());

        assert_eq!(left_membered.len(), 1);
        assert!(left_membered
            .get(&left_doc.borrow().doc_id().into())
            .is_some());
        assert!(left_membered
            .get(&left_group.borrow().group_id().into())
            .is_none()); // NOTE *not* included because Public is not a member

        let left_to_mid_ops = left.events_for_agent(&Public.individual().into()).unwrap();
        assert_eq!(left_to_mid_ops.len(), 14);

        middle.ingest_event_table(left_to_mid_ops).unwrap();

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

        let mid_to_right_ops = middle
            .events_for_agent(&Public.individual().into())
            .unwrap();
        assert_eq!(mid_to_right_ops.len(), 21);

        right.ingest_event_table(mid_to_right_ops).unwrap();

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

        assert_eq!(right.individuals.len(), 3);
        assert_eq!(right.groups.len(), 0);
        assert_eq!(right.docs.len(), 1);

        assert_eq!(
            middle
                .events_for_agent(&Public.individual().into())
                .unwrap()
                .iter()
                .collect::<Vec<_>>()
                .sort_by_key(|(k, _v)| **k),
            right
                .events_for_agent(&Public.individual().into())
                .unwrap()
                .iter()
                .collect::<Vec<_>>()
                .sort_by_key(|(k, _v)| **k),
        );

        right
            .generate_group(vec![left_doc.dupe().into()])
            .await
            .unwrap();

        // Check transitivity
        let transitive_right_to_mid_ops =
            right.events_for_agent(&Public.individual().into()).unwrap();
        assert_eq!(transitive_right_to_mid_ops.len(), 23);

        middle
            .ingest_event_table(transitive_right_to_mid_ops)
            .unwrap();

        assert_eq!(middle.individuals.len(), 3); // NOTE now includes Right
        assert_eq!(middle.groups.len(), 1);
        assert_eq!(middle.docs.len(), 1);
        assert_eq!(middle.delegations.borrow().len(), 4);
    }

    #[tokio::test]
    async fn test_add_member() {
        let mut keyhive = make_keyhive().await;
        let doc = keyhive
            .generate_doc(
                vec![Rc::new(RefCell::new(Public.individual())).into()],
                nonempty![[0u8; 32]],
            )
            .await
            .unwrap();
        let member = Public.individual().into();
        let dlg = keyhive
            .add_member(member, &mut doc.clone().into(), Access::Read, &[])
            .await
            .unwrap();

        assert_eq!(dlg.delegation.subject_id(), doc.borrow().doc_id().into());
    }

    #[tokio::test]
    async fn receiving_an_event_with_added_or_rotated_prekeys_works() {
        let mut alice = make_keyhive().await;
        let mut bob = make_keyhive().await;

        let doc = alice
            .generate_doc(vec![], nonempty![[0u8; 32]])
            .await
            .unwrap();

        // Create a new prekey op by expanding prekeys on bob
        let add_bob_op = bob.expand_prekeys().await.unwrap();

        // Now add bob to alices document using the new op
        let add_op = KeyOp::Add(add_bob_op);
        let bob_on_alice = Rc::new(RefCell::new(Individual::new(add_op.dupe())));
        assert!(alice.register_individual(bob_on_alice.clone()));
        alice
            .add_member(
                bob_on_alice.dupe().into(),
                &mut doc.dupe().into(),
                Access::Read,
                &[],
            )
            .await
            .unwrap();

        // Now receive alices events
        let events = alice.events_for_agent(&bob_on_alice.into()).unwrap();

        // ensure that we are able to process the add op
        bob.ingest_event_table(events).unwrap();

        // Now create a new prekey op by rotating on bob
        let rotate_op = bob.rotate_prekey(*add_op.new_key()).await.unwrap();

        // Create a new document (on a new keyhive) and share it with bob using the rotated key
        let mut charlie = make_keyhive().await;
        let doc2 = charlie
            .generate_doc(vec![], nonempty![[1u8; 32]])
            .await
            .unwrap();
        let bob_on_charlie = Rc::new(RefCell::new(Individual::new(KeyOp::Rotate(rotate_op))));
        assert!(charlie.register_individual(bob_on_charlie.clone()));
        charlie
            .add_member(
                bob_on_charlie.into(),
                &mut doc2.clone().into(),
                Access::Read,
                &[],
            )
            .await
            .unwrap();

        let events = charlie
            .events_for_agent(&bob.active().clone().into())
            .unwrap();
        bob.ingest_event_table(events).unwrap();
    }

    #[tokio::test]
    async fn test_successful_transaction() {
        let sk = MemorySigner::generate(&mut rand::thread_rng());
        let hive = Keyhive::<_, [u8; 32], _, _>::generate(sk, NoListener, rand::rngs::OsRng)
            .await
            .unwrap();

        let trunk = Rc::new(RefCell::new(hive));

        let alice: Peer<MemorySigner, [u8; 32], NoListener> = Rc::new(RefCell::new(
            Individual::generate(
                &MemorySigner::generate(&mut rand::rngs::OsRng),
                &mut rand::rngs::OsRng,
            )
            .await
            .unwrap(),
        ))
        .into();

        trunk
            .borrow_mut()
            .generate_doc(vec![alice.dupe()], nonempty![[0u8; 32]])
            .await
            .unwrap();

        trunk
            .borrow_mut()
            .generate_group(vec![alice.dupe()])
            .await
            .unwrap();

        assert_eq!(trunk.borrow().delegations.borrow().len(), 4);

        let tx = transact_nonblocking(
            &trunk,
            |mut fork: Keyhive<_, _, Log<MemorySigner, _>, rand::rngs::OsRng>| async move {
                let bob: Peer<MemorySigner, [u8; 32], Log<MemorySigner>> = Rc::new(RefCell::new(
                    Individual::generate(
                        &MemorySigner::generate(&mut rand::rngs::OsRng),
                        &mut rand::rngs::OsRng,
                    )
                    .await
                    .unwrap(),
                ))
                .into();

                fork.generate_group(vec![bob.dupe()]).await.unwrap();
                fork.generate_group(vec![bob.dupe()]).await.unwrap();
                fork.generate_group(vec![bob.dupe()]).await.unwrap();

                fork.generate_doc(vec![bob], nonempty![[1u8; 32]])
                    .await
                    .unwrap();

                Ok::<_, String>(fork)
            },
        );

        trunk
            .borrow_mut()
            .generate_doc(vec![alice.dupe()], nonempty![[2u8; 32]])
            .await
            .unwrap();

        let result = tx.await;
        assert!(result.is_ok());

        trunk
            .borrow_mut()
            .generate_doc(vec![alice.dupe()], nonempty![[3u8; 32]])
            .await
            .unwrap();

        assert_eq!(trunk.borrow().delegations.borrow().len(), 8);

        assert_eq!(trunk.borrow().groups.len(), 4);
        assert_eq!(trunk.borrow().docs.len(), 4);
    }

    // #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    // async fn test_failure_transaction_is_noop() {}
}
