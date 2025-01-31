//! The primary API for the library.

use crate::{
    ability::Ability,
    access::Access,
    archive::Archive,
    cgka::{error::CgkaError, operation::CgkaOperation},
    content::reference::ContentRef,
    crypto::{
        digest::Digest,
        encrypted::EncryptedContent,
        share_key::ShareKey,
        signed::{Signed, SigningError, VerificationError},
        verifiable::Verifiable,
    },
    error::missing_dependency::MissingDependency,
    event::{Event, StaticEvent},
    listener::{cgka::CgkaListener, membership::MembershipListener, no_listener::NoListener},
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
            Group, RevokeMemberError,
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
pub struct Keyhive<
    T: ContentRef = [u8; 32],
    L: MembershipListener<T> + CgkaListener = NoListener,
    R: rand::CryptoRng + rand::RngCore = rand::rngs::ThreadRng,
> {
    /// The [`Active`] user agent.
    active: Rc<RefCell<Active<L>>>,

    /// The [`Individual`]s that are known to this agent.
    individuals: HashMap<IndividualId, Rc<RefCell<Individual>>>,

    /// The [`Group`]s that are known to this agent.
    groups: HashMap<GroupId, Rc<RefCell<Group<T, L>>>>,

    /// The [`Document`]s that are known to this agent.
    docs: HashMap<DocumentId, Rc<RefCell<Document<T, L>>>>,

    /// All applied [`Delegation`]s
    delegations: DelegationStore<T, L>,

    /// All applied [`Revocation`]s
    revocations: RevocationStore<T, L>,

    /// Obsever for [`Event`]s. Intended for running live updates.
    event_listener: L,

    /// Cryptographically secure (pseudo)random number generator.
    #[derivative(PartialEq = "ignore")]
    csprng: R,
}

impl<
        T: ContentRef,
        L: MembershipListener<T> + CgkaListener,
        R: rand::CryptoRng + rand::RngCore,
    > Keyhive<T, L, R>
{
    pub fn id(&self) -> IndividualId {
        self.active.borrow().id()
    }

    pub fn agent_id(&self) -> AgentId {
        self.active.borrow().agent_id()
    }

    pub fn generate(
        signing_key: ed25519_dalek::SigningKey,
        event_listener: L,
        mut csprng: R,
    ) -> Result<Self, SigningError> {
        Ok(Self {
            active: Rc::new(RefCell::new(Active::generate(
                signing_key,
                event_listener.clone(),
                &mut csprng,
            )?)),
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

    pub fn active(&self) -> &Rc<RefCell<Active<L>>> {
        &self.active
    }

    pub fn groups(&self) -> &HashMap<GroupId, Rc<RefCell<Group<T, L>>>> {
        &self.groups
    }

    pub fn documents(&self) -> &HashMap<DocumentId, Rc<RefCell<Document<T, L>>>> {
        &self.docs
    }

    pub fn generate_group(
        &mut self,
        coparents: Vec<Peer<T, L>>,
    ) -> Result<Rc<RefCell<Group<T, L>>>, SigningError> {
        let g = Rc::new(RefCell::new(Group::generate(
            NonEmpty {
                head: self.active.dupe().into(),
                tail: coparents.into_iter().map(Into::into).collect(),
            },
            self.delegations.dupe(),
            self.revocations.dupe(),
            self.event_listener.clone(),
            &mut self.csprng,
        )?));

        self.groups.insert(g.borrow().group_id(), g.dupe());

        Ok(g)
    }

    pub fn generate_doc(
        &mut self,
        coparents: Vec<Peer<T, L>>,
        initial_content_heads: NonEmpty<T>,
    ) -> Result<Rc<RefCell<Document<T, L>>>, GenerateDocError> {
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
            self.event_listener.clone(),
            &self.active.borrow().signing_key,
            &mut self.csprng,
        )?;

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

    pub fn rotate_prekey(
        &mut self,
        prekey: ShareKey,
    ) -> Result<Rc<Signed<RotateKeyOp>>, SigningError> {
        self.active
            .borrow_mut()
            .rotate_prekey(prekey, &mut self.csprng)
    }

    pub fn expand_prekeys(&mut self) -> Result<Rc<Signed<AddKeyOp>>, SigningError> {
        self.active.borrow_mut().expand_prekeys(&mut self.csprng)
    }

    pub fn try_sign<U: Serialize>(&self, data: U) -> Result<Signed<U>, SigningError> {
        self.active.borrow().try_sign(data)
    }

    pub fn register_peer(&mut self, peer: Peer<T, L>) -> bool {
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

    pub fn register_group(&mut self, root_delegation: Signed<Delegation<T, L>>) -> bool {
        if self
            .groups
            .contains_key(&GroupId(root_delegation.subject_id()))
        {
            return false;
        }

        let group = Rc::new(RefCell::new(Group::from_individual(
            Individual::new(root_delegation.issuer.into()),
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
        digest: &Digest<MembershipOperation<T, L>>,
    ) -> Option<MembershipOperation<T, L>> {
        self.delegations
            .get(&digest.into())
            .map(|d| d.dupe().into())
            .or_else(|| {
                self.revocations
                    .get(&digest.into())
                    .map(|r| r.dupe().into())
            })
    }

    pub fn add_member(
        &mut self,
        to_add: Agent<T, L>,
        resource: &mut Membered<T, L>,
        can: Access,
        other_relevant_docs: &[Rc<RefCell<Document<T, L>>>], // TODO make this automatic
    ) -> Result<AddMemberUpdate<T, L>, AddMemberError> {
        match resource {
            Membered::Group(group) => Ok(group.borrow_mut().add_member(
                to_add,
                can,
                &self.active.borrow().signing_key,
                other_relevant_docs,
            )?),
            Membered::Document(doc) => doc.borrow_mut().add_member(
                to_add,
                can,
                &self.active.borrow().signing_key,
                other_relevant_docs,
            ),
        }
    }

    #[allow(clippy::type_complexity)]
    pub fn revoke_member(
        &mut self,
        to_revoke: Identifier,
        retain_all_other_members: bool,
        resource: &mut Membered<T, L>,
    ) -> Result<RevokeMemberUpdate<T, L>, RevokeMemberError> {
        let mut relevant_docs = BTreeMap::new();
        for (doc_id, Ability { doc, .. }) in self.reachable_docs() {
            relevant_docs.insert(doc_id, doc.borrow().content_heads.iter().cloned().collect());
        }

        resource.revoke_member(
            to_revoke,
            retain_all_other_members,
            &self.active.borrow().signing_key,
            &mut relevant_docs,
        )
    }

    // FIXME: I've temporarily changed this to return EncryptedContentWithUpdate
    // to make progress on writing end-to-end decrypt/encrypt tests.
    pub fn try_encrypt_content(
        &mut self,
        doc: Rc<RefCell<Document<T, L>>>,
        content_ref: &T,
        pred_refs: &Vec<T>,
        content: &[u8],
    ) -> Result<EncryptedContentWithUpdate<T>, EncryptContentError> {
        // ) -> Result<EncryptedContent<Vec<u8>, T>, EncryptContentError> {
        //         let EncryptedContentWithUpdate {
        //             encrypted_content,
        //             update_op,
        //         } = doc.borrow_mut().try_encrypt_content(
        //             content_ref,
        //             content,
        //             pred_refs,
        //             &mut self.csprng,
        //         )?;

        //         if let Some(found_update_op) = update_op {
        //             let signed_op = Rc::new(
        //                 self.try_sign(found_update_op)
        //                     .map_err(EncryptContentError::SignCgkaOpError)?,
        //             );
        //             self.event_listener.on_cgka_op(&signed_op);
        //         }

        //         Ok(encrypted_content)
        //     }
        let res = doc.borrow_mut().try_encrypt_content(
            content_ref,
            content,
            pred_refs,
            &self.active.borrow().signing_key,
            &mut self.csprng,
        )?;
        Ok(res)
    }

    pub fn try_decrypt_content(
        &mut self,
        doc: Rc<RefCell<Document<T, L>>>,
        encrypted: &EncryptedContent<Vec<u8>, T>,
    ) -> Result<Vec<u8>, DecryptError> {
        doc.borrow_mut().try_decrypt_content(encrypted)
    }

    pub fn force_pcs_update(
        &mut self,
        doc: Rc<RefCell<Document<T, L>>>,
    ) -> Result<Signed<CgkaOperation>, EncryptError> {
        doc.borrow_mut()
            .pcs_update(&self.active.borrow().signing_key, &mut self.csprng)
    }

    pub fn reachable_docs(&self) -> BTreeMap<DocumentId, Ability<T, L>> {
        self.docs_reachable_by_agent(&self.active.dupe().into())
    }

    pub fn reachable_members(
        &self,
        membered: Membered<T, L>,
    ) -> HashMap<Identifier, (Agent<T, L>, Access)> {
        match membered {
            Membered::Group(group) => group.borrow().transitive_members(),
            Membered::Document(doc) => doc.borrow().transitive_members(),
        }
    }

    pub fn docs_reachable_by_agent(
        &self,
        agent: &Agent<T, L>,
    ) -> BTreeMap<DocumentId, Ability<T, L>> {
        let mut caps: BTreeMap<DocumentId, Ability<T, L>> = BTreeMap::new();
        let mut seen: HashSet<AgentId> = HashSet::new();

        #[allow(clippy::type_complexity)]
        let mut explore: Vec<(Rc<RefCell<Group<T, L>>>, Access)> = vec![];

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
        agent: &Agent<T, L>,
    ) -> HashMap<MemberedId, (Membered<T, L>, Access)> {
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
        agent: &Agent<T, L>,
    ) -> Result<HashMap<Digest<Event<T, L>>, Event<T, L>>, CgkaError> {
        let mut ops: HashMap<_, _> = self
            .membership_ops_for_agent(agent)
            .into_iter()
            .map(|(op_digest, op)| (op_digest.into(), op.into()))
            .collect();

        for key_ops in self.reachable_prekey_ops_for_agent(agent).values() {
            for key_op in key_ops.iter() {
                let op = Event::<T, L>::from(key_op.as_ref().dupe());
                ops.insert(Digest::hash(&op), op);
            }
        }

        for cgka_op in self.cgka_ops_reachable_by_agent(agent)?.into_iter() {
            let op = Event::<T, L>::from(cgka_op);
            ops.insert(Digest::hash(&op), op);
        }

        Ok(ops)
    }

    pub fn cgka_ops_reachable_by_agent(
        &self,
        agent: &Agent<T, L>,
    ) -> Result<Vec<Rc<Signed<CgkaOperation>>>, CgkaError> {
        let mut ops = vec![];
        for (_doc_id, ability) in self.docs_reachable_by_agent(agent) {
            for epoch in ability.doc.borrow().cgka_ops()?.iter() {
                ops.extend(epoch.iter().cloned());
            }
        }
        Ok(ops)
    }

    pub fn membership_ops_for_agent(
        &self,
        agent: &Agent<T, L>,
    ) -> HashMap<Digest<MembershipOperation<T, L>>, MembershipOperation<T, L>> {
        let mut ops = HashMap::new();
        let mut visited_hashes = HashSet::new();

        #[allow(clippy::type_complexity)]
        let mut heads: Vec<(Digest<MembershipOperation<T, L>>, MembershipOperation<T, L>)> = vec![];

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
        agent: &Agent<T, L>,
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
            Agent::from(self.active.dupe())
                .key_ops()
                .into_iter()
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

    pub fn get_group(&self, id: GroupId) -> Option<&Rc<RefCell<Group<T, L>>>> {
        self.groups.get(&id)
    }

    pub fn get_document(&self, id: DocumentId) -> Option<&Rc<RefCell<Document<T, L>>>> {
        self.docs.get(&id)
    }

    pub fn get_peer(&self, id: Identifier) -> Option<Peer<T, L>> {
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

    pub fn get_agent(&self, id: Identifier) -> Option<Agent<T, L>> {
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
        let agent = if let Some(agent) = self.get_agent(id) {
            agent
        } else {
            let mut indie = Individual::new(IndividualId(id));
            indie.receive_prekey_op(key_op.clone())?;
            indie.into()
        };

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
                group
                    .borrow_mut()
                    .individual
                    .receive_prekey_op(key_op.clone())?;
            }
            Agent::Document(doc) => {
                doc.borrow_mut()
                    .group
                    .individual
                    .receive_prekey_op(key_op.clone())?;
            }
        }

        Ok(())
    }

    pub fn receive_delegation(
        &mut self,
        static_dlg: &Signed<StaticDelegation<T>>,
    ) -> Result<(), ReceieveStaticDelegationError<T, L>> {
        if self
            .delegations
            .contains_key(&Digest::hash(static_dlg).into())
        {
            return Ok(());
        }

        // NOTE: this is the only place this gets parsed and this verification ONLY happens here
        static_dlg.try_verify()?;

        let proof: Option<Rc<Signed<Delegation<T, L>>>> = static_dlg
            .payload()
            .proof
            .map(|proof_hash| {
                let hash = proof_hash.into();
                self.delegations.get(&hash).ok_or(MissingDependency(hash))
            })
            .transpose()?;

        let delegate_id = static_dlg.payload().delegate;
        let delegate: Agent<T, L> = self.get_agent(delegate_id).unwrap_or_else(|| {
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
                Ok::<_, ReceieveStaticDelegationError<T, L>>(acc)
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
    ) -> Result<(), ReceieveStaticDelegationError<T, L>> {
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
        let revoke: Rc<Signed<Delegation<T, L>>> = self
            .delegations
            .get(&revoke_hash)
            .ok_or(MissingDependency(revoke_hash))?;

        let proof: Option<Rc<Signed<Delegation<T, L>>>> = static_rev
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
            let mut group = Group::from_individual(
                Individual::new(static_rev.issuer.into()),
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

    pub fn receive_event(
        &mut self,
        static_event: StaticEvent<T>,
    ) -> Result<(), ReceiveEventError<T, L>> {
        match static_event {
            StaticEvent::Delegated(d) => self.receive_delegation(&d)?,
            StaticEvent::Revoked(r) => self.receive_revocation(&r)?,

            StaticEvent::PrekeysExpanded(op) => {
                self.receive_prekey_op(&KeyOp::from(Rc::new(op)))?
            }
            StaticEvent::PrekeyRotated(op) => self.receive_prekey_op(&KeyOp::from(Rc::new(op)))?,

            StaticEvent::CgkaOperation(cgka_op) => self.receive_cgka_op(cgka_op)?,
        }

        Ok(())
    }

    pub fn receive_membership_op(
        &mut self,
        static_op: &StaticMembershipOperation<T>,
    ) -> Result<(), ReceieveStaticDelegationError<T, L>> {
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

        let rc = Rc::new(signed_op);
        let op = &rc.dupe().payload;

        let doc_id = op.doc_id();
        let mut doc = self
            .docs
            .get(doc_id)
            .ok_or(ReceiveCgkaOpError::UnknownDocument(*doc_id))?
            .borrow_mut();

        if let CgkaOperation::Add { added_id, pk, .. } = op {
            let active = self.active.borrow();
            if active.id() == *added_id {
                let sk = active
                    .prekey_pairs
                    .get(pk)
                    .ok_or(ReceiveCgkaOpError::UnknownInvitePrekey(*pk))?;
                doc.merge_cgka_invite_op(rc, sk)?;
                return Ok(());
            }
        }
        doc.merge_cgka_op(rc)?;
        Ok(())
    }

    pub fn promote_individual_to_group(
        &mut self,
        individual: Rc<RefCell<Individual>>,
        head: Rc<Signed<Delegation<T, L>>>,
    ) -> Rc<RefCell<Group<T, L>>> {
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
        let active_ref = self.active.borrow();
        let active = Active {
            signing_key: active_ref.signing_key.clone(),
            prekey_pairs: active_ref.prekey_pairs.clone(),
            individual: active_ref.individual.clone(),
            listener: NoListener,
        };

        Archive {
            active,
            topsorted_ops: MembershipOperation::<T, L>::topsort(
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
        listener: L,
        csprng: R,
    ) -> Result<Self, TryFromArchiveError<T, L>> {
        let active = Rc::new(RefCell::new(Active {
            signing_key: archive.active.signing_key.clone(),
            prekey_pairs: archive.active.prekey_pairs.clone(),
            individual: archive.active.individual.clone(),
            listener: listener.clone(),
        }));

        let delegations: DelegationStore<T, L> = DelegationStore::new();
        let revocations: RevocationStore<T, L> = RevocationStore::new();

        let mut individuals = HashMap::new();
        for (k, v) in archive.individuals.iter() {
            individuals.insert(*k, Rc::new(RefCell::new(v.clone())));
        }

        let mut groups = HashMap::new();
        for (group_id, group_archive) in archive.groups.iter() {
            groups.insert(
                *group_id,
                Rc::new(RefCell::new(Group::<T, L>::dummy_from_archive(
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
                Rc::new(RefCell::new(Document::<T, L>::dummy_from_archive(
                    doc_archive.clone(),
                    &individuals,
                    delegations.dupe(),
                    revocations.dupe(),
                    listener.clone(),
                )?)),
            );
        }

        for (digest, static_op) in archive.topsorted_ops.iter() {
            match static_op {
                StaticMembershipOperation::Delegation(sd) => {
                    let proof: Option<Rc<Signed<Delegation<T, L>>>> = sd
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
                        let r: Rc<Signed<Revocation<T, L>>> = revocations
                            .borrow()
                            .get(&rev_digest.into())
                            .ok_or(TryFromArchiveError::MissingRevocation(rev_digest.into()))?
                            .dupe();

                        after_revocations.push(r);
                    }

                    let id = sd.payload.delegate;
                    let delegate: Agent<T, L> = if id == archive.active.id().into() {
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
        fn reify_ops<U: ContentRef, M: MembershipListener<U>>(
            group: &mut Group<U, M>,
            dlg_store: DelegationStore<U, M>,
            rev_store: RevocationStore<U, M>,
            dlg_head_hashes: &HashSet<Digest<Signed<StaticDelegation<U>>>>,
            rev_head_hashes: &HashSet<Digest<Signed<StaticRevocation<U>>>>,
            members: HashMap<Identifier, NonEmpty<Digest<Signed<Delegation<U, M>>>>>,
        ) -> Result<(), TryFromArchiveError<U, M>> {
            let read_dlgs = dlg_store.0.borrow();
            let read_revs = rev_store.0.borrow();

            for dlg_hash in dlg_head_hashes.iter() {
                let actual_dlg: Rc<Signed<Delegation<U, M>>> = read_dlgs
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
}

impl<
        T: ContentRef,
        L: MembershipListener<T> + CgkaListener,
        R: rand::CryptoRng + rand::RngCore,
    > Verifiable for Keyhive<T, L, R>
{
    fn verifying_key(&self) -> ed25519_dalek::VerifyingKey {
        self.active.borrow().verifying_key()
    }
}

impl<
        T: ContentRef,
        L: MembershipListener<T> + CgkaListener,
        R: rand::CryptoRng + rand::RngCore,
    > From<&Keyhive<T, L, R>> for Agent<T, L>
{
    fn from(context: &Keyhive<T, L, R>) -> Self {
        context.active.dupe().into()
    }
}

#[derive(Debug, Error)]
pub enum ReceieveStaticDelegationError<
    T: ContentRef = [u8; 32],
    L: MembershipListener<T> = NoListener,
> {
    #[error(transparent)]
    VerificationError(#[from] VerificationError),

    #[error("Missing proof: {0}")]
    MissingProof(#[from] MissingDependency<Digest<Signed<Delegation<T, L>>>>),

    #[error("Missing revocation dependency: {0}")]
    MissingRevocationDependency(#[from] MissingDependency<Digest<Signed<Revocation<T, L>>>>),

    #[error("Cgka init error: {0}")]
    CgkaInitError(#[from] CgkaError),

    #[error(transparent)]
    GroupReceiveError(#[from] AddError),
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum TryFromArchiveError<T: ContentRef, L: MembershipListener<T>> {
    #[error("Missing delegation: {0}")]
    MissingDelegation(#[from] Digest<Signed<Delegation<T, L>>>),

    #[error("Missing revocation: {0}")]
    MissingRevocation(#[from] Digest<Signed<Revocation<T, L>>>),

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

impl<T: ContentRef, L: MembershipListener<T>> From<MissingIndividualError>
    for TryFromArchiveError<T, L>
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
pub enum ReceiveEventError<T: ContentRef = [u8; 32], L: MembershipListener<T> = NoListener> {
    #[error(transparent)]
    ReceieveStaticDelegationError(#[from] ReceieveStaticDelegationError<T, L>),

    #[error(transparent)]
    ReceivePrekeyOpError(#[from] ReceivePrekeyOpError),

    #[error(transparent)]
    ReceiveCgkaOpError(#[from] ReceiveCgkaOpError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{access::Access, principal::public::Public};
    use nonempty::nonempty;
    use pretty_assertions::assert_eq;
    use rand::RngCore;
    use std::collections::VecDeque;

    #[test]
    fn test_event_round_trip() {
        let mut csprng = rand::thread_rng();

        let sk1 = ed25519_dalek::SigningKey::generate(&mut csprng);
        let sk2 = ed25519_dalek::SigningKey::generate(&mut csprng);

        let mut alice = Keyhive::generate(sk1, NoListener, csprng.clone()).unwrap();
        let mut bob = Keyhive::generate(sk2, NoListener, csprng.clone()).unwrap();

        let bob_peer: Peer = Rc::new(RefCell::new(bob.active.borrow().individual.clone())).into();

        let alice_doc = alice
            .generate_doc(vec![bob_peer], nonempty![[1; 32]])
            .unwrap();

        let alice_to_bob_ops = alice.events_for_agent(&bob.active.dupe().into()).unwrap();
        // assert_eq!(alice_to_bob_ops.len(), 19);

        assert!(alice_to_bob_ops
            .values()
            .any(|op| matches!(op, Event::CgkaOperation(_))));

        assert!(alice_to_bob_ops
            .values()
            .any(|op| matches!(op, Event::Delegated(_))));

        assert!(!alice_to_bob_ops
            .values()
            .any(|op| matches!(op, Event::Revoked(_))));

        let mut buf = alice_to_bob_ops
            .values()
            .map(|op| op.clone().into())
            .collect::<VecDeque<StaticEvent<[u8; 32]>>>();

        while let Some(op) = buf.pop_front() {
            if bob.receive_event(op.clone()).is_err() {
                buf.push_back(op);
            }
        }

        let doc_id = alice_doc.borrow().doc_id();
        let bob_doc = bob.documents().get(&doc_id).unwrap().dupe();
        assert_eq!(bob_doc.borrow().members().len(), 2);

        assert_eq!(
            alice_doc.borrow().cgka().unwrap().ops_graph.cgka_ops.len(),
            4
        );
        assert_eq!(bob_doc.borrow().cgka().unwrap().ops_graph.cgka_ops.len(), 4);
        assert_eq!(
            alice_doc.borrow().cgka().unwrap().ops_graph.cgka_ops,
            bob_doc.borrow().cgka().unwrap().ops_graph.cgka_ops
        );

        let EncryptedContentWithUpdate {
            encrypted_content, ..
        } = alice
            .try_encrypt_content(
                alice_doc.dupe(),
                &[15; 32],
                &vec![[1; 32]],
                b"this is a test",
            )
            .unwrap();

        assert!(encrypted_content.ciphertext != b"this is a test");

        let round_tripped = bob
            .try_decrypt_content(bob_doc.dupe(), &encrypted_content)
            .unwrap();

        assert_eq!(round_tripped, b"this is a test");

        bob.force_pcs_update(bob_doc.dupe()).unwrap();

        let EncryptedContentWithUpdate {
            encrypted_content: new_encrypted_content,
            ..
        } = alice
            .try_encrypt_content(
                alice_doc.dupe(),
                &[14; 32],
                &vec![[15; 32]],
                b"this is another test",
            )
            .unwrap();

        let round_tripped_2 = bob
            .try_decrypt_content(bob_doc.dupe(), &new_encrypted_content)
            .unwrap();

        assert_eq!(round_tripped_2, b"this is another test");

        let EncryptedContentWithUpdate {
            encrypted_content: unintelligable,
            ..
        } = bob
            .try_encrypt_content(
                bob_doc.dupe(),
                &[13; 32],
                &vec![[15; 32], [14; 32]],
                b"BOB MAKE MORE DIFFERENT TEST",
            )
            .unwrap();

        let round_tripped_2 = alice.try_decrypt_content(alice_doc.dupe(), &unintelligable);
        assert!(round_tripped_2.is_err());

        let bob_to_alice_ops = bob.events_for_agent(&alice.active.dupe().into()).unwrap();
        let cgkas: Vec<_> = bob_to_alice_ops
            .iter()
            .filter_map(|(h, op)| {
                if let Event::CgkaOperation(op) = op {
                    Some((h.clone(), op.clone()))
                } else {
                    None
                }
            })
            .collect();

        assert_eq!(cgkas.len(), 5);
        bob.force_pcs_update(bob_doc.dupe()).unwrap();
        bob.force_pcs_update(bob_doc.dupe()).unwrap();
        bob.force_pcs_update(bob_doc.dupe()).unwrap();
        bob.force_pcs_update(bob_doc.dupe()).unwrap();

        let bob_to_alice_ops2 = bob.events_for_agent(&alice.active.dupe().into()).unwrap();
        let cgkas_after_force_pcses: Vec<_> = bob_to_alice_ops2
            .iter()
            .filter_map(|(h, op)| {
                if let Event::CgkaOperation(op) = op {
                    Some((h.clone(), op.clone()))
                } else {
                    None
                }
            })
            .collect();
        assert_eq!(cgkas_after_force_pcses.len(), 9);

        let mut buf = bob_to_alice_ops
            .values()
            .map(|op| op.clone().into())
            .collect::<VecDeque<StaticEvent<[u8; 32]>>>();

        while let Some(op) = buf.pop_front() {
            if alice.receive_event(op.clone()).is_err() {
                buf.push_back(op);
            }
        }

        let round_tripped_3 = alice
            .try_decrypt_content(alice_doc.dupe(), &unintelligable)
            .unwrap();
        assert_eq!(round_tripped_3, b"BOB MAKE MORE DIFFERENT TEST");

        let sk3 = ed25519_dalek::SigningKey::generate(&mut csprng);
        let mut carol: Keyhive<[u8; 32]> =
            Keyhive::generate(sk3, NoListener, csprng.clone()).unwrap();
        let carol_peer: Peer =
            Rc::new(RefCell::new(carol.active.borrow().individual.clone())).into();

        let mut bob_doc_memed = bob_doc.dupe().into();
        let b_to_c_dlg = bob
            .add_member(carol_peer.into(), &mut bob_doc_memed, Access::Read, &[])
            .unwrap();

        assert!(b_to_c_dlg.cgka_ops.len() > 0);

        let EncryptedContentWithUpdate {
            encrypted_content: hi_carol,
            ..
        } = bob
            .try_encrypt_content(
                bob_doc.dupe(),
                &[13; 32],
                &vec![[15; 32], [14; 32]],
                b"Hi Carol",
            )
            .unwrap();

        let bob_to_carol_ops = bob.events_for_agent(&carol.active.dupe().into()).unwrap();

        let mut bob_to_carol_buf = bob_to_carol_ops
            .values()
            .map(|op| op.clone().into())
            .collect::<VecDeque<StaticEvent<[u8; 32]>>>();

        assert!(bob_to_carol_ops
            .values()
            .any(|op| *op == Event::Delegated(b_to_c_dlg.delegation.clone())));

        while let Some(op) = bob_to_carol_buf.pop_front() {
            if carol.receive_event(op.clone()).is_err() {
                bob_to_carol_buf.push_back(op);
            }
        }

        let carol_doc = carol.documents().get(&doc_id).unwrap().dupe();

        assert_eq!(
            carol
                .try_decrypt_content(carol_doc.dupe(), &hi_carol)
                .unwrap(),
            b"Hi Carol"
        );

        assert_eq!(
            carol
                .try_decrypt_content(carol_doc.dupe(), &unintelligable)
                .unwrap(),
            b"BOB MAKE MORE DIFFERENT TEST"
        );
    }

    #[test]
    fn test_archival_round_trip() {
        let mut csprng = rand::thread_rng();

        let sk = ed25519_dalek::SigningKey::generate(&mut csprng);
        let mut hive = Keyhive::generate(sk, NoListener, rand::thread_rng()).unwrap();

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

        assert!(!hive.active.borrow().prekey_pairs.is_empty());
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

        let hive_from_archive =
            Keyhive::try_from_archive(&archive, NoListener, rand::thread_rng()).unwrap();

        assert_eq!(hive, hive_from_archive);
    }

    #[test]
    fn test_receive_delegations_associately() {
        let mut hive1 = make_keyhive();
        let mut hive2 = make_keyhive();

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
        let mut left = make_keyhive();
        let mut middle = make_keyhive();
        let mut right = make_keyhive();

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
        let left_membered = left.membered_reachable_by_agent(&Public.individual().into());

        assert_eq!(left_membered.len(), 1);
        assert!(left_membered
            .get(&left_doc.borrow().doc_id().into())
            .is_some());
        assert!(left_membered
            .get(&left_group.borrow().group_id().into())
            .is_none()); // NOTE *not* included because Public is not a member

        let left_to_mid_ops = left.membership_ops_for_agent(&Public.individual().into());
        assert_eq!(left_to_mid_ops.len(), 2);
        for (h, op) in &left_to_mid_ops {
            middle.receive_membership_op(&op.clone().into()).unwrap();
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

        let mid_to_right_ops = middle.membership_ops_for_agent(&Public.individual().into());
        assert_eq!(mid_to_right_ops.len(), 2);
        for (h, op) in &mid_to_right_ops {
            right.receive_membership_op(&op.clone().into()).unwrap();
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
        let ops_on_right = right.membership_ops_for_agent(&Public.individual().into());
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
        let transitive_right_to_mid_ops =
            right.membership_ops_for_agent(&Public.individual().into());
        assert_eq!(transitive_right_to_mid_ops.len(), 4);
        for (h, op) in &transitive_right_to_mid_ops {
            middle.receive_membership_op(&op.clone().into()).unwrap();
            assert!(middle.delegations.borrow().get(&h.into()).is_some());
        }
        assert_eq!(middle.individuals.len(), 3); // NOTE now includes Right
        assert_eq!(middle.groups.len(), 1);
        assert_eq!(middle.docs.len(), 1);
        assert_eq!(middle.delegations.borrow().len(), 4);
    }

    fn make_keyhive() -> Keyhive {
        let sk = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
        Keyhive::generate(sk, NoListener, rand::thread_rng()).unwrap()
    }

    #[test]
    fn test_add_member() {
        let mut keyhive = make_keyhive();
        let doc = keyhive
            .generate_doc(
                vec![Rc::new(RefCell::new(Public.individual())).into()],
                nonempty![[0u8; 32]],
            )
            .unwrap();
        let member = Public.individual().into();
        let dlg = keyhive
            .add_member(member, &mut doc.clone().into(), Access::Read, &[])
            .unwrap();

        assert_eq!(dlg.delegation.subject_id(), doc.borrow().doc_id().into());
    }

    // TODO:
    // * Replace Public with real individuals
    // * Break out helper functions
    // * Concurrent combinations
    // * Add group to doc
    // * Add group to multiple docs, then add member to that group

    fn make_indie() -> Rc<RefCell<Individual>> {
        let mut csprng = rand::thread_rng();
        let indie_sk = ed25519_dalek::SigningKey::generate(&mut csprng);
        Rc::new(RefCell::new(
            Individual::generate(&indie_sk, &mut csprng).unwrap(),
        ))
    }

    fn initialize_keyhives_and_doc(count: usize) -> (Vec<Keyhive>, DocumentId) {
        let mut keyhives = vec![];
        let first = make_keyhive();
        keyhives.push(first);
        let indie = make_indie();
        let doc = keyhives[0]
            .generate_doc(vec![indie.dupe().into()], nonempty![[0u8; 32]])
            .unwrap();
        let cgka_epochs = doc.borrow().cgka_ops().unwrap();
        for _ in 0..count - 1 {
            let mut next = make_keyhive();
            let ops = keyhives[0].membership_ops_for_agent(&indie.dupe().into());
            for op in ops.values() {
                next.receive_membership_op(&op.clone().into()).unwrap();
            }
            for epoch in &cgka_epochs {
                for op in epoch.iter() {
                    next.receive_cgka_op((**op).clone()).unwrap();
                }
            }
            keyhives.push(next);
        }
        let doc_id = doc.borrow().doc_id();
        for keyhive in &mut keyhives {
            keyhive.get_document(doc_id).unwrap();
        }
        (keyhives, doc_id)
    }

    fn share_delegation(
        delegation: Rc<Signed<Delegation<[u8; 32]>>>,
        keyhives: &mut Vec<Keyhive>,
        sharer_idx: usize,
    ) {
        let static_dlg = Signed {
            issuer: delegation.issuer,
            signature: delegation.signature,
            payload: delegation.payload.clone().into(),
        };
        for idx in 0..keyhives.len() {
            if idx == sharer_idx {
                continue;
            }
            keyhives[idx].receive_delegation(&static_dlg).unwrap();
        }
    }

    fn share_ops_for_agent(agent: Agent, keyhives: &mut Vec<Keyhive>, sharer_idx: usize) -> usize {
        let mut share_count = 0;
        for idx in 0..keyhives.len() {
            if idx == sharer_idx {
                continue;
            }
            let op_store = keyhives[sharer_idx].membership_ops_for_agent(&agent);

            for (_h, op) in op_store.iter() {
                share_count += 1;
                keyhives[idx]
                    .receive_membership_op(&op.clone().into())
                    .unwrap();
            }
        }

        share_count
    }

    fn share_cgka_op(op: &Signed<CgkaOperation>, keyhives: &mut Vec<Keyhive>, sharer_idx: usize) {
        for idx in 0..keyhives.len() {
            if idx == sharer_idx {
                continue;
            }
            keyhives[idx].receive_cgka_op(op.clone()).unwrap();
        }
    }

    #[test]
    fn test_sharing_ops_to_debug() {
        let (mut keyhives, _doc_id) = initialize_keyhives_and_doc(2);
        let a_idx = 0;
        let b_idx = 1;

        let a_peer: Peer = Rc::new(RefCell::new(
            keyhives[a_idx].active.borrow().individual.clone(),
        ))
        .into();

        let second_group = keyhives[b_idx].generate_group(vec![a_peer]).unwrap();
        let share_count =
            share_ops_for_agent(keyhives[a_idx].active.dupe().into(), &mut keyhives, 1);
        assert!(share_count > 0);

        let indie = make_indie();
        let add = keyhives[b_idx]
            .add_member(
                indie.dupe().into(),
                &mut second_group.dupe().into(),
                Access::Read,
                &[],
            )
            .unwrap();
        share_delegation(add.delegation.dupe(), &mut keyhives, 1);
        let indie_op_count = share_ops_for_agent(indie.dupe().into(), &mut keyhives, 1);
        assert!(indie_op_count > 0);
    }

    // #[test]
    // fn test_concurrent_cgka_operations() {
    //     let (mut keyhives, doc_id) = initialize_keyhives_and_doc(2);
    //     let a_idx = 0;
    //     let b_idx = 1;

    //     let a_doc = keyhives[a_idx].get_document(doc_id).unwrap().dupe();
    //     let cgka_op = keyhives[a_idx].force_pcs_update(a_doc.dupe()).unwrap();
    //     share_cgka_op(&cgka_op, &mut keyhives, a_idx);

    //     let content = "Let's start!";
    //     let content_ref = generate_content_ref();
    //     let pred_refs = Vec::new();
    //     let encrypted_with_update = keyhives[a_idx]
    //         .try_encrypt_content(a_doc.dupe(), &content_ref, &pred_refs, content.as_bytes())
    //         .unwrap();
    //     assert_eq!(
    //         content,
    //         &String::from_utf8(
    //             keyhives[a_idx]
    //                 .try_decrypt_content(a_doc, &encrypted_with_update.encrypted_content)
    //                 .unwrap()
    //         )
    //         .unwrap()
    //     );

    //     if let Some(op) = encrypted_with_update.update_op {
    //         keyhives[b_idx].receive_cgka_op(op.clone()).unwrap();
    //     }
    //     let encrypted = encrypted_with_update.encrypted_content;
    //     let b_doc = keyhives[b_idx].get_document(doc_id).unwrap().dupe();
    //     let b_content: String = String::from_utf8(
    //         keyhives[b_idx]
    //             .try_decrypt_content(b_doc.dupe(), &encrypted)
    //             .unwrap(),
    //     )
    //     .unwrap();
    //     assert_eq!(content, &b_content);

    //     let second_group = keyhives[b_idx].generate_group(vec![]).unwrap();
    //     share_ops_for_agent(second_group.dupe().into(), &mut keyhives, 1);
    //     let indie = make_indie();
    //     let add = keyhives[b_idx]
    //         .add_member(
    //             indie.dupe().into(),
    //             &mut second_group.dupe().into(),
    //             Access::Read,
    //             &[],
    //         )
    //         .unwrap();
    //     share_delegation(add.delegation.dupe(), &mut keyhives, b_idx);
    //     share_ops_for_agent(indie.dupe().into(), &mut keyhives, b_idx);
    // }

    fn generate_content_ref() -> [u8; 32] {
        let mut csprng = rand::thread_rng();
        let mut content_ref = [0u8; 32];
        csprng.fill_bytes(&mut content_ref);
        content_ref
    }
}
