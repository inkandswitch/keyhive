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
    listener::{log::Log, membership::MembershipListener, no_listener::NoListener},
    principal::{
        active::Active,
        agent::{id::AgentId, Agent},
        document::{
            id::DocumentId, AddMemberError, AddMemberUpdate, DecryptError,
            DocCausalDecryptionError, Document, EncryptError, EncryptedContentWithUpdate,
            GenerateDocError, MissingIndividualError, RevokeMemberUpdate,
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
    store::{
        ciphertext::{memory::MemoryCiphertextStore, CausalDecryptionState, CiphertextStore},
        delegation::DelegationStore,
        revocation::RevocationStore,
    },
    transact::{
        fork::ForkAsync,
        merge::{Merge, MergeAsync},
    },
};
use derive_where::derive_where;
use dupe::{Dupe, OptionDupedExt};
use futures::lock::Mutex;
use nonempty::NonEmpty;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    fmt::{Debug, Formatter},
    marker::PhantomData,
    sync::Arc,
};
use thiserror::Error;
use tracing::instrument;

/// The main object for a user agent & top-level owned stores.
#[derive(Clone)]
pub struct Keyhive<
    S: AsyncSigner + Clone,
    T: ContentRef = [u8; 32],
    P: for<'de> Deserialize<'de> = Vec<u8>,
    C: CiphertextStore<T, P> + Clone = MemoryCiphertextStore<T, P>,
    L: MembershipListener<S, T> = NoListener,
    R: rand::CryptoRng = rand::rngs::OsRng,
> {
    /// The public verifying key for the active user.
    verifying_key: ed25519_dalek::VerifyingKey,

    /// The [`Active`] user agent.
    active: Arc<Mutex<Active<S, T, L>>>,

    /// The [`Individual`]s that are known to this agent.
    individuals: Arc<Mutex<HashMap<IndividualId, Arc<Mutex<Individual>>>>>,

    /// The [`Group`]s that are known to this agent.
    #[allow(clippy::type_complexity)]
    groups: Arc<Mutex<HashMap<GroupId, Arc<Mutex<Group<S, T, L>>>>>>,

    /// The [`Document`]s that are known to this agent.
    #[allow(clippy::type_complexity)]
    docs: Arc<Mutex<HashMap<DocumentId, Arc<Mutex<Document<S, T, L>>>>>>,

    /// All applied [`Delegation`]s
    delegations: DelegationStore<S, T, L>,

    /// All applied [`Revocation`]s
    revocations: RevocationStore<S, T, L>,

    /// Obsever for [`Event`]s. Intended for running live updates.
    event_listener: L,

    /// Storeage for ciphertexts that cannot yet be decrypted.
    ciphertext_store: C,

    /// Cryptographically secure (pseudo)random number generator.
    csprng: Arc<Mutex<R>>,

    _plaintext_phantom: PhantomData<P>,
}

impl<
        S: AsyncSigner + Clone,
        T: ContentRef,
        P: for<'de> Deserialize<'de>,
        C: CiphertextStore<T, P> + Clone,
        L: MembershipListener<S, T>,
        R: rand::CryptoRng + rand::RngCore,
    > Keyhive<S, T, P, C, L, R>
{
    #[instrument(skip_all)]
    pub fn id(&self) -> IndividualId {
        self.verifying_key.into()
    }

    #[instrument(skip_all)]
    pub async fn agent_id(&self) -> AgentId {
        self.active.lock().await.agent_id()
    }

    #[instrument(skip_all)]
    pub async fn generate(
        signer: S,
        ciphertext_store: C,
        event_listener: L,
        mut csprng: R,
    ) -> Result<Self, SigningError> {
        Ok(Self {
            verifying_key: signer.verifying_key(),
            active: Arc::new(Mutex::new(
                Active::generate(signer, event_listener.clone(), &mut csprng).await?,
            )),
            individuals: Arc::new(Mutex::new(HashMap::from_iter([(
                Public.id().into(),
                Arc::new(Mutex::new(Public.individual())),
            )]))),
            groups: Arc::new(Mutex::new(HashMap::new())),
            docs: Arc::new(Mutex::new(HashMap::new())),
            delegations: DelegationStore::new(),
            revocations: RevocationStore::new(),
            ciphertext_store,
            event_listener,
            csprng: Arc::new(Mutex::new(csprng)),
            _plaintext_phantom: PhantomData,
        })
    }

    /// The current [`Active`] Keyhive user.
    #[instrument(skip_all)]
    pub fn active(&self) -> &Arc<Mutex<Active<S, T, L>>> {
        &self.active
    }

    /// Get the [`Individual`] for the current Keyhive user.
    ///
    /// This is what you would share with a peer for them to
    /// register your identity on their system.
    ///
    /// Importantly this includes prekeys in addition to your public key.
    #[instrument(skip_all)]
    pub async fn individual(&self) -> Individual {
        self.active.lock().await.individual().clone()
    }

    #[allow(clippy::type_complexity)]
    #[instrument(skip_all)]
    pub fn groups(&self) -> &Arc<Mutex<HashMap<GroupId, Arc<Mutex<Group<S, T, L>>>>>> {
        &self.groups
    }

    #[allow(clippy::type_complexity)]
    #[instrument(skip_all)]
    pub fn documents(&self) -> &Arc<Mutex<HashMap<DocumentId, Arc<Mutex<Document<S, T, L>>>>>> {
        &self.docs
    }

    #[allow(clippy::type_complexity)]
    #[instrument(skip_all)]
    pub async fn generate_group(
        &self,
        coparents: Vec<Peer<S, T, L>>,
    ) -> Result<Arc<Mutex<Group<S, T, L>>>, SigningError> {
        let group = Group::generate(
            NonEmpty {
                head: Agent::Active(self.active.lock().await.id(), self.active.dupe()),
                tail: coparents.into_iter().map(Into::into).collect(),
            },
            self.delegations.dupe(),
            self.revocations.dupe(),
            self.event_listener.clone(),
            self.csprng.dupe(),
        )
        .await?;
        let group_id = group.group_id();
        let g = Arc::new(Mutex::new(group));
        self.groups.lock().await.insert(group_id, g.dupe());
        Ok(g)
    }

    #[allow(clippy::type_complexity)]
    #[instrument(skip_all)]
    pub async fn generate_doc(
        &self,
        coparents: Vec<Peer<S, T, L>>,
        initial_content_heads: NonEmpty<T>,
    ) -> Result<Arc<Mutex<Document<S, T, L>>>, GenerateDocError> {
        for peer in coparents.iter() {
            if self.get_agent(peer.id()).await.is_none() {
                self.register_peer(peer.dupe()).await;
            }
        }

        let signer = {
            let locked = self.active.lock().await;
            locked.signer.clone()
        };

        let active_id = { self.active.lock().await.id() };
        let new_doc = Document::generate(
            NonEmpty {
                head: Agent::Active(active_id, self.active.dupe()),
                tail: coparents.into_iter().map(Into::into).collect(),
            },
            initial_content_heads,
            self.delegations.dupe(),
            self.revocations.dupe(),
            self.event_listener.clone(),
            &signer,
            self.csprng.dupe(),
        )
        .await?;

        for head in new_doc.delegation_heads().values() {
            self.delegations.insert(head.dupe()).await;

            for dep in head.payload().proof_lineage() {
                self.delegations.insert(dep).await;
            }
        }

        let doc_id = new_doc.doc_id();
        let doc = Arc::new(Mutex::new(new_doc));
        self.docs.lock().await.insert(doc_id, doc.dupe());

        Ok(doc)
    }

    #[instrument(skip_all)]
    pub async fn contact_card(&self) -> Result<ContactCard, SigningError> {
        let rot_key_op = self
            .active
            .lock()
            .await
            .generate_private_prekey(self.csprng.dupe())
            .await?;

        Ok(ContactCard(KeyOp::Rotate(rot_key_op)))
    }

    #[instrument(skip_all)]
    pub async fn receive_contact_card(
        &self,
        contact_card: &ContactCard,
    ) -> Result<Arc<Mutex<Individual>>, ReceivePrekeyOpError> {
        if let Some(indie) = self.get_individual(contact_card.id()).await {
            indie
                .lock()
                .await
                .receive_prekey_op(contact_card.op().dupe())?;
            Ok(indie.dupe())
        } else {
            let new_user = Arc::new(Mutex::new(Individual::from(contact_card)));
            self.register_individual(new_user.dupe()).await;
            Ok(new_user)
        }
    }

    #[instrument(skip_all)]
    pub async fn rotate_prekey(
        &self,
        prekey: ShareKey,
    ) -> Result<Arc<Signed<RotateKeyOp>>, SigningError> {
        self.active
            .lock()
            .await
            .rotate_prekey(prekey, self.csprng.dupe())
            .await
    }

    #[instrument(skip_all)]
    pub async fn expand_prekeys(&self) -> Result<Arc<Signed<AddKeyOp>>, SigningError> {
        self.active
            .lock()
            .await
            .expand_prekeys(self.csprng.dupe())
            .await
    }

    #[instrument(skip_all)]
    pub async fn try_sign<U: Serialize + Debug>(&self, data: U) -> Result<Signed<U>, SigningError> {
        let signer = self.active.lock().await.signer.clone();
        signer.try_sign_async(data).await
    }

    #[instrument(skip_all)]
    pub async fn register_peer(&self, peer: Peer<S, T, L>) -> bool {
        if self.get_peer(peer.id()).await.is_some() {
            return false;
        }

        match peer {
            Peer::Individual(id, indie) => {
                self.individuals.lock().await.insert(id, indie.dupe());
            }
            Peer::Group(group_id, group) => {
                self.groups.lock().await.insert(group_id, group.dupe());
            }
            Peer::Document(doc_id, doc) => {
                self.docs.lock().await.insert(doc_id, doc.dupe());
            }
        }

        true
    }

    #[instrument(skip_all)]
    pub async fn register_individual(&self, individual: Arc<Mutex<Individual>>) -> bool {
        let id = { individual.lock().await.id() };

        {
            let mut locked_individuals = self.individuals.lock().await;
            if locked_individuals.contains_key(&id) {
                return false;
            }

            locked_individuals.insert(id, individual.dupe());
        }
        true
    }

    #[instrument(skip_all)]
    pub async fn register_group(&self, root_delegation: Signed<Delegation<S, T, L>>) -> bool {
        if self
            .groups
            .lock()
            .await
            .contains_key(&GroupId(root_delegation.subject_id()))
        {
            return false;
        }

        let group = Arc::new(Mutex::new(
            Group::new(
                GroupId(root_delegation.issuer.into()),
                Arc::new(root_delegation),
                self.delegations.dupe(),
                self.revocations.dupe(),
                self.event_listener.clone(),
            )
            .await,
        ));

        {
            let locked = group.lock().await;
            self.groups
                .lock()
                .await
                .insert(locked.group_id(), group.dupe());
        }
        true
    }

    #[instrument(skip_all)]
    pub async fn get_membership_operation(
        &self,
        digest: &Digest<MembershipOperation<S, T, L>>,
    ) -> Option<MembershipOperation<S, T, L>> {
        if let Some(d) = self.delegations.get(&digest.into()).await {
            Some(d.dupe().into())
        } else {
            self.revocations
                .get(&digest.into())
                .await
                .map(|r| r.dupe().into())
        }
    }

    #[allow(clippy::type_complexity)]
    pub async fn add_member(
        &self,
        to_add: Agent<S, T, L>,
        resource: &Membered<S, T, L>,
        can: Access,
        other_relevant_docs: &[Arc<Mutex<Document<S, T, L>>>], // TODO make this automatic
    ) -> Result<AddMemberUpdate<S, T, L>, AddMemberError> {
        let signer = { self.active.lock().await.signer.clone() };
        match resource {
            Membered::Group(_, group) => Ok(group
                .lock()
                .await
                .add_member(to_add, can, &signer, other_relevant_docs)
                .await?),
            Membered::Document(_, doc) => {
                let mut locked = doc.lock().await;
                locked
                    .add_member(to_add, can, &signer, other_relevant_docs)
                    .await
            }
        }
    }

    #[allow(clippy::type_complexity)]
    #[instrument(skip_all)]
    pub async fn revoke_member(
        &self,
        to_revoke: Identifier,
        retain_all_other_members: bool,
        resource: &Membered<S, T, L>,
    ) -> Result<RevokeMemberUpdate<S, T, L>, RevokeMemberError> {
        let mut relevant_docs = BTreeMap::new();
        for (doc_id, Ability { doc, .. }) in self.reachable_docs().await {
            let locked = doc.lock().await;
            relevant_docs.insert(doc_id, locked.content_heads.iter().cloned().collect());
        }

        let signer = { self.active.lock().await.signer.clone() };
        resource
            .revoke_member(
                to_revoke,
                retain_all_other_members,
                &signer,
                &mut relevant_docs,
            )
            .await
    }

    #[instrument(skip_all)]
    pub async fn try_encrypt_content(
        &self,
        doc: Arc<Mutex<Document<S, T, L>>>,
        content_ref: &T,
        pred_refs: &Vec<T>,
        content: &[u8],
    ) -> Result<EncryptedContentWithUpdate<T>, EncryptContentError> {
        let signer = { self.active.lock().await.signer.clone() };
        let result = {
            let mut locked_csprng = self.csprng.lock().await;
            doc.lock()
                .await
                .try_encrypt_content(
                    content_ref,
                    content,
                    pred_refs,
                    &signer,
                    &mut *locked_csprng,
                )
                .await?
        };
        if let Some(op) = &result.update_op {
            self.event_listener.on_cgka_op(&Arc::new(op.clone())).await;
        }
        Ok(result)
    }

    pub async fn try_decrypt_content(
        &self,
        doc: Arc<Mutex<Document<S, T, L>>>,
        encrypted: &EncryptedContent<P, T>,
    ) -> Result<Vec<u8>, DecryptError> {
        doc.lock().await.try_decrypt_content(encrypted)
    }

    pub async fn try_causal_decrypt_content(
        &self,
        doc: Arc<Mutex<Document<S, T, L>>>,
        encrypted: &EncryptedContent<P, T>,
    ) -> Result<CausalDecryptionState<T, P>, DocCausalDecryptionError<T, P, C>>
    where
        T: for<'de> Deserialize<'de>,
        P: Serialize + Clone,
    {
        doc.lock()
            .await
            .try_causal_decrypt_content(encrypted, self.ciphertext_store.clone())
            .await
    }

    #[instrument(skip_all)]
    pub async fn force_pcs_update(
        &self,
        doc: Arc<Mutex<Document<S, T, L>>>,
    ) -> Result<Signed<CgkaOperation>, EncryptError> {
        let signer = { self.active.lock().await.signer.clone() };
        let mut locked_csprng = self.csprng.lock().await;
        doc.lock()
            .await
            .pcs_update(&signer, &mut *locked_csprng)
            .await
    }

    #[instrument(skip_all)]
    pub async fn reachable_docs(&self) -> BTreeMap<DocumentId, Ability<S, T, L>> {
        let active = self.active.dupe();
        let locked_active = self.active.lock().await;
        self.docs_reachable_by_agent(&Agent::Active(locked_active.id(), active))
            .await
    }

    #[instrument(skip_all)]
    pub async fn reachable_members(
        &self,
        membered: Membered<S, T, L>,
    ) -> HashMap<Identifier, (Agent<S, T, L>, Access)> {
        match membered {
            Membered::Group(_, group) => group.lock().await.transitive_members().await,
            Membered::Document(_, doc) => doc.lock().await.transitive_members().await,
        }
    }

    #[instrument(skip_all)]
    pub async fn docs_reachable_by_agent(
        &self,
        agent: &Agent<S, T, L>,
    ) -> BTreeMap<DocumentId, Ability<S, T, L>> {
        let mut caps: BTreeMap<DocumentId, Ability<S, T, L>> = BTreeMap::new();

        // TODO will be very slow on large hives. Old code here: https://github.com/inkandswitch/keyhive/pull/111/files:
        let docs = { self.docs.lock().await.values().cloned().collect::<Vec<_>>() };
        for doc in docs {
            let locked = doc.lock().await;
            if let Some((_, cap)) = locked.transitive_members().await.get(&agent.id()) {
                caps.insert(
                    locked.doc_id(),
                    Ability {
                        doc: doc.dupe(),
                        can: *cap,
                    },
                );
            }
        }

        caps
    }

    #[instrument(skip_all)]
    pub async fn membered_reachable_by_agent(
        &self,
        agent: &Agent<S, T, L>,
    ) -> HashMap<MemberedId, (Membered<S, T, L>, Access)> {
        let mut caps = HashMap::new();

        let groups = {
            self.groups
                .lock()
                .await
                .values()
                .cloned()
                .collect::<Vec<_>>()
        };
        for group in groups {
            let locked = group.lock().await;
            if let Some((_, can)) = locked.transitive_members().await.get(&agent.id()) {
                let membered = Membered::Group(locked.group_id(), group.dupe());
                caps.insert(locked.group_id().into(), (membered, *can));
            }
        }

        let docs = { self.docs.lock().await.values().cloned().collect::<Vec<_>>() };
        for doc in docs {
            let locked = doc.lock().await;
            if let Some((_, can)) = locked.transitive_members().await.get(&agent.id()) {
                let membered = Membered::Document(locked.doc_id(), doc.dupe());
                caps.insert(locked.doc_id().into(), (membered, *can));
            }
        }

        caps
    }

    #[allow(clippy::type_complexity)]
    #[instrument(skip_all)]
    pub async fn events_for_agent(
        &self,
        agent: &Agent<S, T, L>,
    ) -> Result<HashMap<Digest<Event<S, T, L>>, Event<S, T, L>>, CgkaError> {
        let mut ops: HashMap<_, _> = self
            .membership_ops_for_agent(agent)
            .await
            .into_iter()
            .map(|(op_digest, op)| (op_digest.into(), op.into()))
            .collect();

        for key_ops in self.reachable_prekey_ops_for_agent(agent).await.values() {
            for key_op in key_ops.iter() {
                let op = Event::<S, T, L>::from(key_op.as_ref().dupe());
                ops.insert(Digest::hash(&op), op);
            }
        }

        for cgka_op in self.cgka_ops_reachable_by_agent(agent).await?.into_iter() {
            let op = Event::<S, T, L>::from(cgka_op);
            ops.insert(Digest::hash(&op), op);
        }

        Ok(ops)
    }

    #[instrument(skip_all)]
    pub async fn static_events_for_agent(
        &self,
        agent: &Agent<S, T, L>,
    ) -> Result<HashMap<Digest<StaticEvent<T>>, StaticEvent<T>>, CgkaError> {
        Ok(self
            .events_for_agent(agent)
            .await?
            .into_iter()
            .map(|(k, v)| (k.into(), v.into()))
            .collect())
    }

    #[instrument(skip_all)]
    pub async fn cgka_ops_reachable_by_agent(
        &self,
        agent: &Agent<S, T, L>,
    ) -> Result<Vec<Arc<Signed<CgkaOperation>>>, CgkaError> {
        let mut ops = Vec::new();
        let reachable = { self.docs_reachable_by_agent(agent).await };
        for (_doc_id, ability) in reachable {
            let epochs = { ability.doc.lock().await.cgka_ops()? };
            for epoch in &epochs {
                ops.extend(epoch.iter().cloned());
            }
        }
        Ok(ops)
    }

    #[instrument(skip_all)]
    pub async fn cgka_ops_for_doc(
        &self,
        doc: &DocumentId,
    ) -> Result<Option<Vec<Arc<Signed<CgkaOperation>>>>, CgkaError> {
        let locked_docs = self.docs.lock().await;
        let Some(doc) = locked_docs.get(doc) else {
            return Ok(None);
        };
        let mut ops = Vec::new();
        let epochs = { doc.lock().await.cgka_ops()? };
        drop(locked_docs);
        for epoch in &epochs {
            ops.extend(epoch.iter().cloned());
        }
        Ok(Some(ops))
    }

    #[allow(clippy::type_complexity)]
    #[instrument(skip_all)]
    pub async fn membership_ops_for_agent(
        &self,
        agent: &Agent<S, T, L>,
    ) -> HashMap<Digest<MembershipOperation<S, T, L>>, MembershipOperation<S, T, L>> {
        let mut ops = HashMap::new();
        let mut visited_hashes = HashSet::new();

        #[allow(clippy::type_complexity)]
        let mut heads: Vec<(
            Digest<MembershipOperation<S, T, L>>,
            MembershipOperation<S, T, L>,
        )> = Vec::new();

        for (mem_rc, _max_acces) in self.membered_reachable_by_agent(agent).await.values() {
            for (hash, dlg_head) in mem_rc.delegation_heads().await.iter() {
                heads.push((hash.into(), dlg_head.dupe().into()));
            }

            for (hash, rev_head) in mem_rc.revocation_heads().await.iter() {
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

    #[instrument(skip_all)]
    pub async fn reachable_prekey_ops_for_agent(
        &self,
        agent: &Agent<S, T, L>,
    ) -> HashMap<Identifier, Vec<Arc<KeyOp>>> {
        fn add_many_keys(
            map: &mut HashMap<Identifier, Vec<Arc<KeyOp>>>,
            agent_id: Identifier,
            key_ops: HashSet<Arc<KeyOp>>,
        ) {
            let mut heads: Vec<Arc<KeyOp>> = vec![];
            let mut rotate_key_ops: HashMap<ShareKey, HashSet<Arc<KeyOp>>> = HashMap::new();

            for key_op in &key_ops {
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

        let (active_id, prekeys) = {
            let locked = self.active.lock().await;
            (
                locked.id().into(),
                locked.individual.prekey_ops().values().cloned().collect(),
            )
        };
        add_many_keys(&mut map, active_id, prekeys);

        // Add the agents own keys
        add_many_keys(&mut map, agent.id(), agent.key_ops().await);

        for (mem, _) in self.membered_reachable_by_agent(agent).await.values() {
            match mem {
                Membered::Group(group_id, group) => {
                    let group_transitive_members =
                        { group.lock().await.transitive_members().await };

                    add_many_keys(
                        &mut map,
                        (*group_id).into(),
                        Agent::Group(*group_id, group.dupe())
                            .key_ops()
                            .await
                            .into_iter()
                            .collect(),
                    );

                    for (agent_id, (agent, _acess)) in &group_transitive_members {
                        add_many_keys(
                            &mut map,
                            *agent_id,
                            agent.key_ops().await.into_iter().collect(),
                        );
                    }
                }
                Membered::Document(doc_id, doc) => {
                    let doc_transitive_members = { doc.lock().await.transitive_members().await };

                    add_many_keys(
                        &mut map,
                        (*doc_id).into(),
                        Agent::Document(*doc_id, doc.dupe())
                            .key_ops()
                            .await
                            .into_iter()
                            .collect(),
                    );

                    for (agent_id, (agent, _acess)) in &doc_transitive_members {
                        add_many_keys(
                            &mut map,
                            *agent_id,
                            agent.key_ops().await.into_iter().collect(),
                        );
                    }
                }
            }
        }

        map
    }

    #[instrument(skip_all)]
    pub async fn get_individual(&self, id: IndividualId) -> Option<Arc<Mutex<Individual>>> {
        self.individuals.lock().await.get(&id).duped()
    }

    #[allow(clippy::type_complexity)]
    #[instrument(skip_all)]
    pub async fn get_group(&self, id: GroupId) -> Option<Arc<Mutex<Group<S, T, L>>>> {
        self.groups.lock().await.get(&id).duped()
    }

    #[allow(clippy::type_complexity)]
    #[instrument(skip_all)]
    pub async fn get_document(&self, id: DocumentId) -> Option<Arc<Mutex<Document<S, T, L>>>> {
        self.docs.lock().await.get(&id).duped()
    }

    #[instrument(skip_all)]
    pub async fn get_peer(&self, id: Identifier) -> Option<Peer<S, T, L>> {
        let indie_id = IndividualId(id);

        {
            let locked_docs = self.docs.lock().await;
            if let Some(doc) = locked_docs.get(&DocumentId(id)) {
                return Some(Peer::Document(id.into(), doc.dupe()));
            }
        }

        {
            let locked_groups = self.groups.lock().await;
            if let Some(group) = locked_groups.get(&GroupId::new(id)) {
                return Some(Peer::Group(id.into(), group.dupe()));
            }
        }

        {
            let locked_individuals = self.individuals.lock().await;
            if let Some(indie) = locked_individuals.get(&indie_id) {
                return Some(Peer::Individual(id.into(), indie.dupe()));
            }
        }

        None
    }

    #[instrument(skip_all)]
    pub async fn get_agent(&self, id: Identifier) -> Option<Agent<S, T, L>> {
        let indie_id = id.into();

        let active_id = { self.active.lock().await.id() };
        if indie_id == active_id {
            return Some(Agent::Active(indie_id, self.active.dupe()));
        }

        {
            let locked_docs = self.docs.lock().await;
            if let Some(doc) = locked_docs.get(&DocumentId(id)) {
                return Some(Agent::Document(id.into(), doc.dupe()));
            }
        }

        {
            let locked_groups = self.groups.lock().await;
            if let Some(group) = locked_groups.get(&GroupId::new(id)) {
                return Some(Agent::Group(id.into(), group.dupe()));
            }
        }

        {
            let locked_individuals = self.individuals.lock().await;
            if let Some(indie) = locked_individuals.get(&indie_id) {
                return Some(Agent::Individual(id.into(), indie.dupe()));
            }
        }

        None
    }

    #[instrument(skip_all)]
    pub async fn receive_prekey_op(&self, key_op: &KeyOp) -> Result<(), ReceivePrekeyOpError> {
        let id = Identifier(*key_op.issuer());
        let agent = if let Some(agent) = self.get_agent(id).await {
            agent
        } else {
            let indie = Arc::new(Mutex::new(Individual::new(key_op.clone())));
            self.register_individual(indie.dupe()).await;
            Agent::Individual(id.into(), indie)
        };

        match agent {
            Agent::Active(_, active) => {
                active
                    .lock()
                    .await
                    .individual
                    .receive_prekey_op(key_op.clone())?;
            }
            Agent::Individual(_, indie) => {
                indie.lock().await.receive_prekey_op(key_op.clone())?;
            }
            Agent::Group(_, group) => {
                let mut locked = group.lock().await;
                if let IdOrIndividual::Individual(indie) = &mut locked.id_or_indie {
                    indie.receive_prekey_op(key_op.clone())?;
                } else {
                    let individual = Individual::new(key_op.dupe());
                    locked.id_or_indie = IdOrIndividual::Individual(individual);
                }
            }
            Agent::Document(_, doc) => {
                let mut locked = doc.lock().await;
                if let IdOrIndividual::Individual(indie) = &mut locked.group.id_or_indie {
                    indie.receive_prekey_op(key_op.clone())?;
                } else {
                    let individual = Individual::new(key_op.dupe());
                    locked.group.id_or_indie = IdOrIndividual::Individual(individual);
                }
            }
        }

        Ok(())
    }

    #[instrument(skip_all)]
    pub async fn receive_delegation(
        &self,
        static_dlg: &Signed<StaticDelegation<T>>,
    ) -> Result<(), ReceieveStaticDelegationError<S, T, L>> {
        if self
            .delegations
            .contains_key(&Digest::hash(static_dlg).into())
            .await
        {
            return Ok(());
        }

        // NOTE: this is the only place this gets parsed and this verification ONLY happens here
        // TODO add a Verified<T> newtype wapper
        static_dlg.try_verify()?;

        let proof: Option<Arc<Signed<Delegation<S, T, L>>>> =
            if let Some(proof_hash) = static_dlg.payload().proof {
                let hash = proof_hash.into();
                Some(
                    self.delegations
                        .get(&hash)
                        .await
                        .ok_or(MissingDependency(hash))?,
                )
            } else {
                None
            };

        let delegate_id = static_dlg.payload().delegate;
        let delegate: Agent<S, T, L> = self
            .get_agent(delegate_id)
            .await
            .ok_or(ReceieveStaticDelegationError::UnknownAgent(delegate_id))?;

        let mut after_revocations = Vec::new();
        for static_rev_hash in static_dlg.payload().after_revocations.iter() {
            let rev_hash = static_rev_hash.into();
            let locked_revs = self.revocations.0.lock().await;
            let resolved_rev = locked_revs
                .get(&rev_hash)
                .ok_or(MissingDependency(rev_hash))?;
            after_revocations.push(resolved_rev.dupe());
        }

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
        let delegation = Arc::new(delegation);
        let mut found = false;
        {
            if let Some(group) = self.groups.lock().await.get(&GroupId(subject_id)) {
                found = true;
                group
                    .lock()
                    .await
                    .receive_delegation(delegation.clone())
                    .await?;
            } else if let Some(doc) = self.docs.lock().await.get(&DocumentId(subject_id)) {
                found = true;
                doc.lock()
                    .await
                    .receive_delegation(delegation.clone())
                    .await?;
            } else if let Some(indie) = self
                .individuals
                .lock()
                .await
                .remove(&IndividualId(subject_id))
            {
                found = true;
                self.promote_individual_to_group(indie, delegation.clone())
                    .await;
            }
        }
        if !found {
            let group = Group::new(
                GroupId(subject_id),
                delegation.dupe(),
                self.delegations.dupe(),
                self.revocations.dupe(),
                self.event_listener.clone(),
            )
            .await;

            if let Some(content_heads) = static_dlg
                .payload
                .after_content
                .get(&subject_id.into())
                .and_then(|content_heads| NonEmpty::collect(content_heads.iter().cloned()))
            {
                let doc = Document::from_group(group, content_heads).await?;
                let mut locked_docs = self.docs.lock().await;
                locked_docs.insert(doc.doc_id(), Arc::new(Mutex::new(doc)));
            } else {
                self.groups
                    .lock()
                    .await
                    .insert(group.group_id(), Arc::new(Mutex::new(group)));
            }
        };

        // FIXME remove because this is way too high in the stack
        // self.event_listener.on_delegation(&delegation).await;

        Ok(())
    }

    #[instrument(skip_all)]
    pub async fn receive_revocation(
        &self,
        static_rev: &Signed<StaticRevocation<T>>,
    ) -> Result<(), ReceieveStaticDelegationError<S, T, L>> {
        if self
            .revocations
            .contains_key(&Digest::hash(static_rev).into())
            .await
        {
            return Ok(());
        }

        // NOTE: this is the only place this gets parsed and this verification ONLY happens here
        static_rev.try_verify()?;

        let revoke_hash = static_rev.payload.revoke.into();
        let revoke: Arc<Signed<Delegation<S, T, L>>> = self
            .delegations
            .get(&revoke_hash)
            .await
            .ok_or(MissingDependency(revoke_hash))?;

        let proof: Option<Arc<Signed<Delegation<S, T, L>>>> =
            if let Some(proof_hash) = static_rev.payload().proof {
                let hash = proof_hash.into();
                Some(
                    self.delegations
                        .get(&hash)
                        .await
                        .ok_or(MissingDependency(hash))?,
                )
            } else {
                None
            };

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
        let revocation = Arc::new(revocation);
        if let Some(group) = self.groups.lock().await.get(&GroupId(id)) {
            group
                .lock()
                .await
                .receive_revocation(revocation.clone())
                .await?;
        } else if let Some(doc) = self.docs.lock().await.get(&DocumentId(id)) {
            doc.lock()
                .await
                .receive_revocation(revocation.clone())
                .await?;
        } else if let Some(indie) = self.individuals.lock().await.remove(&IndividualId(id)) {
            let group = self
                .promote_individual_to_group(indie, revocation.payload.revoke.dupe())
                .await;
            group
                .lock()
                .await
                .receive_revocation(revocation.clone())
                .await?;
        } else {
            let group = Arc::new(Mutex::new(
                Group::new(
                    GroupId(static_rev.issuer.into()),
                    revocation.payload.revoke.dupe(),
                    self.delegations.dupe(),
                    self.revocations.dupe(),
                    self.event_listener.clone(),
                )
                .await,
            ));

            {
                let group2 = group.dupe();
                let mut locked = group.lock().await;
                self.groups.lock().await.insert(locked.group_id(), group2);
                locked.receive_revocation(revocation.clone()).await?;
            }
        }

        Ok(())
    }

    #[instrument(skip_all)]
    pub async fn receive_static_event(
        &self,
        static_event: StaticEvent<T>,
    ) -> Result<(), ReceiveStaticEventError<S, T, L>> {
        match static_event {
            StaticEvent::PrekeysExpanded(add_op) => {
                self.receive_prekey_op(&Arc::new(*add_op).into()).await?
            }
            StaticEvent::PrekeyRotated(rot_op) => {
                self.receive_prekey_op(&Arc::new(*rot_op).into()).await?
            }
            StaticEvent::CgkaOperation(cgka_op) => self.receive_cgka_op(*cgka_op).await?,
            StaticEvent::Delegated(dlg) => self.receive_delegation(&dlg).await?,
            StaticEvent::Revoked(rev) => self.receive_revocation(&rev).await?,
        }
        Ok(())
    }

    #[instrument(skip_all)]
    pub async fn receive_membership_op(
        &self,
        static_op: &StaticMembershipOperation<T>,
    ) -> Result<(), ReceieveStaticDelegationError<S, T, L>> {
        match static_op {
            StaticMembershipOperation::Delegation(d) => self.receive_delegation(d).await?,
            StaticMembershipOperation::Revocation(r) => self.receive_revocation(r).await?,
        }
        Ok(())
    }

    #[instrument(skip_all)]
    pub async fn receive_cgka_op(
        &self,
        signed_op: Signed<CgkaOperation>,
    ) -> Result<(), ReceiveCgkaOpError> {
        signed_op.try_verify()?;

        let doc_id = signed_op.payload.doc_id();
        let doc = {
            let locked_docs = self.docs.lock().await;
            locked_docs
                .get(doc_id)
                .ok_or(ReceiveCgkaOpError::UnknownDocument(*doc_id))?
                .dupe()
        };

        let signed_op = Arc::new(signed_op);
        if let CgkaOperation::Add { added_id, pk, .. } = signed_op.payload {
            let locked_active = self.active.lock().await;
            let active_id = locked_active.id();
            if active_id == added_id {
                let sk = {
                    locked_active
                        .prekey_pairs
                        .get(&pk)
                        .ok_or(ReceiveCgkaOpError::UnknownInvitePrekey(pk))?
                };
                doc.lock()
                    .await
                    .merge_cgka_invite_op(signed_op.clone(), sk)?;
                self.event_listener.on_cgka_op(&signed_op).await;
                return Ok(());
            } else if Public.individual().id() == added_id {
                let sk = Public.share_secret_key();
                doc.lock()
                    .await
                    .merge_cgka_invite_op(signed_op.clone(), &sk)?;
                self.event_listener.on_cgka_op(&signed_op).await;
                return Ok(());
            }
        }
        doc.lock().await.merge_cgka_op(signed_op.clone())?;
        self.event_listener.on_cgka_op(&signed_op).await;
        Ok(())
    }

    #[instrument(skip_all)]
    pub async fn promote_individual_to_group(
        &self,
        individual: Arc<Mutex<Individual>>,
        head: Arc<Signed<Delegation<S, T, L>>>,
    ) -> Arc<Mutex<Group<S, T, L>>> {
        let indie = individual.lock().await.clone();
        let group = Arc::new(Mutex::new(
            Group::from_individual(
                indie,
                head,
                self.delegations.dupe(),
                self.revocations.dupe(),
                self.event_listener.clone(),
            )
            .await,
        ));

        let agent = Agent::Group(group.lock().await.group_id(), group.dupe());

        {
            let mut locked_delegations = self.delegations.0.lock().await;
            for (digest, dlg) in locked_delegations.clone().iter() {
                if dlg.payload.delegate == agent {
                    locked_delegations.0.insert(
                        *digest,
                        Arc::new(Signed {
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
        }

        {
            let group_id = group.lock().await.id();
            let mut locked_revocations = self.revocations.0.lock().await;
            for (digest, rev) in locked_revocations.clone().iter() {
                if rev.payload.subject_id() == group_id {
                    locked_revocations.0.insert(
                        *digest,
                        Arc::new(Signed {
                            issuer: rev.issuer,
                            signature: rev.signature,
                            payload: Revocation {
                                revoke: self
                                    .delegations
                                    .get(&Digest::hash(&rev.payload.revoke))
                                    .await
                                    .expect("revoked delegation to be available")
                                    .dupe(),
                                proof: if let Some(proof) = rev.payload.proof.dupe() {
                                    self.delegations.get(&Digest::hash(&proof)).await
                                } else {
                                    panic!("revoked delegation to be available");
                                },
                                after_content: rev.payload.after_content.clone(),
                            },
                        }),
                    );
                }
            }
        }

        group
    }

    #[instrument(skip_all)]
    pub async fn into_archive(&self) -> Archive<T> {
        let active = { self.active.lock().await.into_archive() };

        let topsorted_ops = {
            let delegations = self.delegations.0.lock().await;
            let revocations = self.revocations.0.lock().await;
            MembershipOperation::<S, T, L>::topsort(&delegations, &revocations)
                .into_iter()
                .map(|(k, v)| (k.into(), v.into()))
                .collect()
        };

        let mut individuals = HashMap::new();
        {
            let locked_individuals = self.individuals.lock().await;
            for (k, arc) in locked_individuals.iter() {
                individuals.insert(*k, arc.lock().await.clone());
            }
        }

        let mut groups = HashMap::new();
        {
            let locked_groups = self.groups.lock().await;
            for (k, arc) in locked_groups.iter() {
                groups.insert(*k, arc.lock().await.into_archive());
            }
        }

        let mut docs = HashMap::new();
        {
            let locked_docs = self.docs.lock().await;
            for (k, arc) in locked_docs.iter() {
                docs.insert(*k, arc.lock().await.into_archive());
            }
        }

        Archive {
            active,
            topsorted_ops,
            individuals,
            groups,
            docs,
        }
    }

    #[instrument(skip_all)]
    pub async fn try_from_archive(
        archive: &Archive<T>,
        signer: S,
        ciphertext_store: C,
        listener: L,
        csprng: Arc<Mutex<R>>,
    ) -> Result<Self, TryFromArchiveError<S, T, L>> {
        let active = Arc::new(Mutex::new(Active::from_archive(
            &archive.active,
            signer,
            listener.clone(),
        )));

        let delegations: DelegationStore<S, T, L> = DelegationStore::new();
        let revocations: RevocationStore<S, T, L> = RevocationStore::new();

        let mut individuals = HashMap::new();
        for (k, v) in archive.individuals.iter() {
            individuals.insert(*k, Arc::new(Mutex::new(v.clone())));
        }

        let mut groups = HashMap::new();
        for (group_id, group_archive) in archive.groups.iter() {
            groups.insert(
                *group_id,
                Arc::new(Mutex::new(Group::<S, T, L>::dummy_from_archive(
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
                Arc::new(Mutex::new(Document::<S, T, L>::dummy_from_archive(
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
                    let proof: Option<Arc<Signed<Delegation<S, T, L>>>> =
                        if let Some(proof_digest) = sd.payload.proof {
                            Some(delegations.get(&proof_digest.into()).await.ok_or(
                                TryFromArchiveError::MissingDelegation(proof_digest.into()),
                            )?)
                        } else {
                            None
                        };

                    let mut after_revocations = vec![];
                    for rev_digest in sd.payload.after_revocations.iter() {
                        let r: Arc<Signed<Revocation<S, T, L>>> = revocations
                            .get(&rev_digest.into())
                            .await
                            .ok_or(TryFromArchiveError::MissingRevocation(rev_digest.into()))?
                            .dupe();

                        after_revocations.push(r);
                    }

                    let id = sd.payload.delegate;
                    let delegate: Agent<S, T, L> = if id == archive.active.individual.id().into() {
                        Agent::Active(id.into(), active.dupe())
                    } else {
                        individuals
                            .get(&IndividualId(id))
                            .map(|i| Agent::Individual(id.into(), i.dupe()))
                            .or_else(|| {
                                groups
                                    .get(&GroupId(id))
                                    .map(|g| Agent::Group(id.into(), g.dupe()))
                            })
                            .or_else(|| {
                                docs.get(&DocumentId(id))
                                    .map(|d| Agent::Document(id.into(), d.dupe()))
                            })
                            .ok_or(TryFromArchiveError::MissingAgent(Box::new(id)))?
                    };

                    // NOTE Manually pushing; skipping various steps intentionally
                    delegations.0.lock().await.0.insert(
                        (*digest).into(),
                        Arc::new(Signed {
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
                    let revoke = delegations.get(&sr.payload.revoke.into()).await.ok_or(
                        TryFromArchiveError::MissingDelegation(sr.payload.revoke.into()),
                    )?;

                    let proof =
                        if let Some(proof_digest) = sr.payload.proof {
                            Some(delegations.get(&proof_digest.into()).await.ok_or(
                                TryFromArchiveError::MissingDelegation(proof_digest.into()),
                            )?)
                        } else {
                            None
                        };

                    revocations.0.lock().await.0.insert(
                        (*digest).into(),
                        Arc::new(Signed {
                            issuer: sr.issuer,
                            signature: sr.signature,
                            payload: Revocation {
                                revoke,
                                proof,
                                after_content: sr.payload.after_content.clone(),
                            },
                        }),
                    );
                }
            };
        }

        #[allow(clippy::type_complexity)]
        async fn reify_ops<Z: AsyncSigner, U: ContentRef, M: MembershipListener<Z, U>>(
            group: &mut Group<Z, U, M>,
            dlg_store: DelegationStore<Z, U, M>,
            rev_store: RevocationStore<Z, U, M>,
            dlg_head_hashes: &HashSet<Digest<Signed<StaticDelegation<U>>>>,
            rev_head_hashes: &HashSet<Digest<Signed<StaticRevocation<U>>>>,
            members: HashMap<Identifier, NonEmpty<Digest<Signed<Delegation<Z, U, M>>>>>,
        ) -> Result<(), TryFromArchiveError<Z, U, M>> {
            let read_dlgs = dlg_store.0.lock().await;
            let read_revs = rev_store.0.lock().await;

            for dlg_hash in dlg_head_hashes.iter() {
                let actual_dlg: Arc<Signed<Delegation<Z, U, M>>> = read_dlgs
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
                let mut proofs = Vec::new();
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

            let mut locked_group = group.lock().await;
            reify_ops(
                &mut locked_group,
                delegations.dupe(),
                revocations.dupe(),
                &group_archive.state.delegation_heads,
                &group_archive.state.revocation_heads,
                group_archive
                    .members
                    .iter()
                    .map(|(k, v)| (*k, v.clone().map(|x| x.into())))
                    .collect(),
            )
            .await?;
        }

        for (doc_id, doc) in docs.iter() {
            let doc_archive = archive
                .docs
                .get(doc_id)
                .ok_or(TryFromArchiveError::MissingDocument(Box::new(*doc_id)))?;

            let mut locked_doc = doc.lock().await;
            reify_ops(
                &mut locked_doc.group,
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
            )
            .await?;
        }

        Ok(Self {
            verifying_key: archive.active.individual.verifying_key(),
            active,
            individuals: Arc::new(Mutex::new(individuals)),
            groups: Arc::new(Mutex::new(groups)),
            docs: Arc::new(Mutex::new(docs)),
            delegations,
            revocations,
            csprng,
            ciphertext_store,
            event_listener: listener,
            _plaintext_phantom: PhantomData,
        })
    }

    #[cfg(any(test, feature = "ingest_static"))]
    #[instrument(level = "trace", skip_all)]
    pub async fn ingest_archive(
        &self,
        archive: Archive<T>,
    ) -> Result<(), ReceiveStaticEventError<S, T, L>> {
        {
            let mut locked = self.active.lock().await;
            locked.prekey_pairs.extend(archive.active.prekey_pairs);
            locked.individual.merge(archive.active.individual);
        }
        for (id, indie) in archive.individuals {
            let mut locked_indies = self.individuals.lock().await;
            if let Some(our_indie) = locked_indies.get_mut(&id) {
                our_indie.merge_async(indie).await;
            } else {
                locked_indies.insert(id, Arc::new(Mutex::new(indie)));
            }
        }
        let events = archive
            .topsorted_ops
            .into_iter()
            .map(|(_, op)| match op {
                StaticMembershipOperation::Delegation(signed) => StaticEvent::Delegated(signed),
                StaticMembershipOperation::Revocation(signed) => StaticEvent::Revoked(signed),
            })
            .collect::<Vec<_>>();
        self.ingest_unsorted_static_events(events).await?;
        Ok(())
    }

    #[instrument(skip_all)]
    pub fn event_listener(&self) -> &L {
        &self.event_listener
    }

    #[cfg(any(test, feature = "ingest_static"))]
    #[instrument(level = "trace", skip_all)]
    pub async fn ingest_unsorted_static_events(
        &self,
        events: Vec<StaticEvent<T>>,
    ) -> Result<(), ReceiveStaticEventError<S, T, L>> {
        let mut epoch = events;

        loop {
            let mut next_epoch = vec![];
            let mut err = None;
            let epoch_len = epoch.len();

            for event in epoch {
                if let Err(e) = self.receive_static_event(event.clone()).await {
                    err = Some(e);
                    next_epoch.push(event);
                }
            }

            if next_epoch.is_empty() {
                tracing::debug!("Finished ingesting static events");
                return Ok(());
            }

            if next_epoch.len() == epoch_len {
                // Stuck on a fixed point
                tracing::warn!("Fixed point while ingesting static events");
                return Err(err.unwrap());
            }

            epoch = next_epoch
        }
    }

    #[allow(clippy::type_complexity)]
    #[cfg(any(test, feature = "test_utils"))]
    #[instrument(level = "trace", skip_all)]
    pub async fn ingest_event_table(
        &self,
        events: HashMap<Digest<Event<S, T, L>>, Event<S, T, L>>,
    ) -> Result<(), ReceiveStaticEventError<S, T, L>> {
        self.ingest_unsorted_static_events(
            events.values().cloned().map(Into::into).collect::<Vec<_>>(),
        )
        .await
    }
}

impl<
        S: AsyncSigner + Clone,
        T: ContentRef + Debug,
        P: for<'de> Deserialize<'de>,
        C: CiphertextStore<T, P> + Clone,
        L: MembershipListener<S, T>,
        R: rand::CryptoRng + rand::RngCore,
    > Debug for Keyhive<S, T, P, C, L, R>
{
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
        f.debug_struct("Keyhive")
            .field("active", &self.active)
            .field("individuals", &self.individuals)
            .field("groups", &self.groups)
            .field("docs", &self.docs)
            .field("delegations", &self.delegations)
            .field("revocations", &self.revocations)
            .field("ciphertext_store", &"<STORE>")
            .field("csprng", &"<CSPRNG>")
            .finish()
    }
}

impl<
        S: AsyncSigner + Clone,
        T: ContentRef + Clone,
        P: for<'de> Deserialize<'de> + Clone,
        C: CiphertextStore<T, P> + Clone,
        L: MembershipListener<S, T>,
        R: rand::CryptoRng + rand::RngCore + Clone,
    > ForkAsync for Keyhive<S, T, P, C, L, R>
{
    type AsyncForked = Keyhive<S, T, P, C, Log<S, T>, R>;

    async fn fork_async(&self) -> Self::AsyncForked {
        // TODO this is probably fairly slow, and due to the logger type changing
        let signer = { self.active.lock().await.signer.clone() };
        Keyhive::try_from_archive(
            &self.into_archive().await,
            signer,
            self.ciphertext_store.clone(),
            Log::new(),
            self.csprng.clone(),
        )
        .await
        .expect("local round trip to work")
    }
}

impl<
        S: AsyncSigner + Clone,
        T: ContentRef + Clone,
        P: for<'de> Deserialize<'de> + Clone,
        C: CiphertextStore<T, P> + Clone,
        L: MembershipListener<S, T>,
        R: rand::CryptoRng + rand::RngCore + Clone,
    > MergeAsync for Arc<Mutex<Keyhive<S, T, P, C, L, R>>>
{
    async fn merge_async(&self, fork: Self::AsyncForked) {
        let locked = self.lock().await;
        locked
            .active
            .lock()
            .await
            .merge(fork.active.lock().await.clone());

        {
            let mut locked_fork_indies = fork.individuals.lock().await;
            let mut locked_indies = locked.individuals.lock().await;
            for (id, forked_indie) in locked_fork_indies.drain() {
                if let Some(og_indie) = locked_indies.get(&id) {
                    og_indie
                        .lock()
                        .await
                        .merge(forked_indie.lock().await.clone())
                } else {
                    locked_indies.insert(id, forked_indie);
                }
            }
        }

        let forked_listener = { fork.event_listener.0.lock().await.clone() };
        for event in forked_listener.iter() {
            match event {
                Event::PrekeysExpanded(_add_op) => {
                    continue; // NOTE: handled above
                }
                Event::PrekeyRotated(_rot_op) => {
                    continue; // NOTE: handled above
                }
                _ => {}
            }

            locked
                .receive_static_event(event.clone().into())
                .await
                .expect("prechecked events to work");
        }
    }
}

impl<
        S: AsyncSigner + Clone,
        T: ContentRef,
        P: for<'de> Deserialize<'de>,
        C: CiphertextStore<T, P> + Clone,
        L: MembershipListener<S, T>,
        R: rand::CryptoRng + rand::RngCore,
    > Verifiable for Keyhive<S, T, P, C, L, R>
{
    fn verifying_key(&self) -> ed25519_dalek::VerifyingKey {
        self.verifying_key
    }
}

#[derive(Error)]
#[derive_where(Debug; T)]
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

#[derive(Error)]
#[derive_where(Debug; T)]
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
        access::Access, crypto::signer::memory::MemorySigner, principal::public::Public,
        transact::transact_async,
    };
    use nonempty::nonempty;
    use pretty_assertions::assert_eq;
    use testresult::TestResult;

    async fn make_keyhive() -> Keyhive<
        MemorySigner,
        [u8; 32],
        Vec<u8>,
        Arc<Mutex<MemoryCiphertextStore<[u8; 32], Vec<u8>>>>,
        NoListener,
    > {
        let sk = MemorySigner::generate(&mut rand::rngs::OsRng);
        let store: MemoryCiphertextStore<[u8; 32], Vec<u8>> = MemoryCiphertextStore::new();
        Keyhive::generate(
            sk,
            Arc::new(Mutex::new(store)),
            NoListener,
            rand::rngs::OsRng,
        )
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn test_archival_round_trip() -> TestResult {
        test_utils::init_logging();

        let mut csprng = rand::rngs::OsRng;

        let sk = MemorySigner::generate(&mut csprng);
        let store = Arc::new(Mutex::new(MemoryCiphertextStore::<[u8; 32], String>::new()));
        let hive =
            Keyhive::generate(sk.clone(), store.clone(), NoListener, rand::rngs::OsRng).await?;

        let indie_sk = MemorySigner::generate(&mut csprng);
        let indie = Arc::new(Mutex::new(
            Individual::generate(&indie_sk, &mut csprng).await?,
        ));
        let indie_peer = Peer::Individual(indie.lock().await.id(), indie.dupe());

        hive.register_individual(indie.dupe()).await;
        hive.generate_group(vec![indie_peer.dupe()]).await?;
        hive.generate_doc(vec![indie_peer.dupe()], nonempty![[1u8; 32], [2u8; 32]])
            .await?;

        assert!(!hive.active.lock().await.prekey_pairs.is_empty());
        assert_eq!(hive.individuals.lock().await.len(), 2);
        assert_eq!(hive.groups.lock().await.len(), 1);
        assert_eq!(hive.docs.lock().await.len(), 1);
        assert_eq!(hive.delegations.0.lock().await.len(), 4);
        assert_eq!(hive.revocations.0.lock().await.len(), 0);

        let archive = hive.into_archive().await;

        assert_eq!(hive.id(), archive.id());
        assert_eq!(archive.individuals.len(), 2);
        assert_eq!(archive.groups.len(), 1);
        assert_eq!(archive.docs.len(), 1);
        assert_eq!(archive.topsorted_ops.len(), 4);

        let hive_from_archive = Keyhive::try_from_archive(
            &archive,
            sk,
            store,
            NoListener,
            Arc::new(Mutex::new(rand::rngs::OsRng)),
        )
        .await
        .unwrap();

        assert_eq!(
            hive.delegations.0.lock().await.len(),
            hive_from_archive.delegations.0.lock().await.len()
        );

        assert_eq!(
            hive.revocations.0.lock().await.len(),
            hive_from_archive.revocations.0.lock().await.len()
        );

        assert_eq!(
            hive.individuals.lock().await.len(),
            hive_from_archive.individuals.lock().await.len()
        );
        assert_eq!(
            hive.groups.lock().await.len(),
            hive_from_archive.groups.lock().await.len()
        );
        assert_eq!(
            hive.docs.lock().await.len(),
            hive_from_archive.docs.lock().await.len()
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_receive_delegations_associately() {
        test_utils::init_logging();

        let hive1 = make_keyhive().await;
        let hive2 = make_keyhive().await;

        let hive2_on_hive1 = Arc::new(Mutex::new(hive2.active.lock().await.individual.clone()));
        hive1.register_individual(hive2_on_hive1.dupe()).await;
        let hive1_on_hive2 = Arc::new(Mutex::new(hive1.active.lock().await.individual.clone()));
        hive2.register_individual(hive1_on_hive2.dupe()).await;
        let group1_on_hive1 = hive1
            .generate_group(vec![Peer::Individual(
                hive2_on_hive1.lock().await.id(),
                hive2_on_hive1.dupe(),
            )])
            .await
            .unwrap();

        assert_eq!(hive1.delegations.0.lock().await.len(), 2);
        assert_eq!(hive1.revocations.0.lock().await.len(), 0);
        assert_eq!(hive1.individuals.lock().await.len(), 2); // NOTE: knows about Public and Hive2
        assert_eq!(hive1.groups.lock().await.len(), 1);
        assert_eq!(hive1.docs.lock().await.len(), 0);

        {
            let locked_group1_on_hive1 = group1_on_hive1.lock().await;
            assert_eq!(locked_group1_on_hive1.delegation_heads().len(), 2);
            assert_eq!(locked_group1_on_hive1.revocation_heads().len(), 0);

            for dlg in locked_group1_on_hive1.delegation_heads().values() {
                assert_eq!(dlg.subject_id(), locked_group1_on_hive1.group_id().into());

                let delegate_id = dlg.payload.delegate.dupe().agent_id();
                assert!(
                    delegate_id == hive1.agent_id().await || delegate_id == hive2.agent_id().await
                );
            }

            assert_eq!(hive2.delegations.0.lock().await.len(), 0);
            assert_eq!(hive2.revocations.0.lock().await.len(), 0);
            assert_eq!(hive2.individuals.lock().await.len(), 2);
            assert_eq!(hive2.groups.lock().await.len(), 0);
            assert_eq!(hive2.docs.lock().await.len(), 0);

            let heads = locked_group1_on_hive1.delegation_heads().clone();
            for dlg in heads.values() {
                let static_dlg = dlg.as_ref().clone().map(|d| d.into()); // TODO add From instance
                hive2.receive_delegation(&static_dlg).await.unwrap();
            }
        }

        assert_eq!(hive2.delegations.0.lock().await.len(), 2);
        assert_eq!(hive2.revocations.0.lock().await.len(), 0);
        assert_eq!(hive2.individuals.lock().await.len(), 2); // NOTE: Public and Hive2
        assert_eq!(hive2.groups.lock().await.len(), 1);
        assert_eq!(hive2.docs.lock().await.len(), 0);
    }

    #[tokio::test]
    async fn test_transitive_ops_for_agent() {
        test_utils::init_logging();

        let left = make_keyhive().await;
        let middle = make_keyhive().await;
        let right = make_keyhive().await;

        // 2 delegations (you & public)
        let left_doc = left
            .generate_doc(
                vec![Peer::Individual(
                    Public.individual().id(),
                    Arc::new(Mutex::new(Public.individual())),
                )],
                nonempty![[0u8; 32]],
            )
            .await
            .unwrap();
        // 1 delegation (you)
        let left_group = left.generate_group(vec![]).await.unwrap();

        assert_eq!(left.delegations.0.lock().await.len(), 3);
        assert_eq!(left.revocations.0.lock().await.len(), 0);

        assert_eq!(left.individuals.lock().await.len(), 1);
        assert!(left
            .individuals
            .lock()
            .await
            .contains_key(&IndividualId(Public.id())));

        assert_eq!(left.groups.lock().await.len(), 1);
        assert_eq!(left.docs.lock().await.len(), 1);

        assert!(left
            .docs
            .lock()
            .await
            .contains_key(&left_doc.lock().await.doc_id()));
        assert!(left
            .groups
            .lock()
            .await
            .contains_key(&left_group.lock().await.group_id()));

        // NOTE: *NOT* the group
        let left_membered = left
            .membered_reachable_by_agent(&Public.individual().into())
            .await;

        assert_eq!(left_membered.len(), 1);
        assert!(left_membered.contains_key(&left_doc.lock().await.doc_id().into()));
        assert!(!left_membered.contains_key(&left_group.lock().await.group_id().into())); // NOTE *not* included because Public is not a member

        let left_to_mid_ops = left
            .events_for_agent(&Public.individual().into())
            .await
            .unwrap();
        assert_eq!(left_to_mid_ops.len(), 14);

        middle.ingest_event_table(left_to_mid_ops).await.unwrap();

        // Left unchanged
        assert_eq!(left.groups.lock().await.len(), 1);
        assert_eq!(left.docs.lock().await.len(), 1);
        assert_eq!(left.delegations.0.lock().await.len(), 3);
        assert_eq!(left.revocations.0.lock().await.len(), 0);

        // Middle should now look the same
        assert!(middle
            .docs
            .lock()
            .await
            .contains_key(&left_doc.lock().await.doc_id()));
        assert!(!middle
            .groups
            .lock()
            .await
            .contains_key(&left_group.lock().await.group_id())); // NOTE: *None*

        assert_eq!(middle.individuals.lock().await.len(), 2); // NOTE: includes Left
        assert_eq!(middle.groups.lock().await.len(), 0);
        assert_eq!(middle.docs.lock().await.len(), 1);

        assert_eq!(middle.revocations.0.lock().await.len(), 0);
        assert_eq!(middle.delegations.0.lock().await.len(), 2);
        let left_doc_id = left_doc.lock().await.doc_id();
        assert_eq!(
            middle
                .docs
                .lock()
                .await
                .get(&left_doc_id)
                .unwrap()
                .lock()
                .await
                .delegation_heads()
                .len(),
            2
        );

        let mid_to_right_ops = middle
            .events_for_agent(&Public.individual().into())
            .await
            .unwrap();
        assert_eq!(mid_to_right_ops.len(), 21);

        right.ingest_event_table(mid_to_right_ops).await.unwrap();

        // Left unchanged
        assert_eq!(left.groups.lock().await.len(), 1);
        assert_eq!(left.docs.lock().await.len(), 1);
        assert_eq!(left.delegations.0.lock().await.0.len(), 3);
        assert_eq!(left.revocations.0.lock().await.0.len(), 0);

        // Middle unchanged
        assert_eq!(middle.individuals.lock().await.len(), 2);
        assert_eq!(middle.groups.lock().await.len(), 0);
        assert_eq!(middle.docs.lock().await.len(), 1);

        assert_eq!(middle.delegations.0.lock().await.len(), 2);
        assert_eq!(middle.revocations.0.lock().await.len(), 0);

        // Right should now look the same
        assert_eq!(right.revocations.0.lock().await.len(), 0);
        assert_eq!(right.delegations.0.lock().await.len(), 2);

        assert!(right.groups.lock().await.len() == 1 || right.docs.lock().await.len() == 1);
        assert!(right
            .docs
            .lock()
            .await
            .contains_key(&DocumentId(left_doc.lock().await.id())));
        assert!(!right
            .groups
            .lock()
            .await
            .contains_key(&left_group.lock().await.group_id())); // NOTE: *None*

        assert_eq!(right.individuals.lock().await.len(), 3);
        assert_eq!(right.groups.lock().await.len(), 0);
        assert_eq!(right.docs.lock().await.len(), 1);

        assert_eq!(
            middle
                .events_for_agent(&Public.individual().into())
                .await
                .unwrap()
                .iter()
                .collect::<Vec<_>>()
                .sort_by_key(|(k, _v)| **k),
            right
                .events_for_agent(&Public.individual().into())
                .await
                .unwrap()
                .iter()
                .collect::<Vec<_>>()
                .sort_by_key(|(k, _v)| **k),
        );

        right
            .generate_group(vec![Peer::Document(
                left_doc.lock().await.doc_id(),
                left_doc.dupe(),
            )])
            .await
            .unwrap();

        // Check transitivity
        let transitive_right_to_mid_ops = right
            .events_for_agent(&Public.individual().into())
            .await
            .unwrap();
        assert_eq!(transitive_right_to_mid_ops.len(), 23);

        middle
            .ingest_event_table(transitive_right_to_mid_ops)
            .await
            .unwrap();

        assert_eq!(middle.individuals.lock().await.len(), 3); // NOTE now includes Right
        assert_eq!(middle.groups.lock().await.len(), 1);
        assert_eq!(middle.docs.lock().await.len(), 1);
        assert_eq!(middle.delegations.0.lock().await.len(), 4);
    }

    #[tokio::test]
    async fn test_add_member() {
        test_utils::init_logging();

        let keyhive = make_keyhive().await;
        let doc = keyhive
            .generate_doc(
                vec![Peer::Individual(
                    Public.individual().id(),
                    Arc::new(Mutex::new(Public.individual())),
                )],
                nonempty![[0u8; 32]],
            )
            .await
            .unwrap();
        let member = Public.individual().into();
        let membered = Membered::Document(doc.lock().await.doc_id(), doc.dupe());
        let dlg = keyhive
            .add_member(member, &membered, Access::Read, &[])
            .await
            .unwrap();

        assert_eq!(
            dlg.delegation.subject_id(),
            doc.lock().await.doc_id().into()
        );
    }

    #[tokio::test]
    async fn receiving_an_event_with_added_or_rotated_prekeys_works() {
        test_utils::init_logging();

        let alice = make_keyhive().await;
        let bob = make_keyhive().await;

        let doc = alice
            .generate_doc(vec![], nonempty![[0u8; 32]])
            .await
            .unwrap();

        // Create a new prekey op by expanding prekeys on bob
        let add_bob_op = bob.expand_prekeys().await.unwrap();

        // Now add bob to alices document using the new op
        let add_op = KeyOp::Add(add_bob_op);
        let bob_on_alice = Arc::new(Mutex::new(Individual::new(add_op.dupe())));
        assert!(alice.register_individual(bob_on_alice.clone()).await);
        let bob_on_alice_id = { bob_on_alice.lock().await.id() };
        let doc_id = { doc.lock().await.doc_id() };
        alice
            .add_member(
                Agent::Individual(bob_on_alice_id, bob_on_alice.dupe()),
                &Membered::Document(doc_id, doc.dupe()),
                Access::Read,
                &[],
            )
            .await
            .unwrap();

        // Now receive alices events
        let events = alice
            .events_for_agent(&Agent::Individual(bob_on_alice_id, bob_on_alice.dupe()))
            .await
            .unwrap();

        // ensure that we are able to process the add op
        bob.ingest_event_table(events).await.unwrap();

        // Now create a new prekey op by rotating on bob
        let rotate_op = bob.rotate_prekey(*add_op.new_key()).await.unwrap();

        // Create a new document (on a new keyhive) and share it with bob using the rotated key
        let charlie = make_keyhive().await;
        let doc2 = charlie
            .generate_doc(vec![], nonempty![[1u8; 32]])
            .await
            .unwrap();
        let bob_on_charlie = Arc::new(Mutex::new(Individual::new(KeyOp::Rotate(rotate_op))));
        assert!(charlie.register_individual(bob_on_charlie.clone()).await);
        let bob_on_charlie_id = { bob_on_charlie.lock().await.id() };
        let doc2_id = { doc2.lock().await.doc_id() };
        charlie
            .add_member(
                Agent::Individual(bob_on_charlie_id, bob_on_charlie.dupe()),
                &Membered::Document(doc2_id, doc2.dupe()),
                Access::Read,
                &[],
            )
            .await
            .unwrap();

        let events = charlie
            .events_for_agent(&Agent::Individual(bob_on_charlie_id, bob_on_charlie.dupe()))
            .await
            .unwrap();

        bob.ingest_event_table(events).await.unwrap();
    }

    #[tokio::test]
    async fn test_async_transaction() -> TestResult {
        test_utils::init_logging();

        let sk = MemorySigner::generate(&mut rand::rngs::OsRng);
        let hive = Keyhive::<_, [u8; 32], Vec<u8>, _, NoListener, _>::generate(
            sk,
            Arc::new(Mutex::new(MemoryCiphertextStore::new())),
            NoListener,
            rand::rngs::OsRng,
        )
        .await?;

        let trunk = Arc::new(Mutex::new(hive));

        let alice_indie = Individual::generate(
            &MemorySigner::generate(&mut rand::rngs::OsRng),
            &mut rand::rngs::OsRng,
        )
        .await?;

        let alice: Peer<MemorySigner, [u8; 32], NoListener> =
            Peer::Individual(alice_indie.id(), Arc::new(Mutex::new(alice_indie)));

        {
            let locked_trunk = trunk.lock().await;
            locked_trunk
                .generate_doc(vec![alice.dupe()], nonempty![[0u8; 32]])
                .await?;

            locked_trunk.generate_group(vec![alice.dupe()]).await?;

            assert_eq!(locked_trunk.active.lock().await.prekey_pairs.len(), 7);
            assert_eq!(locked_trunk.delegations.0.lock().await.len(), 4);
            assert_eq!(locked_trunk.groups.lock().await.len(), 1);
            assert_eq!(locked_trunk.docs.lock().await.len(), 1);
        }

        let tx = transact_async(
            &trunk,
            |fork: Keyhive<_, _, _, _, Log<_, [u8; 32]>, _>| async move {
                // Depending on when the async runs
                let init_dlg_count = fork.delegations.0.lock().await.len();
                assert!(init_dlg_count >= 4);
                assert!(init_dlg_count <= 6);

                // Depending on when the async runs
                let init_doc_count = fork.docs.lock().await.len();
                assert!(init_doc_count == 1 || init_doc_count == 2);

                // Only one before this gets awaited
                let init_group_count = fork.groups.lock().await.len();
                assert_eq!(init_group_count, 1);

                assert_eq!(fork.active.lock().await.prekey_pairs.len(), 7);
                fork.expand_prekeys().await.unwrap(); // 1 event (prekey)
                assert_eq!(fork.active.lock().await.prekey_pairs.len(), 8);

                let bob_indie = Individual::generate(
                    &MemorySigner::generate(&mut rand::rngs::OsRng),
                    &mut rand::rngs::OsRng,
                )
                .await
                .unwrap();

                let bob: Peer<MemorySigner, [u8; 32], Log<MemorySigner>> =
                    Peer::Individual(bob_indie.id(), Arc::new(Mutex::new(bob_indie)));

                fork.generate_group(vec![bob.dupe()]).await.unwrap(); // 2 events (dlgs)
                fork.generate_group(vec![bob.dupe()]).await.unwrap(); // 2 events (dlgs)
                fork.generate_group(vec![bob.dupe()]).await.unwrap(); // 2 events (dlgs)
                assert_eq!(fork.groups.lock().await.len(), 4);

                // 2 events (dlgs)
                fork.generate_doc(vec![bob], nonempty![[1u8; 32]])
                    .await
                    .unwrap();
                assert_eq!(fork.docs.lock().await.len(), init_doc_count + 1);

                let mut dlg_count = 0;
                let mut cgka_count = 0;
                let mut prekey_expanded_count = 0;
                for op in fork.event_listener().0.lock().await.iter() {
                    match op {
                        Event::PrekeysExpanded(_) => {
                            prekey_expanded_count += 1;
                        }
                        Event::PrekeyRotated(_) => {
                            panic!("unexpected prekey rotation passed to listener")
                        }
                        Event::CgkaOperation(_) => {
                            cgka_count += 1;
                        }
                        Event::Delegated(_) => {
                            dlg_count += 1;
                        }
                        Event::Revoked(_) => {
                            panic!("unexpected revocation passed to listener")
                        }
                    }
                }
                assert_eq!(dlg_count, 8);
                assert_eq!(cgka_count, 4);
                assert_eq!(prekey_expanded_count, 1);
                Ok::<_, String>(fork)
            },
        )
        .await;

        {
            let locked_trunk = trunk.lock().await;
            locked_trunk
                .generate_doc(vec![alice.dupe()], nonempty![[2u8; 32]])
                .await
                .unwrap();

            assert!(!locked_trunk.docs.lock().await.is_empty());
            assert!(locked_trunk.docs.lock().await.len() <= 3);

            // FIXME add transact right on Keyhive taht aslo dispatches new events
            let () = tx?;

            // tx is done, so should be all caught up. Counts are now certain.
            assert_eq!(locked_trunk.active.lock().await.prekey_pairs.len(), 8);
            assert_eq!(locked_trunk.docs.lock().await.len(), 3);
            assert_eq!(locked_trunk.groups.lock().await.len(), 4);

            locked_trunk
                .generate_doc(vec![alice.dupe()], nonempty![[3u8; 32]])
                .await
                .unwrap();

            assert_eq!(locked_trunk.docs.lock().await.len(), 4);
        }

        Ok(())
    }
}
