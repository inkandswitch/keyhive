//! The primary API for the library.

use crate::{
    ability::Ability,
    access::Access,
    archive::Archive,
    contact_card::ContactCard,
    crypto::signed_ext::{SignedId, SignedSubjectId},
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
    stats::Stats,
    store::{
        ciphertext::{memory::MemoryCiphertextStore, CausalDecryptionState, CiphertextStore},
        delegation::DelegationStore,
        revocation::RevocationStore,
    },
    transact::{
        fork::ForkAsync,
        merge::{Merge, MergeAsync},
    },
    util::content_addressed_map::CaMap,
};
use beekem::{encrypted::EncryptedContent, error::CgkaError, operation::CgkaOperation};
use derive_where::derive_where;
use dupe::{Dupe, OptionDupedExt};
use futures::lock::Mutex;
use keyhive_crypto::{
    content::reference::ContentRef,
    digest::Digest,
    share_key::ShareKey,
    signed::{Signed, SigningError, VerificationError},
    signer::async_signer::AsyncSigner,
    verifiable::Verifiable,
};
use nonempty::NonEmpty;
use serde::{Deserialize, Serialize};
use std::{
    collections::{hash_map::Entry, BTreeMap, HashMap, HashSet},
    fmt::{Debug, Formatter},
    marker::PhantomData,
    mem,
    sync::Arc,
};
use thiserror::Error;
use tracing::instrument;

type MembershipOpMap<S, T, L> =
    HashMap<Digest<MembershipOperation<S, T, L>>, MembershipOperation<S, T, L>>;

/// Reachable prekey ops for all agents, with shared storage.
///
/// Instead of duplicating topsorted key ops across agents, the ops are stored
/// once in [`ops`] and each agent has an index into that shared map.
#[derive(Debug)]
pub struct AllReachablePrekeyOps {
    /// Topsorted key ops per identifier (agent, group, or doc), computed once.
    pub ops: HashMap<Identifier, Vec<Arc<KeyOp>>>,

    /// For each agent: the set of identifiers whose ops in [`ops`] are reachable.
    pub index: HashMap<Identifier, HashSet<Identifier>>,
}

impl AllReachablePrekeyOps {
    /// Returns the set of agent identifiers that have reachable ops.
    pub fn agents(&self) -> impl Iterator<Item = &Identifier> {
        self.index.keys()
    }

    /// Returns an iterator over all reachable [`KeyOp`]s for the given agent
    /// (flattened across all source identifiers), or `None` if the agent is not
    /// in the index.
    pub fn ops_for_agent(
        &self,
        agent_id: &Identifier,
    ) -> Option<impl Iterator<Item = &Arc<KeyOp>>> {
        self.index.get(agent_id).map(|ids| {
            ids.iter()
                .filter_map(|id| self.ops.get(id))
                .flat_map(|ops| ops.iter())
        })
    }
}

/// Membership ops for all agents, with shared storage.
///
/// Instead of computing BFS per agent (which repeats work for agents sharing
/// groups/docs), the BFS is computed once per source (group, doc, or agent)
/// and each agent has an index into the shared source sets.
#[derive_where(Debug; T)]
pub struct AllMembershipOps<
    S: AsyncSigner,
    T: ContentRef = [u8; 32],
    L: MembershipListener<S, T> = NoListener,
> {
    /// Membership ops per source (group, doc, or agent), computed once.
    pub ops: HashMap<Identifier, MembershipOpMap<S, T, L>>,

    /// For each agent: the set of source identifiers whose ops are reachable.
    pub index: HashMap<Identifier, HashSet<Identifier>>,
}

#[allow(clippy::type_complexity)]
impl<S: AsyncSigner, T: ContentRef, L: MembershipListener<S, T>> AllMembershipOps<S, T, L> {
    /// Returns the set of agent identifiers that have reachable ops.
    pub fn agents(&self) -> impl Iterator<Item = &Identifier> {
        self.index.keys()
    }

    /// Returns an iterator over all reachable membership ops for the given agent
    /// (flattened across all source identifiers), or `None` if the agent is not
    /// in the index. May contain duplicates if sources share sub-chains.
    pub fn ops_for_agent(
        &self,
        agent_id: &Identifier,
    ) -> Option<
        impl Iterator<
            Item = (
                &Digest<MembershipOperation<S, T, L>>,
                &MembershipOperation<S, T, L>,
            ),
        >,
    > {
        self.index.get(agent_id).map(|ids| {
            ids.iter()
                .filter_map(|id| self.ops.get(id))
                .flat_map(|ops| ops.iter())
        })
    }
}

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
    delegations: Arc<Mutex<DelegationStore<S, T, L>>>,

    /// All applied [`Revocation`]s
    revocations: Arc<Mutex<RevocationStore<S, T, L>>>,

    /// [`StaticEvent`]s that are still awaiting dependencies.
    pending_events: Arc<Mutex<Vec<Arc<StaticEvent<T>>>>>,

    /// Observer for [`Event`]s. Intended for running live updates.
    event_listener: L,

    /// Storage for ciphertexts that cannot yet be decrypted.
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
        let verifying_key = signer.verifying_key();
        let inner_active = Active::generate(signer, event_listener.clone(), &mut csprng).await?;
        let active_id = inner_active.id();

        Ok(Self {
            verifying_key,
            individuals: Arc::new(Mutex::new(HashMap::from_iter([
                (
                    Public.id().into(),
                    Arc::new(Mutex::new(Public.individual())),
                ),
                (active_id, inner_active.individual().dupe()),
            ]))),
            active: Arc::new(Mutex::new(inner_active)),
            groups: Arc::new(Mutex::new(HashMap::new())),
            docs: Arc::new(Mutex::new(HashMap::new())),
            delegations: Arc::new(Mutex::new(DelegationStore::new())),
            revocations: Arc::new(Mutex::new(RevocationStore::new())),
            pending_events: Arc::new(Mutex::new(Vec::new())),
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
    pub async fn individual(&self) -> Arc<Mutex<Individual>> {
        self.active.lock().await.individual().dupe()
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
            self.delegations.lock().await.insert(head.dupe());

            for dep in head.payload().proof_lineage() {
                self.delegations.lock().await.insert(dep);
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
    pub async fn get_existing_contact_card(&self) -> ContactCard {
        self.active
            .lock()
            .await
            .individual()
            .lock()
            .await
            .contact_card()
    }

    #[instrument(skip_all)]
    pub async fn receive_contact_card(
        &self,
        contact_card: &ContactCard,
    ) -> Result<Arc<Mutex<Individual>>, ReceivePrekeyOpError> {
        let result = if let Some(indie) = self.get_individual(contact_card.id()).await {
            indie
                .lock()
                .await
                .receive_prekey_op(contact_card.op().dupe())?;
            indie.dupe()
        } else {
            let new_user = Arc::new(Mutex::new(Individual::from(contact_card)));
            self.register_individual(new_user.dupe()).await;
            new_user
        };

        match contact_card.op() {
            KeyOp::Add(add_op) => {
                self.event_listener.on_prekeys_expanded(add_op).await;
            }
            KeyOp::Rotate(rot_op) => {
                self.event_listener.on_prekey_rotated(rot_op).await;
            }
        }

        Ok(result)
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
        if let Some(d) = self.delegations.lock().await.get(&digest.coerce()) {
            Some(d.dupe().into())
        } else {
            self.revocations
                .lock()
                .await
                .get(&digest.coerce())
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

    #[instrument(skip_all)]
    pub async fn pending_event_hashes(&self) -> HashSet<Digest<StaticEvent<T>>> {
        self.pending_events
            .lock()
            .await
            .iter()
            .map(|event| Digest::hash(event.as_ref()))
            .collect()
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
            .map(|(op_digest, op)| (op_digest.coerce(), op.into()))
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
            .map(|(k, v)| (k.coerce(), v.into()))
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
                heads.push((hash.coerce(), dlg_head.dupe().into()));
            }

            for (hash, rev_head) in mem_rc.revocation_heads().await.iter() {
                heads.push((hash.coerce(), rev_head.dupe().into()));
            }
        }

        // Include any revocations for this agent that were missed
        if let Some(agent_revocations) = self
            .revocations
            .lock()
            .await
            .get_revocations_for_agent(&agent.agent_id())
        {
            for rev in agent_revocations {
                let hash: Digest<MembershipOperation<S, T, L>> =
                    Digest::hash(rev.as_ref()).coerce();
                heads.push((hash, rev.into()));
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
                        heads.push((Digest::hash(proof.as_ref()).coerce(), proof.dupe().into()));
                    }

                    for rev in dlg.payload.after_revocations.iter() {
                        heads.push((Digest::hash(rev.as_ref()).coerce(), rev.dupe().into()));
                    }

                    // If this delegation is to a group, include the group's delegation heads
                    if let Agent::Group(_group_id, group) = &dlg.payload.delegate {
                        for dlg in group.lock().await.delegation_heads().values() {
                            let dlg_hash = Digest::hash(dlg.as_ref()).coerce();
                            if !visited_hashes.contains(&dlg_hash) {
                                heads.push((dlg_hash, dlg.dupe().into()));
                            }
                        }
                    }
                }
                MembershipOperation::Revocation(rev) => {
                    if let Some(proof) = &rev.payload.proof {
                        heads.push((Digest::hash(proof.as_ref()).coerce(), proof.dupe().into()));
                    }

                    let r = rev.payload.revoke.dupe();
                    heads.push((Digest::hash(r.as_ref()).coerce(), r.into()));
                }
            }
        }

        ops
    }

    /// Compute membership ops for all agents in a single pass.
    ///
    /// Instead of calling `membership_ops_for_agent` per agent (which repeats
    /// the BFS for shared groups/docs), this iterates each group/doc once,
    /// does a single BFS from its delegation/revocation heads, and maps the
    /// results to all transitive members. Ops are stored per source (group,
    /// doc, or agent) and each agent's index points to the sources it can reach.
    pub async fn membership_ops_for_all_agents(&self) -> AllMembershipOps<S, T, L> {
        let mut ops: HashMap<Identifier, MembershipOpMap<S, T, L>> = HashMap::new();
        let mut index: HashMap<Identifier, HashSet<Identifier>> = HashMap::new();

        // Phase 1: For each group, collect heads (while holding lock), then BFS
        let groups = {
            self.groups
                .lock()
                .await
                .values()
                .cloned()
                .collect::<Vec<_>>()
        };
        for group in &groups {
            let (group_id, heads, transitive) = {
                let locked = group.lock().await;
                (
                    locked.group_id(),
                    Self::collect_membership_heads(
                        locked.delegation_heads(),
                        locked.revocation_heads(),
                    ),
                    locked.transitive_members().await,
                )
            };
            let source_id: Identifier = group_id.into();
            ops.insert(source_id, Self::bfs_membership_ops(heads).await);

            for agent_id in transitive.keys() {
                index.entry(*agent_id).or_default().insert(source_id);
            }
        }

        // Phase 2: Same for docs
        let docs = { self.docs.lock().await.values().cloned().collect::<Vec<_>>() };
        for doc in &docs {
            let (doc_id, heads, transitive) = {
                let locked = doc.lock().await;
                (
                    locked.doc_id(),
                    Self::collect_membership_heads(
                        locked.delegation_heads(),
                        locked.revocation_heads(),
                    ),
                    locked.transitive_members().await,
                )
            };
            let source_id: Identifier = doc_id.into();
            ops.insert(source_id, Self::bfs_membership_ops(heads).await);

            for agent_id in transitive.keys() {
                index.entry(*agent_id).or_default().insert(source_id);
            }
        }

        // Phase 3: Include agent-specific revocations that may not be reachable
        // from group/doc heads. These go under the agent's own identifier as source.
        {
            let revocations = self.revocations.lock().await;
            for (agent_id, agent_revs) in revocations.all_agent_revocations() {
                let identifier: Identifier = (*agent_id).into();
                if index.contains_key(&identifier) {
                    let agent_ops = ops.entry(identifier).or_default();
                    let mut visited: HashSet<Digest<MembershipOperation<S, T, L>>> =
                        agent_ops.keys().copied().collect();
                    for rev in agent_revs {
                        let hash: Digest<MembershipOperation<S, T, L>> =
                            Digest::hash(rev.as_ref()).into();
                        if visited.insert(hash) {
                            agent_ops.entry(hash).or_insert_with(|| rev.dupe().into());
                            Self::bfs_extend_from_revocation(rev, agent_ops, &mut visited).await;
                        }
                    }
                    if !agent_ops.is_empty() {
                        index.entry(identifier).or_default().insert(identifier);
                    }
                }
            }
        }

        AllMembershipOps { ops, index }
    }

    /// Collect BFS starting heads from delegation/revocation stores.
    /// This should be cheap (Arc clones + digest copies).
    #[allow(clippy::type_complexity)]
    fn collect_membership_heads(
        dlg_heads: &DelegationStore<S, T, L>,
        rev_heads: &RevocationStore<S, T, L>,
    ) -> Vec<(
        Digest<MembershipOperation<S, T, L>>,
        MembershipOperation<S, T, L>,
    )> {
        let mut heads = Vec::with_capacity(dlg_heads.len() + rev_heads.len());
        for (hash, dlg_head) in dlg_heads.iter() {
            heads.push((hash.into(), dlg_head.dupe().into()));
        }
        for (hash, rev_head) in rev_heads.iter() {
            heads.push((hash.into(), rev_head.dupe().into()));
        }
        heads
    }

    /// BFS from delegation/revocation heads, collecting all reachable membership ops.
    #[allow(clippy::type_complexity)]
    async fn bfs_membership_ops(
        mut heads: Vec<(
            Digest<MembershipOperation<S, T, L>>,
            MembershipOperation<S, T, L>,
        )>,
    ) -> HashMap<Digest<MembershipOperation<S, T, L>>, MembershipOperation<S, T, L>> {
        let mut ops = HashMap::new();
        let mut visited: HashSet<Digest<MembershipOperation<S, T, L>>> = HashSet::new();

        while let Some((hash, op)) = heads.pop() {
            if visited.contains(&hash) {
                continue;
            }
            visited.insert(hash);
            ops.insert(hash, op.clone());

            match op {
                MembershipOperation::Delegation(dlg) => {
                    if let Some(proof) = &dlg.payload.proof {
                        heads.push((Digest::hash(proof.as_ref()).into(), proof.dupe().into()));
                    }
                    for rev in dlg.payload.after_revocations.iter() {
                        heads.push((Digest::hash(rev.as_ref()).into(), rev.dupe().into()));
                    }
                    if let Agent::Group(_group_id, group) = &dlg.payload.delegate {
                        for dlg in group.lock().await.delegation_heads().values() {
                            let dlg_hash = Digest::hash(dlg.as_ref()).into();
                            if !visited.contains(&dlg_hash) {
                                heads.push((dlg_hash, dlg.dupe().into()));
                            }
                        }
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

    /// Follow a revocation's proof and revoke chains, adding new ops.
    async fn bfs_extend_from_revocation(
        rev: &Arc<Signed<Revocation<S, T, L>>>,
        all_ops: &mut MembershipOpMap<S, T, L>,
        visited: &mut HashSet<Digest<MembershipOperation<S, T, L>>>,
    ) {
        #[allow(clippy::type_complexity)]
        let mut heads: Vec<(
            Digest<MembershipOperation<S, T, L>>,
            MembershipOperation<S, T, L>,
        )> = Vec::new();

        if let Some(proof) = &rev.payload.proof {
            heads.push((Digest::hash(proof.as_ref()).into(), proof.dupe().into()));
        }
        let r = rev.payload.revoke.dupe();
        heads.push((Digest::hash(r.as_ref()).into(), r.into()));

        while let Some((hash, op)) = heads.pop() {
            if visited.contains(&hash) {
                continue;
            }
            visited.insert(hash);
            all_ops.entry(hash).or_insert_with(|| op.clone());

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
    }

    #[instrument(skip_all)]
    pub async fn reachable_prekey_ops_for_agent(
        &self,
        agent: &Agent<S, T, L>,
    ) -> HashMap<Identifier, Vec<Arc<KeyOp>>> {
        fn add_many_keys(
            map: &mut HashMap<Identifier, CaMap<KeyOp>>,
            agent_id: Identifier,
            key_ops: CaMap<KeyOp>,
        ) {
            map.entry(agent_id).or_default().extend(key_ops.0);
        }

        let mut map = HashMap::new();

        let (active_id, prekeys) = {
            let locked = self.active.lock().await;
            let prekeys = locked.individual.lock().await.prekey_ops().clone();
            (locked.id().into(), prekeys)
        };
        add_many_keys(&mut map, active_id, prekeys);

        // Add the agents own keys
        add_many_keys(&mut map, agent.id(), agent.key_ops().await);

        let groups = {
            self.groups
                .lock()
                .await
                .values()
                .cloned()
                .collect::<Vec<_>>()
        };
        for group in groups {
            let (group_id, transitive) = {
                let locked = group.lock().await;
                (locked.group_id(), locked.transitive_members().await)
            };
            if transitive.contains_key(&agent.id()) {
                add_many_keys(
                    &mut map,
                    group_id.into(),
                    Agent::Group(group_id, group.dupe()).key_ops().await,
                );

                for (agent_id, (agent, _access)) in &transitive {
                    if !map.contains_key(agent_id) {
                        add_many_keys(&mut map, *agent_id, agent.key_ops().await);
                    }
                }
            }
        }

        let docs = { self.docs.lock().await.values().cloned().collect::<Vec<_>>() };
        for doc in docs {
            let (doc_id, transitive) = {
                let locked = doc.lock().await;
                (locked.doc_id(), locked.transitive_members().await)
            };
            if transitive.contains_key(&agent.id()) {
                add_many_keys(
                    &mut map,
                    doc_id.into(),
                    Agent::Document(doc_id, doc.dupe()).key_ops().await,
                );

                for (agent_id, (agent, _access)) in &transitive {
                    if !map.contains_key(agent_id) {
                        add_many_keys(&mut map, *agent_id, agent.key_ops().await);
                    }
                }
            }
        }

        map.into_iter()
            .map(|(id, keys)| (id, KeyOp::topsort(&keys)))
            .collect()
    }

    /// Compute reachable prekey ops for all agents in a single pass.
    ///
    /// This avoids the redundant `transitive_members()` and `key_ops()` calls
    /// that happen when calling `reachable_prekey_ops_for_agent` once per agent.
    ///
    /// Returns an [`AllReachablePrekeyOps`] containing:
    /// - `ops`: topsorted key ops per identifier, computed once and shared
    /// - `index`: for each agent, the set of identifier keys into `ops` that are
    ///   reachable for that agent
    #[instrument(skip_all)]
    pub async fn reachable_prekey_ops_for_all_agents(&self) -> AllReachablePrekeyOps {
        // Phase 1: Precompute shared data
        let (active_id, active_prekeys) = {
            let locked = self.active.lock().await;
            let prekeys = locked.individual.lock().await.prekey_ops().clone();
            (locked.id().into(), prekeys)
        };

        let groups = {
            self.groups
                .lock()
                .await
                .values()
                .cloned()
                .collect::<Vec<_>>()
        };
        let docs = { self.docs.lock().await.values().cloned().collect::<Vec<_>>() };

        type TransitiveMembers<S, T, L> = HashMap<Identifier, (Agent<S, T, L>, Access)>;

        // For each group: (group_id, group_arc, transitive_members)
        #[allow(clippy::type_complexity)]
        let mut group_data: Vec<(
            GroupId,
            Arc<Mutex<Group<S, T, L>>>,
            TransitiveMembers<S, T, L>,
        )> = Vec::with_capacity(groups.len());
        for group in groups {
            let (group_id, transitive) = {
                let locked = group.lock().await;
                (locked.group_id(), locked.transitive_members().await)
            };
            group_data.push((group_id, group, transitive));
        }

        // For each doc: (doc_id, doc_arc, transitive_members)
        #[allow(clippy::type_complexity)]
        let mut doc_data: Vec<(
            DocumentId,
            Arc<Mutex<Document<S, T, L>>>,
            TransitiveMembers<S, T, L>,
        )> = Vec::with_capacity(docs.len());
        for doc in docs {
            let (doc_id, transitive) = {
                let locked = doc.lock().await;
                (locked.doc_id(), locked.transitive_members().await)
            };
            doc_data.push((doc_id, doc, transitive));
        }

        // Phase 2: Collect all key_ops (call key_ops() once per unique agent),
        // then topsort once per identifier.
        let mut key_ops_cache: HashMap<Identifier, CaMap<KeyOp>> = HashMap::new();
        key_ops_cache.insert(active_id, active_prekeys);

        for (group_id, group, transitive) in &group_data {
            let g_id: Identifier = (*group_id).into();
            if let Entry::Vacant(e) = key_ops_cache.entry(g_id) {
                e.insert(Agent::Group(*group_id, group.dupe()).key_ops().await);
            }
            for (agent_id, (agent, _access)) in transitive {
                if let Entry::Vacant(e) = key_ops_cache.entry(*agent_id) {
                    e.insert(agent.key_ops().await);
                }
            }
        }

        for (doc_id, doc, transitive) in &doc_data {
            let d_id: Identifier = (*doc_id).into();
            if let Entry::Vacant(e) = key_ops_cache.entry(d_id) {
                e.insert(Agent::Document(*doc_id, doc.dupe()).key_ops().await);
            }
            for (agent_id, (agent, _access)) in transitive {
                if let Entry::Vacant(e) = key_ops_cache.entry(*agent_id) {
                    e.insert(agent.key_ops().await);
                }
            }
        }

        // Include all registered individuals (even those not in any group/doc)
        for (id, indie) in self.individuals.lock().await.iter() {
            let agent_id: Identifier = (*id).into();
            if let Entry::Vacant(e) = key_ops_cache.entry(agent_id) {
                e.insert(indie.lock().await.prekey_ops().clone());
            }
        }

        let ops: HashMap<Identifier, Vec<Arc<KeyOp>>> = key_ops_cache
            .iter()
            .map(|(id, ca_map)| (*id, KeyOp::topsort(ca_map)))
            .collect();

        // Phase 3: Build per-agent index (just sets of identifiers, no data cloning)
        let mut index: HashMap<Identifier, HashSet<Identifier>> = HashMap::new();

        // Active agent gets its own entry
        index.entry(active_id).or_default().insert(active_id);

        // Every registered individual gets at least their own ops + active's ops
        for id in self.individuals.lock().await.keys() {
            let agent_id: Identifier = (*id).into();
            let entry = index.entry(agent_id).or_default();
            entry.insert(active_id);
            entry.insert(agent_id);
        }

        for (group_id, _, transitive) in &group_data {
            let g_id: Identifier = (*group_id).into();
            for agent_id in transitive.keys() {
                let entry = index.entry(*agent_id).or_default();
                entry.insert(active_id);
                entry.insert(*agent_id);
                entry.insert(g_id);
                entry.extend(transitive.keys());
            }
        }

        for (doc_id, _, transitive) in &doc_data {
            let d_id: Identifier = (*doc_id).into();
            for agent_id in transitive.keys() {
                let entry = index.entry(*agent_id).or_default();
                entry.insert(active_id);
                entry.insert(*agent_id);
                entry.insert(d_id);
                entry.extend(transitive.keys());
            }
        }

        AllReachablePrekeyOps { ops, index }
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
    pub async fn static_event_to_event(
        &self,
        static_event: StaticEvent<T>,
    ) -> Result<Event<S, T, L>, StaticEventConversionError<S, T, L>> {
        match static_event {
            StaticEvent::PrekeysExpanded(op) => Ok(Event::PrekeysExpanded(Arc::new(*op))),
            StaticEvent::PrekeyRotated(op) => Ok(Event::PrekeyRotated(Arc::new(*op))),
            StaticEvent::CgkaOperation(op) => Ok(Event::CgkaOperation(Arc::new(*op))),
            StaticEvent::Delegated(static_dlg) => {
                let delegation = self.static_delegation_to_delegation(&static_dlg).await?;
                Ok(Event::Delegated(Arc::new(Signed::new(
                    delegation,
                    static_dlg.issuer,
                    static_dlg.signature,
                ))))
            }
            StaticEvent::Revoked(static_rev) => {
                let revocation = self.static_revocation_to_revocation(&static_rev).await?;
                Ok(Event::Revoked(Arc::new(Signed::new(
                    revocation,
                    static_rev.issuer,
                    static_rev.signature,
                ))))
            }
        }
    }

    #[instrument(skip_all)]
    async fn static_delegation_to_delegation(
        &self,
        static_dlg: &Signed<StaticDelegation<T>>,
    ) -> Result<Delegation<S, T, L>, StaticEventConversionError<S, T, L>> {
        let proof: Option<Arc<Signed<Delegation<S, T, L>>>> =
            if let Some(proof_hash) = static_dlg.payload().proof {
                let hash = proof_hash.coerce();
                Some(
                    self.delegations
                        .lock()
                        .await
                        .get(&hash)
                        .ok_or(StaticEventConversionError::MissingDelegation(hash))?,
                )
            } else {
                None
            };

        let delegate_id = static_dlg.payload().delegate;
        let delegate: Agent<S, T, L> = self
            .get_agent(delegate_id)
            .await
            .ok_or(StaticEventConversionError::UnknownAgent(delegate_id))?;

        let mut after_revocations = Vec::new();
        for static_rev_hash in static_dlg.payload().after_revocations.iter() {
            let rev_hash = static_rev_hash.coerce();
            let resolved_rev = self
                .revocations
                .lock()
                .await
                .get(&rev_hash)
                .ok_or(StaticEventConversionError::MissingRevocation(rev_hash))?;
            after_revocations.push(resolved_rev);
        }

        Ok(Delegation {
            delegate,
            proof,
            can: static_dlg.payload().can,
            after_revocations,
            after_content: static_dlg.payload.after_content.clone(),
        })
    }

    #[instrument(skip_all)]
    async fn static_revocation_to_revocation(
        &self,
        static_rev: &Signed<StaticRevocation<T>>,
    ) -> Result<Revocation<S, T, L>, StaticEventConversionError<S, T, L>> {
        let revoke_hash = static_rev.payload.revoke.coerce();
        let revoke: Arc<Signed<Delegation<S, T, L>>> = self
            .delegations
            .lock()
            .await
            .get(&revoke_hash)
            .ok_or(StaticEventConversionError::MissingDelegation(revoke_hash))?;

        let proof: Option<Arc<Signed<Delegation<S, T, L>>>> =
            if let Some(proof_hash) = static_rev.payload().proof {
                let hash = proof_hash.coerce();
                Some(
                    self.delegations
                        .lock()
                        .await
                        .get(&hash)
                        .ok_or(StaticEventConversionError::MissingDelegation(hash))?,
                )
            } else {
                None
            };

        Ok(Revocation {
            revoke,
            proof,
            after_content: static_rev.payload.after_content.clone(),
        })
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
                    .lock()
                    .await
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
    ) -> Result<(), ReceiveStaticDelegationError<S, T, L>> {
        if self
            .delegations
            .lock()
            .await
            .contains_key(&Digest::hash(static_dlg).coerce())
        {
            return Ok(());
        }

        // NOTE: this is the only place this gets parsed and this verification ONLY happens here
        // TODO add a Verified<T> newtype wapper
        static_dlg.try_verify()?;

        let payload = self.static_delegation_to_delegation(static_dlg).await?;

        let mut after_revocations = Vec::new();
        for static_rev_hash in static_dlg.payload().after_revocations.iter() {
            let rev_hash = static_rev_hash.coerce();
            let locked_revs = self.revocations.lock().await;
            let resolved_rev = locked_revs
                .get(&rev_hash)
                .ok_or(MissingDependency(rev_hash))?;
            after_revocations.push(resolved_rev.dupe());
        }

        let delegation = Signed::new(payload, static_dlg.issuer, static_dlg.signature);

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
    ) -> Result<(), ReceiveStaticDelegationError<S, T, L>> {
        if self
            .revocations
            .lock()
            .await
            .contains_key(&Digest::hash(static_rev).coerce())
        {
            return Ok(());
        }

        // NOTE: this is the only place this gets parsed and this verification ONLY happens here
        static_rev.try_verify()?;

        let payload = self.static_revocation_to_revocation(static_rev).await?;

        let revocation = Signed::new(payload, static_rev.issuer, static_rev.signature);

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
            StaticEvent::CgkaOperation(cgka_op) => {
                self.receive_cgka_op(*cgka_op).await?;
            }
            StaticEvent::Delegated(dlg) => self.receive_delegation(&dlg).await?,
            StaticEvent::Revoked(rev) => self.receive_revocation(&rev).await?,
        }
        Ok(())
    }

    #[instrument(skip_all)]
    pub async fn receive_membership_op(
        &self,
        static_op: &StaticMembershipOperation<T>,
    ) -> Result<(), ReceiveStaticDelegationError<S, T, L>> {
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

        let doc_id: DocumentId = (*signed_op.payload.doc_id()).into();
        let doc = {
            let locked_docs = self.docs.lock().await;
            locked_docs
                .get(&doc_id)
                .ok_or(ReceiveCgkaOpError::UnknownDocument(doc_id))?
                .dupe()
        };

        let signed_op = Arc::new(signed_op);
        if let CgkaOperation::Add { added_id, pk, .. } = signed_op.payload {
            let added_id: IndividualId = added_id.into();
            let locked_active = self.active.lock().await;
            let active_id = locked_active.id();
            if active_id == added_id {
                let sk = {
                    let locked_prekeys = locked_active.prekey_pairs.lock().await;
                    *locked_prekeys
                        .get(&pk)
                        .ok_or(ReceiveCgkaOpError::UnknownInvitePrekey(pk))?
                };
                if doc
                    .lock()
                    .await
                    .merge_cgka_invite_op(signed_op.clone(), &sk)?
                {
                    self.event_listener.on_cgka_op(&signed_op).await;
                };
                return Ok(());
            } else if Public.individual().id() == added_id {
                let sk = Public.share_secret_key();
                if doc
                    .lock()
                    .await
                    .merge_cgka_invite_op(signed_op.clone(), &sk)?
                {
                    self.event_listener.on_cgka_op(&signed_op).await;
                }
                return Ok(());
            }
        }
        if doc.lock().await.merge_cgka_op(signed_op.clone())? {
            self.event_listener.on_cgka_op(&signed_op).await;
        }
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
            let mut locked_delegations = self.delegations.lock().await;
            for (_digest, dlg) in locked_delegations.clone().iter() {
                if dlg.payload.delegate == agent {
                    locked_delegations.insert(Arc::new(Signed::new(
                        Delegation {
                            delegate: agent.dupe(),
                            can: dlg.payload.can,
                            proof: dlg.payload.proof.clone(),
                            after_revocations: dlg.payload.after_revocations.clone(),
                            after_content: dlg.payload.after_content.clone(),
                        },
                        dlg.issuer,
                        dlg.signature,
                    )));
                }
            }
        }

        {
            let group_id = group.lock().await.id();
            let mut locked_revocations = self.revocations.lock().await;
            for (_digest, rev) in locked_revocations.clone().iter() {
                if rev.payload.subject_id() == group_id {
                    locked_revocations.insert(Arc::new(Signed::new(
                        Revocation {
                            revoke: self
                                .delegations
                                .lock()
                                .await
                                .get(&Digest::hash(&rev.payload.revoke))
                                .expect("revoked delegation to be available")
                                .dupe(),
                            proof: if let Some(proof) = rev.payload.proof.dupe() {
                                self.delegations.lock().await.get(&Digest::hash(&proof))
                            } else {
                                panic!("revoked delegation to be available");
                            },
                            after_content: rev.payload.after_content.clone(),
                        },
                        rev.issuer,
                        rev.signature,
                    )));
                }
            }
        }

        group
    }

    #[instrument(skip_all)]
    pub async fn into_archive(&self) -> Archive<T> {
        let topsorted_ops = {
            let delegations = self.delegations.lock().await;
            let revocations = self.revocations.lock().await;
            MembershipOperation::<S, T, L>::reverse_topsort(&delegations, &revocations)
                .into_iter()
                .rev()
                .map(|(k, v)| (k.coerce(), v.into()))
                .collect()
        };

        let mut individuals = HashMap::new();
        {
            let locked_individuals = self.individuals.lock().await;
            for (k, arc) in locked_individuals.iter() {
                individuals.insert(*k, arc.lock().await.clone());
            }
        }

        let active = {
            let locked_active = self.active.lock().await;
            locked_active.into_archive().await
        };

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

        let pending_events: Vec<_> = self
            .pending_events
            .lock()
            .await
            .iter()
            .map(|event| event.as_ref().clone())
            .collect();

        Archive {
            active,
            topsorted_ops,
            individuals,
            groups,
            docs,
            pending_events,
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
        let raw_active = Active::from_archive(&archive.active, signer, listener.clone());

        let delegations = Arc::new(Mutex::new(DelegationStore::new()));
        let revocations = Arc::new(Mutex::new(RevocationStore::new()));

        let mut individuals = HashMap::new();
        for (k, v) in archive.individuals.iter() {
            individuals.insert(*k, Arc::new(Mutex::new(v.clone())));
        }
        individuals.insert(archive.active.individual.id(), raw_active.individual.dupe());

        let active = Arc::new(Mutex::new(raw_active));

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

        for (_digest, static_op) in archive.topsorted_ops.iter() {
            match static_op {
                StaticMembershipOperation::Delegation(sd) => {
                    let proof: Option<Arc<Signed<Delegation<S, T, L>>>> =
                        if let Some(proof_digest) = sd.payload.proof {
                            Some(delegations.lock().await.get(&proof_digest.coerce()).ok_or(
                                TryFromArchiveError::MissingDelegation(proof_digest.coerce()),
                            )?)
                        } else {
                            None
                        };

                    let mut after_revocations = vec![];
                    for rev_digest in sd.payload.after_revocations.iter() {
                        let r: Arc<Signed<Revocation<S, T, L>>> = revocations
                            .lock()
                            .await
                            .get(&rev_digest.coerce())
                            .ok_or(TryFromArchiveError::MissingRevocation(rev_digest.coerce()))?
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
                    delegations.lock().await.insert(Arc::new(Signed::new(
                        Delegation {
                            delegate,
                            proof,
                            can: sd.payload.can,
                            after_revocations,
                            after_content: sd.payload.after_content.clone(),
                        },
                        sd.issuer,
                        sd.signature,
                    )));
                }
                StaticMembershipOperation::Revocation(sr) => {
                    let revoke = delegations
                        .lock()
                        .await
                        .get(&sr.payload.revoke.coerce())
                        .ok_or(TryFromArchiveError::MissingDelegation(
                            sr.payload.revoke.coerce(),
                        ))?;

                    let proof = if let Some(proof_digest) = sr.payload.proof {
                        Some(delegations.lock().await.get(&proof_digest.coerce()).ok_or(
                            TryFromArchiveError::MissingDelegation(proof_digest.coerce()),
                        )?)
                    } else {
                        None
                    };

                    revocations.lock().await.insert(Arc::new(Signed::new(
                        Revocation {
                            revoke,
                            proof,
                            after_content: sr.payload.after_content.clone(),
                        },
                        sr.issuer,
                        sr.signature,
                    )));
                }
            };
        }

        #[allow(clippy::type_complexity)]
        async fn reify_ops<Z: AsyncSigner, U: ContentRef, M: MembershipListener<Z, U>>(
            group: &mut Group<Z, U, M>,
            dlg_store: Arc<Mutex<DelegationStore<Z, U, M>>>,
            rev_store: Arc<Mutex<RevocationStore<Z, U, M>>>,
            dlg_head_hashes: &HashSet<Digest<Signed<StaticDelegation<U>>>>,
            rev_head_hashes: &HashSet<Digest<Signed<StaticRevocation<U>>>>,
            members: HashMap<Identifier, NonEmpty<Digest<Signed<Delegation<Z, U, M>>>>>,
        ) -> Result<(), TryFromArchiveError<Z, U, M>> {
            let read_dlgs = dlg_store.lock().await;
            let read_revs = rev_store.lock().await;

            for dlg_hash in dlg_head_hashes.iter() {
                let actual_dlg: Arc<Signed<Delegation<Z, U, M>>> = read_dlgs
                    .get(&dlg_hash.coerce())
                    .ok_or(TryFromArchiveError::MissingDelegation(dlg_hash.coerce()))?
                    .dupe();

                group.state.delegation_heads.insert(actual_dlg);
            }

            for rev_hash in rev_head_hashes.iter() {
                let actual_rev = read_revs
                    .get(&rev_hash.coerce())
                    .ok_or(TryFromArchiveError::MissingRevocation(rev_hash.coerce()))?;
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
                    .map(|(k, v)| (*k, v.clone().map(|x| x.coerce())))
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
                    .map(|(k, v)| (*k, v.clone().map(|x| x.coerce())))
                    .collect(),
            )
            .await?;
        }

        let mut pending_events = Vec::new();
        for event in &archive.pending_events {
            pending_events.push(Arc::new(event.clone()));
        }

        Ok(Self {
            verifying_key: archive.active.individual.verifying_key(),
            active,
            individuals: Arc::new(Mutex::new(individuals)),
            groups: Arc::new(Mutex::new(groups)),
            docs: Arc::new(Mutex::new(docs)),
            delegations,
            revocations,
            pending_events: Arc::new(Mutex::new(pending_events)),
            csprng,
            ciphertext_store,
            event_listener: listener,
            _plaintext_phantom: PhantomData,
        })
    }

    #[allow(clippy::type_complexity)]
    #[instrument(level = "trace", skip_all)]
    pub async fn ingest_archive(
        &self,
        archive: Archive<T>,
    ) -> Result<Vec<Arc<StaticEvent<T>>>, ReceiveStaticEventError<S, T, L>> {
        tracing::debug!("Keyhive::ingest_archive()");
        {
            let locked_active = self.active.lock().await;
            {
                locked_active
                    .prekey_pairs
                    .lock()
                    .await
                    .extend(archive.active.prekey_pairs);
            }
            {
                locked_active
                    .individual
                    .lock()
                    .await
                    .merge(archive.active.individual);
            }
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
        Ok(self.ingest_unsorted_static_events(events).await)
    }

    #[instrument(skip_all)]
    pub fn event_listener(&self) -> &L {
        &self.event_listener
    }

    #[instrument(level = "trace", skip_all)]
    pub async fn ingest_unsorted_static_events(
        &self,
        mut events: Vec<StaticEvent<T>>,
    ) -> Vec<Arc<StaticEvent<T>>> {
        // FIXME: Some errors might not be recoverable on future attempts
        tracing::debug!("Keyhive::ingest_unsorted_static_events()");
        for event in self.pending_events.as_ref().lock().await.iter() {
            events.push(event.as_ref().clone());
        }

        // Deduplicate events by hash
        use std::collections::HashMap;
        let mut unique_events: HashMap<Digest<StaticEvent<T>>, StaticEvent<T>> = HashMap::new();
        for event in events {
            let hash = Digest::hash(&event);
            unique_events.entry(hash).or_insert(event);
        }
        let mut epoch: Vec<StaticEvent<T>> = unique_events.into_values().collect();

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
                return Vec::new();
            }

            if next_epoch.len() == epoch_len {
                tracing::debug!(
                    "ingest_unsorted_static_events: Stuck on a fixed point: {:?}. Error: {:?}",
                    epoch_len,
                    err
                );
                let new_pending: Vec<Arc<StaticEvent<T>>> =
                    next_epoch.clone().into_iter().map(Arc::new).collect();
                drop(mem::replace(
                    &mut *self.pending_events.lock().await,
                    new_pending.clone(),
                ));
                // FIXME: Some errors might not be recoverable on future attempts
                return new_pending;
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
        tracing::debug!("Keyhive::ingest_event_table");
        self.ingest_unsorted_static_events(
            events.values().cloned().map(Into::into).collect::<Vec<_>>(),
        )
        .await;
        Ok(())
    }

    pub async fn stats(&self) -> Stats {
        let active_prekey_count = self
            .active
            .lock()
            .await
            .individual
            .lock()
            .await
            .prekey_ops()
            .len() as u64;

        // Count prekeys_expanded and prekey_rotations across all individuals
        let mut prekeys_expanded = 0;
        let mut prekey_rotations = 0;
        for individual in self.individuals.lock().await.values() {
            for key_op in individual.lock().await.prekey_ops().values() {
                match key_op.as_ref() {
                    KeyOp::Add(_) => prekeys_expanded += 1,
                    KeyOp::Rotate(_) => prekey_rotations += 1,
                }
            }
        }

        // Count CGKA operations across all documents
        let mut cgka_operations = 0;
        for doc in self.docs.lock().await.values() {
            if let Ok(cgka) = doc.lock().await.cgka() {
                cgka_operations += cgka.ops_count() as u64;
            }
        }

        let active_id = self.id();
        let pending_events = self.pending_events.lock().await;

        let mut pending_prekeys_expanded = 0;
        let mut pending_prekeys_expanded_by_active = 0;
        let mut pending_prekey_rotated = 0;
        let mut pending_prekey_rotated_by_active = 0;
        let mut pending_cgka_operation = 0;
        let mut pending_cgka_operation_by_active = 0;
        let mut pending_delegated = 0;
        let mut pending_delegated_by_active = 0;
        let mut pending_revoked = 0;
        let mut pending_revoked_by_active = 0;

        for event in pending_events.iter() {
            match event.as_ref() {
                StaticEvent::PrekeysExpanded(signed) => {
                    pending_prekeys_expanded += 1;
                    if signed.id() == active_id.into() {
                        pending_prekeys_expanded_by_active += 1;
                    }
                }
                StaticEvent::PrekeyRotated(signed) => {
                    pending_prekey_rotated += 1;
                    if signed.id() == active_id.into() {
                        pending_prekey_rotated_by_active += 1;
                    }
                }
                StaticEvent::CgkaOperation(signed) => {
                    pending_cgka_operation += 1;
                    if signed.id() == active_id.into() {
                        pending_cgka_operation_by_active += 1;
                    }
                }
                StaticEvent::Delegated(signed) => {
                    pending_delegated += 1;
                    if signed.id() == active_id.into() {
                        pending_delegated_by_active += 1;
                    }
                }
                StaticEvent::Revoked(signed) => {
                    pending_revoked += 1;
                    if signed.id() == active_id.into() {
                        pending_revoked_by_active += 1;
                    }
                }
            }
        }

        Stats {
            individuals: self.individuals.as_ref().lock().await.len() as u64,
            groups: self.groups.as_ref().lock().await.len() as u64,
            docs: self.docs.as_ref().lock().await.len() as u64,
            delegations: self.delegations.lock().await.len() as u64,
            revocations: self.revocations.lock().await.len() as u64,
            prekeys_expanded,
            prekey_rotations,
            cgka_operations,
            active_prekey_count,
            pending_prekeys_expanded,
            pending_prekeys_expanded_by_active,
            pending_prekey_rotated,
            pending_prekey_rotated_by_active,
            pending_cgka_operation,
            pending_cgka_operation_by_active,
            pending_delegated,
            pending_delegated_by_active,
            pending_revoked,
            pending_revoked_by_active,
        }
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
        let forked_active = { fork.active.lock().await.clone() };
        let locked = self.lock().await;
        locked.active.lock().await.merge_async(forked_active).await;

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
    ReceiveStaticMembershipError(#[from] ReceiveStaticDelegationError<S, T, L>),
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
            Self::ReceiveStaticMembershipError(e) => e.is_missing_dependency(),
        }
    }
}

#[derive(Error)]
#[derive_where(Debug; T)]
pub enum ReceiveStaticDelegationError<
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

impl<S, T, L> ReceiveStaticDelegationError<S, T, L>
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
pub enum StaticEventConversionError<S: AsyncSigner, T: ContentRef, L: MembershipListener<S, T>> {
    #[error("Missing delegation: {0}")]
    MissingDelegation(Digest<Signed<Delegation<S, T, L>>>),

    #[error("Missing revocation: {0}")]
    MissingRevocation(Digest<Signed<Revocation<S, T, L>>>),

    #[error("Unknown agent: {0}")]
    UnknownAgent(Identifier),
}

impl<S: AsyncSigner, T: ContentRef, L: MembershipListener<S, T>>
    From<StaticEventConversionError<S, T, L>> for ReceiveStaticDelegationError<S, T, L>
{
    fn from(error: StaticEventConversionError<S, T, L>) -> Self {
        match error {
            StaticEventConversionError::MissingDelegation(hash) => {
                ReceiveStaticDelegationError::MissingProof(MissingDependency(hash))
            }
            StaticEventConversionError::MissingRevocation(hash) => {
                ReceiveStaticDelegationError::MissingRevocationDependency(MissingDependency(hash))
            }
            StaticEventConversionError::UnknownAgent(id) => {
                ReceiveStaticDelegationError::UnknownAgent(id)
            }
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
    ReceiveStaticDelegationError(#[from] ReceiveStaticDelegationError<S, T, L>),

    #[error(transparent)]
    ReceivePrekeyOpError(#[from] ReceivePrekeyOpError),

    #[error(transparent)]
    ReceiveCgkaOpError(#[from] ReceiveCgkaOpError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{access::Access, principal::public::Public, transact::transact_async};
    use keyhive_crypto::signer::memory::MemorySigner;
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

        assert!(!hive
            .active
            .lock()
            .await
            .prekey_pairs
            .lock()
            .await
            .is_empty());
        assert_eq!(hive.individuals.lock().await.len(), 3);
        assert_eq!(hive.groups.lock().await.len(), 1);
        assert_eq!(hive.docs.lock().await.len(), 1);
        assert_eq!(hive.delegations.lock().await.len(), 4);
        assert_eq!(hive.revocations.lock().await.len(), 0);

        let archive = hive.into_archive().await;

        assert_eq!(hive.id(), archive.id());
        assert_eq!(archive.individuals.len(), 3);
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
            hive.delegations.lock().await.len(),
            hive_from_archive.delegations.lock().await.len()
        );

        assert_eq!(
            hive.revocations.lock().await.len(),
            hive_from_archive.revocations.lock().await.len()
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
    async fn test_loading_archive_after_revoking_delegation() -> TestResult {
        test_utils::init_logging();

        let mut csprng = rand::rngs::OsRng;
        let sk = MemorySigner::generate(&mut csprng);
        let store = Arc::new(Mutex::new(MemoryCiphertextStore::<[u8; 32], String>::new()));
        let kh =
            Keyhive::generate(sk.clone(), store.clone(), NoListener, rand::rngs::OsRng).await?;

        let indie_sk = MemorySigner::generate(&mut csprng);
        let indie = Arc::new(Mutex::new(
            Individual::generate(&indie_sk, &mut csprng).await?,
        ));
        kh.register_individual(indie.dupe()).await;
        let doc = kh.generate_doc(vec![], nonempty![[1u8; 32]]).await?;
        let doc_id = DocumentId(doc.lock().await.id());
        let membered_doc = Membered::Document(doc_id, doc.dupe());

        // Delegate to an individual and then revoke
        let indie_id = indie.lock().await.id();
        let indie_agent = Agent::Individual(indie_id, indie.dupe());
        kh.add_member(indie_agent, &membered_doc, Access::Write, &[])
            .await?;
        kh.revoke_member(indie_id.into(), true, &membered_doc)
            .await?;

        // Create an archive and try to load it into a fresh Keyhive
        let archive = kh.into_archive().await;
        let kh2 = Keyhive::try_from_archive(
            &archive,
            sk,
            Arc::new(Mutex::new(MemoryCiphertextStore::<[u8; 32], String>::new())),
            NoListener,
            Arc::new(Mutex::new(rand::rngs::OsRng)),
        )
        .await?;

        assert_eq!(kh2.verifying_key, archive.active.individual.verifying_key());

        Ok(())
    }

    #[tokio::test]
    async fn test_receive_delegations_associatively() {
        test_utils::init_logging();

        let hive1 = make_keyhive().await;
        let hive2 = make_keyhive().await;

        let hive2_on_hive1 = Arc::new(Mutex::new(
            hive2.active.lock().await.individual.lock().await.clone(),
        ));
        hive1.register_individual(hive2_on_hive1.dupe()).await;
        let hive1_on_hive2 = Arc::new(Mutex::new(
            hive1.active.lock().await.individual.lock().await.clone(),
        ));
        hive2.register_individual(hive1_on_hive2.dupe()).await;
        let group1_on_hive1 = hive1
            .generate_group(vec![Peer::Individual(
                hive2_on_hive1.lock().await.id(),
                hive2_on_hive1.dupe(),
            )])
            .await
            .unwrap();

        assert_eq!(hive1.delegations.lock().await.len(), 2);
        assert_eq!(hive1.revocations.lock().await.len(), 0);
        assert_eq!(hive1.individuals.lock().await.len(), 3); // NOTE: knows about Public and Hive2
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

            assert_eq!(hive2.delegations.lock().await.len(), 0);
            assert_eq!(hive2.revocations.lock().await.len(), 0);
            assert_eq!(hive2.individuals.lock().await.len(), 3);
            assert_eq!(hive2.groups.lock().await.len(), 0);
            assert_eq!(hive2.docs.lock().await.len(), 0);

            let heads = locked_group1_on_hive1.delegation_heads().clone();
            for dlg in heads.values() {
                let static_dlg = dlg.as_ref().clone().map(|d| d.into()); // TODO add From instance
                hive2.receive_delegation(&static_dlg).await.unwrap();
            }
        }

        assert_eq!(hive2.delegations.lock().await.len(), 2);
        assert_eq!(hive2.revocations.lock().await.len(), 0);
        assert_eq!(hive2.individuals.lock().await.len(), 3); // NOTE: Yourself, Public, and Hive2
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

        assert_eq!(left.delegations.lock().await.len(), 3);
        assert_eq!(left.revocations.lock().await.len(), 0);

        assert_eq!(left.individuals.lock().await.len(), 2);
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
        assert_eq!(left.delegations.lock().await.len(), 3);
        assert_eq!(left.revocations.lock().await.len(), 0);

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

        assert_eq!(middle.individuals.lock().await.len(), 3); // NOTE: includes Left
        assert_eq!(middle.groups.lock().await.len(), 0);
        assert_eq!(middle.docs.lock().await.len(), 1);

        assert_eq!(middle.revocations.lock().await.len(), 0);
        assert_eq!(middle.delegations.lock().await.len(), 2);
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
        assert_eq!(left.delegations.lock().await.len(), 3);
        assert_eq!(left.revocations.lock().await.len(), 0);

        // Middle unchanged
        assert_eq!(middle.individuals.lock().await.len(), 3);
        assert_eq!(middle.groups.lock().await.len(), 0);
        assert_eq!(middle.docs.lock().await.len(), 1);

        assert_eq!(middle.delegations.lock().await.len(), 2);
        assert_eq!(middle.revocations.lock().await.len(), 0);

        // Right should now look the same
        assert_eq!(right.revocations.lock().await.len(), 0);
        assert_eq!(right.delegations.lock().await.len(), 2);

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

        assert_eq!(right.individuals.lock().await.len(), 4);
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

        assert_eq!(middle.individuals.lock().await.len(), 4); // NOTE now includes Right
        assert_eq!(middle.groups.lock().await.len(), 1);
        assert_eq!(middle.docs.lock().await.len(), 1);
        assert_eq!(middle.delegations.lock().await.len(), 4);
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
    async fn test_peer_sees_other_peer_access_via_group() {
        test_utils::init_logging();

        // Create a keyhive and a doc
        let hive1 = make_keyhive().await;
        let group = hive1.generate_group(vec![]).await.unwrap();
        let group_id = group.lock().await.group_id();
        let doc = hive1
            .generate_doc(
                vec![Peer::Group(group_id, group.dupe())],
                nonempty![[0u8; 32]],
            )
            .await
            .unwrap();
        let doc_id = doc.lock().await.doc_id();

        // Create two more keyhives
        let hive2 = make_keyhive().await;
        let hive2_op = hive2.expand_prekeys().await.unwrap();
        let hive2_on_hive1 = Arc::new(Mutex::new(Individual::new(KeyOp::Add(hive2_op))));
        assert!(hive1.register_individual(hive2_on_hive1.clone()).await);
        let hive2_on_hive1_id = { hive2_on_hive1.lock().await.id() };

        let hive3 = make_keyhive().await;
        let hive3_op = hive3.expand_prekeys().await.unwrap();
        let hive3_on_hive1 = Arc::new(Mutex::new(Individual::new(KeyOp::Add(hive3_op))));
        assert!(hive1.register_individual(hive3_on_hive1.clone()).await);
        let hive3_on_hive1_id = { hive3_on_hive1.lock().await.id() };

        // Add hive2 as a member of the doc
        hive1
            .add_member(
                Agent::Individual(hive2_on_hive1_id, hive2_on_hive1.dupe()),
                &Membered::Document(doc_id, doc.dupe()),
                Access::Write,
                &[],
            )
            .await
            .unwrap();

        // Add hive3 as a member of the group that was parent of the doc
        hive1
            .add_member(
                Agent::Individual(hive3_on_hive1_id, hive3_on_hive1.dupe()),
                &Membered::Group(group_id, group.dupe()),
                Access::Read,
                &[],
            )
            .await
            .unwrap();

        // Verify hive1 can see hive3's access to the doc
        let doc_on_hive1 = hive1.get_document(doc_id).await.unwrap();
        let hive1_members = doc_on_hive1.lock().await.transitive_members().await;
        let hive3_on_hive1_access = hive1_members.get(&hive3_on_hive1_id.into());
        assert!(
            hive3_on_hive1_access.is_some(),
            "hive1 should see hive3's access to the doc"
        );

        // Register hive3 with hive2
        let hive3_card_op = hive3.expand_prekeys().await.unwrap();
        let hive3_on_hive2 = Arc::new(Mutex::new(Individual::new(KeyOp::Add(hive3_card_op))));
        hive2.register_individual(hive3_on_hive2.clone()).await;
        let hive3_on_hive2_id = { hive3_on_hive2.lock().await.id() };

        // Send keyhive events from hive1 to hive2
        let events_for_hive2_from_hive1 = hive1
            .events_for_agent(&Agent::Individual(hive2_on_hive1_id, hive2_on_hive1.dupe()))
            .await
            .unwrap();
        hive2
            .ingest_event_table(events_for_hive2_from_hive1)
            .await
            .unwrap();

        // Now verify hive2 can see hive3's access to the doc
        let doc_on_hive2 = hive2.get_document(doc_id).await.unwrap();
        let members = doc_on_hive2.lock().await.transitive_members().await;
        let hive3_access = members.get(&hive3_on_hive2_id.into());
        assert!(
            hive3_access.is_some(),
            "hive2 should see hive3's access to the doc",
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

    /// Test that reachable_prekey_ops_for_agent merges prekeys from multiple sources
    /// rather than overwriting them.
    #[tokio::test]
    async fn test_reachable_prekey_ops_merges_not_overwrites() {
        test_utils::init_logging();

        let alice = make_keyhive().await;
        let bob = make_keyhive().await;

        let bob_add_op = bob.expand_prekeys().await.unwrap();
        let bob_rotate_op1 = bob
            .rotate_prekey(bob_add_op.payload.share_key)
            .await
            .unwrap();
        let bob_rotate_op2 = bob.rotate_prekey(bob_rotate_op1.payload.new).await.unwrap();

        let bob_on_alice_for_delegation =
            Arc::new(Mutex::new(Individual::new(KeyOp::Add(bob_add_op.clone()))));
        assert!(
            alice
                .register_individual(bob_on_alice_for_delegation.clone())
                .await
        );
        let bob_id = bob_on_alice_for_delegation.lock().await.id();

        let doc = alice
            .generate_doc(vec![], nonempty![[0u8; 32]])
            .await
            .unwrap();
        let doc_id = doc.lock().await.doc_id();
        alice
            .add_member(
                Agent::Individual(bob_id, bob_on_alice_for_delegation.dupe()),
                &Membered::Document(doc_id, doc.dupe()),
                Access::Read,
                &[],
            )
            .await
            .unwrap();

        let mut bob_individual_with_rotations = Individual::new(KeyOp::Add(bob_add_op.clone()));
        bob_individual_with_rotations
            .receive_prekey_op(KeyOp::Rotate(bob_rotate_op1))
            .unwrap();
        bob_individual_with_rotations
            .receive_prekey_op(KeyOp::Rotate(bob_rotate_op2))
            .unwrap();
        let bob_on_alice_with_rotations = Arc::new(Mutex::new(bob_individual_with_rotations));

        assert_eq!(
            bob_on_alice_with_rotations.lock().await.prekey_ops().len(),
            3,
            "bob_on_alice_with_rotations should have 3 prekey ops"
        );

        assert_eq!(
            bob_on_alice_for_delegation.lock().await.prekey_ops().len(),
            1,
            "bob_on_alice_for_delegation should have 1 prekey op"
        );

        let prekey_ops = alice
            .reachable_prekey_ops_for_agent(&Agent::Individual(
                bob_id,
                bob_on_alice_with_rotations.dupe(),
            ))
            .await;

        let bob_prekeys_in_result = prekey_ops.get(&bob_id.into());
        assert!(
            bob_prekeys_in_result.is_some(),
            "Bob's prekeys should be in the result"
        );

        let bob_prekey_vec = bob_prekeys_in_result.unwrap();
        assert_eq!(
            bob_prekey_vec.len(),
            3,
            "all 3 of Bob's prekey ops should be present, but got {}",
            bob_prekey_vec.len()
        );
    }

    /// Test that reachable_prekey_ops_for_all_agents matches
    /// reachable_prekey_ops_for_agent for each agent.
    #[tokio::test]
    async fn test_reachable_prekey_ops_for_all_agents_matches_per_agent() {
        use crate::crypto::digest::Digest;

        test_utils::init_logging();

        let alice = make_keyhive().await;
        let bob = make_keyhive().await;
        let carol = make_keyhive().await;
        let dan = make_keyhive().await;
        let eve = make_keyhive().await;

        // Register all individuals on alice, with varying numbers of prekey rotations
        // so that op counts differ across agents.
        let bob_add_op = bob.expand_prekeys().await.unwrap();
        let bob_rot1 = bob
            .rotate_prekey(bob_add_op.payload.share_key)
            .await
            .unwrap();
        let bob_rot2 = bob.rotate_prekey(bob_rot1.payload.new).await.unwrap();
        let mut bob_individual = Individual::new(KeyOp::Add(bob_add_op));
        bob_individual
            .receive_prekey_op(KeyOp::Rotate(bob_rot1))
            .unwrap();
        bob_individual
            .receive_prekey_op(KeyOp::Rotate(bob_rot2))
            .unwrap();
        let bob_indie = Arc::new(Mutex::new(bob_individual));
        assert!(alice.register_individual(bob_indie.clone()).await);
        let bob_id = bob_indie.lock().await.id();

        let carol_add_op = carol.expand_prekeys().await.unwrap();
        let carol_rot1 = carol
            .rotate_prekey(carol_add_op.payload.share_key)
            .await
            .unwrap();
        let mut carol_individual = Individual::new(KeyOp::Add(carol_add_op));
        carol_individual
            .receive_prekey_op(KeyOp::Rotate(carol_rot1))
            .unwrap();
        let carol_indie = Arc::new(Mutex::new(carol_individual));
        assert!(alice.register_individual(carol_indie.clone()).await);
        let carol_id = carol_indie.lock().await.id();

        let dan_add_op = dan.expand_prekeys().await.unwrap();
        let dan_indie = Arc::new(Mutex::new(Individual::new(KeyOp::Add(dan_add_op))));
        assert!(alice.register_individual(dan_indie.clone()).await);
        let dan_id = dan_indie.lock().await.id();

        let eve_add_op = eve.expand_prekeys().await.unwrap();
        let eve_rot1 = eve
            .rotate_prekey(eve_add_op.payload.share_key)
            .await
            .unwrap();
        let eve_rot2 = eve.rotate_prekey(eve_rot1.payload.new).await.unwrap();
        let eve_rot3 = eve.rotate_prekey(eve_rot2.payload.new).await.unwrap();
        let mut eve_individual = Individual::new(KeyOp::Add(eve_add_op));
        eve_individual
            .receive_prekey_op(KeyOp::Rotate(eve_rot1))
            .unwrap();
        eve_individual
            .receive_prekey_op(KeyOp::Rotate(eve_rot2))
            .unwrap();
        eve_individual
            .receive_prekey_op(KeyOp::Rotate(eve_rot3))
            .unwrap();
        let eve_indie = Arc::new(Mutex::new(eve_individual));
        assert!(alice.register_individual(eve_indie.clone()).await);
        let eve_id = eve_indie.lock().await.id();

        // Frank: registered but not added to any doc or group, with extra ops
        let frank = make_keyhive().await;
        let frank_add_op = frank.expand_prekeys().await.unwrap();
        let frank_rot1 = frank
            .rotate_prekey(frank_add_op.payload.share_key)
            .await
            .unwrap();
        let frank_rot2 = frank.rotate_prekey(frank_rot1.payload.new).await.unwrap();
        let frank_indie = Arc::new(Mutex::new(Individual::new(KeyOp::Add(frank_add_op))));
        assert!(alice.register_individual(frank_indie.clone()).await);
        let frank_id = frank_indie.lock().await.id();
        // Receive additional prekey ops after registration
        alice
            .receive_prekey_op(&KeyOp::Rotate(frank_rot1))
            .await
            .unwrap();
        alice
            .receive_prekey_op(&KeyOp::Rotate(frank_rot2))
            .await
            .unwrap();

        // Create doc1 with bob (3 ops) and carol (2 ops)
        let doc1 = alice
            .generate_doc(vec![], nonempty![[0u8; 32]])
            .await
            .unwrap();
        let doc1_id = doc1.lock().await.doc_id();
        alice
            .add_member(
                Agent::Individual(bob_id, bob_indie.dupe()),
                &Membered::Document(doc1_id, doc1.dupe()),
                Access::Read,
                &[],
            )
            .await
            .unwrap();
        alice
            .add_member(
                Agent::Individual(carol_id, carol_indie.dupe()),
                &Membered::Document(doc1_id, doc1.dupe()),
                Access::Write,
                &[],
            )
            .await
            .unwrap();

        // Create doc2 with dan (1 op)
        let doc2 = alice
            .generate_doc(vec![], nonempty![[1u8; 32]])
            .await
            .unwrap();
        let doc2_id = doc2.lock().await.doc_id();
        alice
            .add_member(
                Agent::Individual(dan_id, dan_indie.dupe()),
                &Membered::Document(doc2_id, doc2.dupe()),
                Access::Read,
                &[],
            )
            .await
            .unwrap();

        // Create a group with carol (2 ops) and eve (4 ops), then add group to doc2
        let group = alice.generate_group(vec![]).await.unwrap();
        let group_id = group.lock().await.group_id();
        alice
            .add_member(
                Agent::Individual(carol_id, carol_indie.dupe()),
                &Membered::Group(group_id, group.dupe()),
                Access::Read,
                &[],
            )
            .await
            .unwrap();
        alice
            .add_member(
                Agent::Individual(eve_id, eve_indie.dupe()),
                &Membered::Group(group_id, group.dupe()),
                Access::Write,
                &[],
            )
            .await
            .unwrap();
        alice
            .add_member(
                Agent::Group(group_id, group.dupe()),
                &Membered::Document(doc2_id, doc2.dupe()),
                Access::Read,
                &[],
            )
            .await
            .unwrap();

        // Get the all-agents result
        let all_results = alice.reachable_prekey_ops_for_all_agents().await;

        // Verify no phantom agents: every agent in the index should match
        // a per-agent call. Count checked after all per-agent comparisons below.

        // Check the active agent
        let active_agent: Agent<_, _, _> = alice.active().lock().await.clone().into();
        let active_id: Identifier = active_agent.id();
        let active_all_ops = all_results.ops_for_agent(&active_id);
        assert!(
            active_all_ops.is_some(),
            "active agent should be in all_results"
        );
        let active_per_agent_ops = alice.reachable_prekey_ops_for_agent(&active_agent).await;
        let active_indexed_ids = &all_results.index[&active_id];
        let mut active_all_keys: Vec<_> = active_indexed_ids.iter().collect();
        active_all_keys.sort();
        let mut active_per_agent_keys: Vec<_> = active_per_agent_ops.keys().collect();
        active_per_agent_keys.sort();
        assert_eq!(
            active_all_keys, active_per_agent_keys,
            "key sets should match for active agent"
        );

        // For each agent in the index, compare with per-agent result
        let mut expected_checked: HashSet<Identifier> = HashSet::new();
        expected_checked.insert(active_id);
        let agents: Vec<(IndividualId, Arc<Mutex<Individual>>)> = vec![
            (bob_id, bob_indie),
            (carol_id, carol_indie),
            (dan_id, dan_indie),
            (eve_id, eve_indie),
            (frank_id, frank_indie),
        ];
        for (id, indie) in &agents {
            let agent_id: Identifier = (*id).into();
            expected_checked.insert(agent_id);

            let all_ops = all_results.ops_for_agent(&agent_id);
            assert!(all_ops.is_some(), "agent {:?} should be in all_results", id);

            let per_agent_ops = alice
                .reachable_prekey_ops_for_agent(&Agent::Individual(*id, indie.dupe()))
                .await;

            // Same identifier keys in index vs per-agent
            let indexed_ids = &all_results.index[&agent_id];
            let mut all_keys: Vec<_> = indexed_ids.iter().collect();
            all_keys.sort();
            let mut per_agent_keys: Vec<_> = per_agent_ops.keys().collect();
            per_agent_keys.sort();
            assert_eq!(
                all_keys, per_agent_keys,
                "key sets should match for agent {:?}",
                id
            );

            // Same flattened ops (compare by content digest)
            let mut all_digests: Vec<_> = all_ops
                .unwrap()
                .map(|op| Digest::hash(op.as_ref()))
                .collect();
            all_digests.sort();
            let mut per_agent_digests: Vec<_> = per_agent_ops
                .values()
                .flat_map(|ops| ops.iter())
                .map(|op| Digest::hash(op.as_ref()))
                .collect();
            per_agent_digests.sort();
            assert_eq!(
                all_digests, per_agent_digests,
                "ops should match for agent {:?}",
                id
            );
        }

        // Verify no phantom agents: every agent in the index should
        // produce results matching reachable_prekey_ops_for_agent.
        // (Some agents like group/doc owners may be implicitly registered.)
        for agent_id in all_results.agents() {
            if expected_checked.contains(agent_id) {
                continue; // already verified above
            }
            if let Some(indie) = alice.get_individual((*agent_id).into()).await {
                let per_agent_ops = alice
                    .reachable_prekey_ops_for_agent(&Agent::Individual((*agent_id).into(), indie))
                    .await;
                let indexed_ids = &all_results.index[agent_id];
                let mut all_keys: Vec<_> = indexed_ids.iter().collect();
                all_keys.sort();
                let mut per_agent_keys: Vec<_> = per_agent_ops.keys().collect();
                per_agent_keys.sort();
                assert_eq!(
                    all_keys, per_agent_keys,
                    "key sets should match for implicitly registered agent {:?}",
                    agent_id
                );
            }
        }
    }

    #[tokio::test]
    async fn test_membership_ops_for_all_agents_matches_per_agent() {
        test_utils::init_logging();

        let alice = make_keyhive().await;
        let bob = make_keyhive().await;
        let carol = make_keyhive().await;
        let dave = make_keyhive().await;
        let eve = make_keyhive().await;

        // Register all on alice
        let bob_add_op = bob.expand_prekeys().await.unwrap();
        let bob_indie = Arc::new(Mutex::new(Individual::new(KeyOp::Add(bob_add_op))));
        assert!(alice.register_individual(bob_indie.clone()).await);
        let bob_id = bob_indie.lock().await.id();

        let carol_add_op = carol.expand_prekeys().await.unwrap();
        let carol_indie = Arc::new(Mutex::new(Individual::new(KeyOp::Add(carol_add_op))));
        assert!(alice.register_individual(carol_indie.clone()).await);
        let carol_id = carol_indie.lock().await.id();

        let dave_add_op = dave.expand_prekeys().await.unwrap();
        let dave_indie = Arc::new(Mutex::new(Individual::new(KeyOp::Add(dave_add_op))));
        assert!(alice.register_individual(dave_indie.clone()).await);
        let dave_id = dave_indie.lock().await.id();

        let eve_add_op = eve.expand_prekeys().await.unwrap();
        let eve_indie = Arc::new(Mutex::new(Individual::new(KeyOp::Add(eve_add_op))));
        assert!(alice.register_individual(eve_indie.clone()).await);
        let eve_id = eve_indie.lock().await.id();

        // doc1: bob and carol are direct members
        let doc1 = alice
            .generate_doc(vec![], nonempty![[0u8; 32]])
            .await
            .unwrap();
        let doc1_id = doc1.lock().await.doc_id();
        alice
            .add_member(
                Agent::Individual(bob_id, bob_indie.dupe()),
                &Membered::Document(doc1_id, doc1.dupe()),
                Access::Read,
                &[],
            )
            .await
            .unwrap();
        alice
            .add_member(
                Agent::Individual(carol_id, carol_indie.dupe()),
                &Membered::Document(doc1_id, doc1.dupe()),
                Access::Write,
                &[],
            )
            .await
            .unwrap();

        // group: bob and carol
        let group = alice.generate_group(vec![]).await.unwrap();
        let group_id = group.lock().await.group_id();
        alice
            .add_member(
                Agent::Individual(bob_id, bob_indie.dupe()),
                &Membered::Group(group_id, group.dupe()),
                Access::Read,
                &[],
            )
            .await
            .unwrap();
        alice
            .add_member(
                Agent::Individual(carol_id, carol_indie.dupe()),
                &Membered::Group(group_id, group.dupe()),
                Access::Write,
                &[],
            )
            .await
            .unwrap();

        // doc2: group is a member (so bob and carol are transitive members)
        let doc2 = alice
            .generate_doc(vec![], nonempty![[1u8; 32]])
            .await
            .unwrap();
        let doc2_id = doc2.lock().await.doc_id();
        alice
            .add_member(
                Agent::Group(group_id, group.dupe()),
                &Membered::Document(doc2_id, doc2.dupe()),
                Access::Read,
                &[],
            )
            .await
            .unwrap();

        // dave: only on doc1 directly (not in any group)
        alice
            .add_member(
                Agent::Individual(dave_id, dave_indie.dupe()),
                &Membered::Document(doc1_id, doc1.dupe()),
                Access::Read,
                &[],
            )
            .await
            .unwrap();

        // eve: registered but not a member of anything

        // Revoke bob from doc1
        alice
            .revoke_member(
                bob_id.into(),
                false,
                &Membered::Document(doc1_id, doc1.dupe()),
            )
            .await
            .unwrap();

        // Get the all-agents result
        let all_results = alice.membership_ops_for_all_agents().await;

        // For each agent, compare with per-agent result
        let agents: Vec<(IndividualId, Arc<Mutex<Individual>>)> = vec![
            (bob_id, bob_indie),
            (carol_id, carol_indie),
            (dave_id, dave_indie),
            (eve_id, eve_indie),
        ];
        for (id, indie) in &agents {
            let agent = Agent::Individual(*id, indie.dupe());
            let agent_id: Identifier = (*id).into();

            let per_agent_ops = alice.membership_ops_for_agent(&agent).await;
            let per_agent_digests: HashSet<_> = per_agent_ops.keys().copied().collect();

            // Collect all digests for this agent across all sources
            let all_digests: HashSet<_> = all_results
                .ops_for_agent(&agent_id)
                .map(|iter| iter.map(|(digest, _)| *digest).collect())
                .unwrap_or_default();

            assert_eq!(
                per_agent_digests, all_digests,
                "membership op digests should match for agent {:?}",
                id
            );
        }
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

            assert_eq!(
                locked_trunk
                    .active
                    .lock()
                    .await
                    .prekey_pairs
                    .lock()
                    .await
                    .len(),
                7
            );
            assert_eq!(locked_trunk.delegations.lock().await.len(), 4);
            assert_eq!(locked_trunk.groups.lock().await.len(), 1);
            assert_eq!(locked_trunk.docs.lock().await.len(), 1);
        }

        let tx = transact_async(
            &trunk,
            |fork: Keyhive<_, _, _, _, Log<_, [u8; 32]>, _>| async move {
                // Depending on when the async runs
                let init_dlg_count = fork.delegations.lock().await.len();
                assert!(init_dlg_count >= 4);
                assert!(init_dlg_count <= 6);

                // Depending on when the async runs
                let init_doc_count = fork.docs.lock().await.len();
                assert!(init_doc_count == 1 || init_doc_count == 2);

                // Only one before this gets awaited
                let init_group_count = fork.groups.lock().await.len();
                assert_eq!(init_group_count, 1);

                assert_eq!(fork.active.lock().await.prekey_pairs.lock().await.len(), 7);
                fork.expand_prekeys().await.unwrap(); // 1 event (prekey)
                assert_eq!(fork.active.lock().await.prekey_pairs.lock().await.len(), 8);

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
            assert_eq!(
                locked_trunk
                    .active
                    .lock()
                    .await
                    .prekey_pairs
                    .lock()
                    .await
                    .len(),
                8
            );
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
