//! The primary API for the library.

use crate::{
    all_agent_events::{AllAgentEvents, EventDigest},
    archive::Archive,
    certificate::{decode_stored, explanation, root_edges, CertificateError, KeylineStorageError},
    cgka::{
        certificate_sets::{CertificateSets, CitationSet},
        citations::{citation_of, KeylineImplicitRemovesProtocol, Members, SharedCitations},
        AllCgkaOps, Cgka,
    },
    contact_card::ContactCard,
    content::heads::ContentHeads,
    error::not_found::NotFound,
    event::{static_event::StaticEvent, Event},
    listener::{log::Log, membership::MembershipListener},
    principal::{
        active::{Active, ImportPrekeySecretsError},
        document::{
            id::DocumentId, AddMemberError, DecryptError, DocCausalDecryptionError, Document,
            DocumentState, EncryptError, EncryptedContentWithUpdate, GenerateDocError,
        },
        group::{id::GroupId, Group, RevokeMemberError},
        individual::{
            id::IndividualId,
            op::{
                add_key::AddKeyOp, rotate_key::RotateKeyOp, AllReachablePrekeyOps, KeyOp, KeyOps,
            },
            Individual, IndividualState, ReceivePrekeyOpError,
        },
        membered::id::MemberedId,
        Principal,
    },
    stats::Stats,
    transact::{
        fork::ForkAsync,
        merge::{Merge, MergeAsync},
    },
    update::{AddMemberUpdate, RevokeMemberUpdate},
    util::content_addressed_map::CaMap,
};
use beekem::{
    cgka::{ImplicitRemovesProtocol, NoImplicitRemoves},
    collections::Set,
    error::CgkaError,
    id::MemberId,
    keys::{LeafKeyPair, ShareKeyMap},
    operation::{CgkaChange, CgkaOperation, CitationId},
    pcs_key::PcsKey,
};
use dupe::{Dupe, OptionDupedExt};
use future_form::FutureForm;
use futures::lock::Mutex;
use keyhive_codec::traits::{Decode, Encode};
use keyhive_content::{
    ancestor_key::AncestorKey,
    encrypted::EncryptedContent,
    envelope::Envelope,
    reference::ContentRef,
    store::{CausalDecryptionError, CausalDecryptionState, CiphertextStore, CiphertextStoreExt},
};
use keyhive_crypto::{
    bytes::Bytes,
    digest::Digest,
    identifier::{Identifier, InvalidIdentifier},
    share_key::{ShareKey, ShareSecretKey},
    signable::Signable,
    signer::{async_signer::AsyncSigner, ephemeral::EphemeralSigner, SigningError},
    symmetric_key::SymmetricKey,
    verifiable::Verifiable,
    verified::{self, SignError, Verified, VerifyError},
};
use keyline::{
    certificate::{Certificate, CertificateId, VerifiedCertificate},
    contract::{Keyline, Version},
    delegation::Delegation,
    power::Power,
    revocation::Revocation,
};
use nonempty::NonEmpty;
use std::{
    collections::{hash_map::Entry, BTreeMap, BTreeSet, HashMap, HashSet},
    fmt::{Debug, Formatter},
    marker::PhantomData,
    mem,
    sync::Arc,
};

use thiserror::Error;
use tracing::instrument;

/// The main object for a replica: a shared handle to its [`KeyhiveState`].
///
/// Cloning one is a single reference count increment, whatever the store and
/// listener types are, and every clone is the same keyhive: it observes the
/// others' writes. Principal handles hold one.
pub struct Keyhive<
    F: FutureForm,
    S: AsyncSigner<F> + Clone,
    T: ContentRef,
    P: Decode,
    C: CiphertextStore<F, T, P> + CiphertextStoreExt<F, T, P> + Clone,
    L: MembershipListener<F, T>,
    R: rand::CryptoRng,
    K: Keyline<F, RetentionWatermark = ContentHeads<T>>,
>(Arc<KeyhiveState<F, S, T, P, C, L, R, K>>);

/// A keyhive's state: the active identity, the principal tables, and the stores.
pub struct KeyhiveState<
    F: FutureForm,
    S: AsyncSigner<F> + Clone,
    T: ContentRef,
    P: Decode,
    C: CiphertextStore<F, T, P> + CiphertextStoreExt<F, T, P> + Clone,
    L: MembershipListener<F, T>,
    R: rand::CryptoRng,
    K: Keyline<F, RetentionWatermark = ContentHeads<T>>,
> {
    /// The [`Active`] individual. Unlocked: what it mutates is behind its own
    /// locks.
    active: Active<F, S, T, L>,

    /// The [`IndividualState`]s that are known to this replica.
    individuals: Mutex<HashMap<IndividualId, Arc<Mutex<IndividualState>>>>,

    /// The [`DocumentState`]s that are known to this replica.
    #[allow(clippy::type_complexity)]
    documents: Mutex<HashMap<DocumentId, Arc<Mutex<DocumentState<T>>>>>,

    /// `Cgka`s for documents this replica stands over but has not joined: a
    /// reader whose invitation (an add of this replica) has not merged yet, or
    /// a relay, which is never added. Operations merge here in causal order
    /// and are served like a held document's. A `Cgka` moves to `documents`
    /// once an invitation merges.
    unjoined: Mutex<HashMap<DocumentId, Cgka<KeylineImplicitRemovesProtocol>>>,

    /// What each CGKA operation's causal past cites. Used for authorizing
    /// CGKA operations that were generated from these certificates. Locked
    /// after a document's lock or `unjoined` when both are held.
    certificate_sets: Mutex<CertificateSets>,

    /// [`StaticEvent`]s that are still awaiting dependencies.
    pending_events: Mutex<Vec<Arc<StaticEvent<T>>>>,

    /// Observer for [`Event`]s. Intended for running live updates.
    event_listener: L,

    /// Storage for ciphertexts that cannot yet be decrypted.
    ciphertext_store: C,

    /// Cryptographically secure (pseudo)random number generator.
    csprng: Arc<Mutex<R>>,

    /// The Keyline store, with the lock that serializes inserts into it.
    ///
    /// The copy of a keyhive that a transaction works on (its fork, see
    /// [`ForkAsync`] for `Keyhive`) shares this store rather than copying it,
    /// so a transaction is not isolated for certificates.
    certificates: Arc<Certificates<K>>,

    _plaintext_phantom: PhantomData<P>,
}

/// Cloning a [`Keyhive`] is `O(1)`: it is an `Arc` refcount bump, not a copy.
/// The clones share live state, so a clone observes later changes rather
/// than a snapshot. [`Dupe`] is the same.
///
/// Written by hand: a derive would require `Clone` of every parameter.
impl<F, S, T, P, C, L, R, K> Clone for Keyhive<F, S, T, P, C, L, R, K>
where
    F: FutureForm,
    S: AsyncSigner<F> + Clone,
    T: ContentRef,
    P: Decode,
    C: CiphertextStore<F, T, P> + CiphertextStoreExt<F, T, P> + Clone,
    L: MembershipListener<F, T>,
    R: rand::CryptoRng,
    K: Keyline<F, RetentionWatermark = ContentHeads<T>>,
{
    fn clone(&self) -> Self {
        Keyhive(self.0.dupe())
    }
}

impl<F, S, T, P, C, L, R, K> Dupe for Keyhive<F, S, T, P, C, L, R, K>
where
    F: FutureForm,
    S: AsyncSigner<F> + Clone,
    T: ContentRef,
    P: Decode,
    C: CiphertextStore<F, T, P> + CiphertextStoreExt<F, T, P> + Clone,
    L: MembershipListener<F, T>,
    R: rand::CryptoRng,
    K: Keyline<F, RetentionWatermark = ContentHeads<T>>,
{
    fn dupe(&self) -> Self {
        self.clone()
    }
}

impl<F, S, T, P, C, L, R, K> std::ops::Deref for Keyhive<F, S, T, P, C, L, R, K>
where
    F: FutureForm,
    S: AsyncSigner<F> + Clone,
    T: ContentRef,
    P: Decode,
    C: CiphertextStore<F, T, P> + CiphertextStoreExt<F, T, P> + Clone,
    L: MembershipListener<F, T>,
    R: rand::CryptoRng,
    K: Keyline<F, RetentionWatermark = ContentHeads<T>>,
{
    type Target = KeyhiveState<F, S, T, P, C, L, R, K>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<
        F: FutureForm,
        S: AsyncSigner<F> + Clone,
        T: ContentRef,
        P: Decode,
        C: CiphertextStore<F, T, P> + CiphertextStoreExt<F, T, P> + Clone,
        L: MembershipListener<F, T>,
        R: rand::CryptoRng + rand::RngCore,
        K: Keyline<F, RetentionWatermark = ContentHeads<T>>,
    > Keyhive<F, S, T, P, C, L, R, K>
where
    K::Error: Send + Sync + 'static,
{
    #[instrument(skip_all)]
    pub fn id(&self) -> IndividualId {
        self.active.id()
    }

    /// A new replica with a fresh active individual.
    ///
    /// This keyhive must be the only writer to the store behind `keyline`.
    /// Moving `keyline` in ensures that for a backend that owns its data, such
    /// as `MemoryKeyline`, but not for one that is a handle to shared storage,
    /// such as a database: another handle writing to the same store would
    /// bypass the insert lock, the listener and reconciliation.
    #[instrument(skip_all)]
    pub async fn generate(
        signer: S,
        ciphertext_store: C,
        event_listener: L,
        keyline: K,
        mut csprng: R,
    ) -> Result<Self, SignError> {
        let inner_active = Active::generate(signer, event_listener.clone(), &mut csprng).await?;
        let active_id = inner_active.id();

        Ok(Keyhive(Arc::new(KeyhiveState {
            individuals: Mutex::new(HashMap::from_iter([(
                active_id,
                inner_active.individual().dupe(),
            )])),
            active: inner_active,
            documents: Mutex::new(HashMap::new()),
            unjoined: Mutex::new(HashMap::new()),
            certificate_sets: Mutex::new(CertificateSets::new()),
            pending_events: Mutex::new(Vec::new()),
            ciphertext_store,
            event_listener,
            csprng: Arc::new(Mutex::new(csprng)),
            certificates: Arc::new(Certificates {
                store: keyline,
                reconciled: async_lock::Mutex::new(None),
                cited: SharedCitations::default(),
            }),
            _plaintext_phantom: PhantomData,
        })))
    }

    /// The current [`Active`] Keyhive user.
    #[instrument(skip_all)]
    pub fn active(&self) -> &Active<F, S, T, L> {
        &self.active
    }

    /// A handle on this replica's own individual. To introduce it to a peer,
    /// share a contact card ([`Self::generate_contact_card`]).
    pub fn individual(&self) -> Individual<Self> {
        Individual::new(self.clone(), self.id())
    }

    /// Generate a group: the active individual and `coparents` are its admins, by
    /// root edges signed with a fresh key that is then discarded.
    #[instrument(skip_all)]
    pub async fn generate_group(
        &self,
        coparents: Vec<Identifier>,
    ) -> Result<GroupId, GenerateGroupError<K::Error>> {
        let (group_id, roots) = self
            .found::<GenerateGroupError<K::Error>>(coparents)
            .await?;
        let group_id = GroupId(group_id);
        self.insert_certificates(&roots).await?;
        Ok(group_id)
    }

    /// A fresh subject's identifier, and root edges making the active individual
    /// and `coparents` its admins, signed with its key, which is discarded.
    async fn found<
        E: From<NotFound> + From<KeylineStorageError<K::Error>> + From<CertificateError>,
    >(
        &self,
        coparents: Vec<Identifier>,
    ) -> Result<(Identifier, Vec<VerifiedCertificate<ContentHeads<T>>>), E> {
        for id in &coparents {
            if !self.is_known(*id).await? {
                return Err(NotFound::new(*id).into());
            }
        }
        let creators = std::iter::once(Identifier::from(self.id())).chain(coparents);
        let (roots, subject) = {
            let mut csprng = self.csprng.lock().await;
            EphemeralSigner::with_signer(&mut *csprng, |subject, signer| {
                root_edges(&*signer, subject, creators)
            })
        };
        Ok((
            subject,
            roots?
                .into_iter()
                .map(|root| VerifiedCertificate::Delegation(Arc::new(root)))
                .collect(),
        ))
    }

    /// The Keyline store this replica's certificates are written to. Inside
    /// the crate only: an insert that bypasses [`Keyhive`] skips the insert
    /// lock, the listener and reconciliation.
    #[cfg(not(any(test, feature = "test_utils")))]
    pub(crate) fn keyline(&self) -> &K {
        &self.certificates.store
    }

    /// The Keyline store this replica's certificates are written to; public
    /// for tests that query it.
    #[cfg(any(test, feature = "test_utils"))]
    pub fn keyline(&self) -> &K {
        &self.certificates.store
    }

    /// Insert certificates under the insert lock, and tell the listener about
    /// those the store did not already hold.
    async fn insert_certificates(
        &self,
        batch: &[VerifiedCertificate<ContentHeads<T>>],
    ) -> Result<(), KeylineStorageError<K::Error>> {
        let fresh = {
            let mut reconciled = self.certificates.reconciled.lock().await;
            self.insert_fresh(&mut reconciled, batch).await?
        };
        // Listeners run with no lock held, so they may call back in.
        for cert in &fresh {
            self.notify(cert).await;
        }
        Ok(())
    }

    /// Insert the certificates of `batch` the store does not hold yet, and
    /// return them. Called with the insert lock held; advances its version.
    async fn insert_fresh(
        &self,
        reconciled: &mut Option<Version>,
        batch: &[VerifiedCertificate<ContentHeads<T>>],
    ) -> Result<Vec<VerifiedCertificate<ContentHeads<T>>>, KeylineStorageError<K::Error>> {
        let mut seen = BTreeSet::new();
        let mut fresh = Vec::with_capacity(batch.len());
        for cert in batch {
            let id = cert.id();
            let held = self
                .keyline()
                .contains(id)
                .await
                .map_err(KeylineStorageError::new)?
                .value;
            if seen.insert(id) && !held {
                fresh.push(cert.clone());
            }
        }
        if !fresh.is_empty() {
            let version = self
                .keyline()
                .insert(fresh.clone())
                .await
                .map_err(KeylineStorageError::new)?;
            *reconciled = Some(version);
            self.certificates.cited.lock().insert_multiple(&fresh);
        }
        Ok(fresh)
    }

    /// The protocol for removing CGKA members of `doc` that a CGKA batch's certificate
    /// set (what it and the batches before it cite) does not entitle to remain in the
    /// CGKA group.
    fn implicit_removes_protocol(&self, doc: Identifier) -> KeylineImplicitRemovesProtocol {
        KeylineImplicitRemovesProtocol::new(doc, self.certificates.cited.dupe())
    }

    /// `resource`'s members over the certificates of `cited` this replica
    /// records, according to Keyline. It's cached by the subset and a
    /// [`KeylineImplicitRemovesProtocol`] reads the answer from the cache.
    async fn members_over<Ids: Sync>(
        &self,
        cited: &Ids,
        resource: Identifier,
    ) -> Result<Members, KeylineStorageError<K::Error>>
    where
        for<'a> &'a Ids: IntoIterator<Item = &'a CitationId>,
    {
        let (subset, key) = {
            let citations = self.certificates.cited.lock();
            let key = citations.key(cited, resource);
            if let Some(hit) = citations.members(&key) {
                return Ok(hit);
            }
            (citations.certificate_subset(cited), key)
        };
        let answer = self
            .keyline()
            .members_for_subset(subset, resource)
            .await
            .map_err(KeylineStorageError::new)?
            .value;
        Ok(self.certificates.cited.lock().cache(key, answer))
    }

    /// Every node with `Read` or higher standing over `resource` in the cited
    /// certificates.
    async fn readers_over(
        &self,
        cited: &CitationSet,
        resource: Identifier,
    ) -> Result<BTreeSet<Identifier>, KeylineStorageError<K::Error>> {
        Ok(self
            .members_over(cited, resource)
            .await?
            .iter()
            .filter(|(_, power)| power.is_reader())
            .map(|(id, _)| *id)
            .collect())
    }

    /// Whether `who` has `Read` or higher standing over `resource` in the
    /// cited certificates.
    async fn is_reader_over(
        &self,
        cited: &CitationSet,
        resource: Identifier,
        who: Identifier,
    ) -> Result<bool, KeylineStorageError<K::Error>> {
        Ok(self
            .members_over(cited, resource)
            .await?
            .get(&who)
            .is_some_and(|power| power.is_reader()))
    }

    /// Cache Keyline's answer to every certificate set a replay of cgka's CGKA
    /// graph queries, fetching those not already cached.
    async fn cache_replay_answers(
        &self,
        doc: Identifier,
        cgka: &Cgka<KeylineImplicitRemovesProtocol>,
    ) -> Result<(), KeylineStorageError<K::Error>> {
        for set in cgka.membership_sets().unwrap_or_default() {
            self.members_over(&set, doc).await?;
        }
        Ok(())
    }

    /// Run `f` on `cgka`, the CGKA for `doc`, first fetching from Keyline any
    /// membership answers `f` requires.
    ///
    /// BeeKEM queries its implicit removes protocol synchronously but Keyline
    /// answers asynchronously so the protocol answers only from the cache in
    /// `CitedCertificates`. When a cached answer is missing, the CGKA fails with
    /// `CgkaError::MembershipUnknown` and makes no changes. This function fetches
    /// that answer and runs `f` again. A replay asks about every batch of the
    /// CGKA graph, which would mean one rerun per batch. So the first time an
    /// answer is missing, it also fetches every answer a replay of the whole
    /// graph requests, and the second run normally succeeds.
    ///
    /// Fails if Keyline does. Otherwise returns `f`'s result once `f` no longer
    /// lacks an answer.
    async fn require_keyline_answers<V, E: LacksKeylineAnswer>(
        &self,
        doc: Identifier,
        cgka: &mut Cgka<KeylineImplicitRemovesProtocol>,
        mut f: impl FnMut(&mut Cgka<KeylineImplicitRemovesProtocol>) -> Result<V, E>,
    ) -> Result<Result<V, E>, KeylineStorageError<K::Error>> {
        // Keep every answer cached for `doc` until this returns.
        let _replaying = self.certificates.cited.replaying(doc);
        let mut fetched = BTreeSet::new();
        loop {
            let result = f(cgka);
            let Some(cited) = result.as_ref().err().and_then(LacksKeylineAnswer::lacked) else {
                return Ok(result);
            };
            let cited = cited.clone();
            // If we're missing an answer we've already fetched, fetching again won't help.
            if !fetched.insert(self.certificates.cited.lock().key(&cited, doc)) {
                return Ok(result);
            }
            self.members_over(&cited, doc).await?;
            // We only cache replay answers the first time. Doing it again
            // would be wasted work.
            if fetched.len() == 1 {
                self.cache_replay_answers(doc, cgka).await?;
            }
        }
    }

    /// Replay `doc`'s CGKA graph in `state` if operations are pending,
    /// fetching the required membership answers.
    async fn settle_cgka(
        &self,
        doc: Identifier,
        state: &mut DocumentState<T>,
    ) -> Result<(), CgkaSyncError<K::Error>> {
        self.require_keyline_answers(doc, state.cgka_mut(), Cgka::replay_if_pending)
            .await??;
        Ok(())
    }

    /// [`Self::settle_cgka`] under the lock a write holds. The write's own adds
    /// and removes leave a replay pending if the membership answer they need
    /// was evicted after it was fetched, as a decryption's replay can do.
    async fn settle_for_write(
        &self,
        doc: DocumentId,
        state: &mut DocumentState<T>,
    ) -> Result<(), EncryptError> {
        self.settle_cgka(doc.into(), state)
            .await
            .map_err(|e| EncryptError::PrepareToWrite(Box::new(e)))
    }

    /// The members of `doc`'s CGKA group in `state`, replaying its CGKA graph
    /// first if operations are pending.
    pub(crate) async fn cgka_group_members(
        &self,
        doc: Identifier,
        state: &Arc<Mutex<DocumentState<T>>>,
    ) -> Result<BTreeSet<IndividualId>, CgkaSyncError<K::Error>> {
        let mut locked = state.lock().await;
        self.settle_cgka(doc, &mut locked).await?;
        let members = locked.cgka_members()?.collect();
        Ok(members)
    }

    /// Build a CGKA from `ops`. Apply them in causal order, then adopt the
    /// the secrets `me` holds for its key in the CGKA group. An operation
    /// that cannot be applied is logged and skipped. Returns the
    /// CGKA and the operations left out because a predecessor is missing.
    ///
    /// The operations are applied without implicit removes and the CGKA then
    /// replays its graph once with the document's implicit removes protocol. The replay asks Keyline only for
    /// what the cached non-members do not cover, so a fork or a reload of a graph
    /// already replayed does not require a new query. If Keyline cannot answer
    /// at that point, or the replay fails, that is logged and the replay waits
    /// for the CGKA's next use.
    async fn cgka_from_ops(
        &self,
        doc_id: DocumentId,
        mut ops: Vec<Arc<Verified<CgkaOperation>>>,
        me: IndividualId,
        secrets: &BTreeMap<ShareKey, ShareSecretKey>,
    ) -> (
        Cgka<KeylineImplicitRemovesProtocol>,
        Vec<Arc<Verified<CgkaOperation>>>,
    ) {
        let doc = Identifier::from(doc_id);
        let mut cgka = Cgka::new(doc_id, me, ShareKeyMap::new(), NoImplicitRemoves);
        let mut has_progressed = true;
        while has_progressed {
            has_progressed = false;
            ops.retain(|op| {
                match apply_one::<core::convert::Infallible, _>(&mut cgka, op.dupe(), me, secrets) {
                    Ok(_) => {
                        has_progressed = true;
                        false
                    }
                    Err(ReceiveCgkaOpError::CgkaError(CgkaError::OutOfOrderOperation)) => true,
                    Err(error) => {
                        tracing::warn!(%doc_id, %error, "an archived operation does not apply");
                        false
                    }
                }
            });
        }
        adopt_own_cgka_secrets(&mut cgka, me, secrets);
        let mut cgka = cgka.with_implicit_removes_protocol(self.implicit_removes_protocol(doc));
        let replayed = self
            .require_keyline_answers(doc, &mut cgka, Cgka::replay_if_pending)
            .await;
        match replayed {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                tracing::warn!(%doc_id, %error, "an archived CGKA graph does not replay");
            }
            Err(error) => {
                tracing::warn!(%doc_id, %error, "Keyline could not answer for an archived CGKA graph");
            }
        }
        (cgka, ops)
    }

    /// Before writing to `doc_id`, issue the CGKA operations this
    /// replica's certificates imply for it ([`Self::issue_implied_cgka_ops`]).
    ///
    /// A CGKA graph can lag behind this replica's certificates. Inserting a
    /// certificate issues operations only for the documents the inserting
    /// replica has locally. Two certificates from different signers can also
    /// potentially remove a member only together, so that neither signer issues
    /// the remove.
    ///
    /// Checking at write time means no honest writer encrypts to a member of
    /// the CGKA group that lacks `Read` in the writer's certificates. If it
    /// cannot remove such a member, the write is refused. Appends the
    /// operations issued to `fresh`.
    async fn reconcile_before_writing(
        &self,
        reconciled: &Reconciled<'_>,
        doc_id: DocumentId,
        fresh: &mut Vec<Arc<Verified<CgkaOperation>>>,
    ) -> Result<(), EncryptError> {
        let doc = Identifier::from(doc_id);
        let Some(state) = self.document_state(doc_id).await else {
            return Ok(());
        };
        let implied = self
            .issue_implied_cgka_ops(reconciled, doc_id, doc, &state, fresh)
            .await
            .map_err(|e| EncryptError::PrepareToWrite(Box::new(e)))?;
        match implied {
            ImpliedCgkaOpsOutcome::Success => Ok(()),
            ImpliedCgkaOpsOutcome::RemoveBlocked => Err(EncryptError::CgkaMemberLacksRead),
        }
    }

    /// Begin a write to `doc`. Take the insert lock, issue the CGKA operations
    /// this replica's certificates imply for `doc`
    /// ([`Self::reconcile_before_writing`]), then rotate this identity's key
    /// in its CGKA group if that key is a prekey that's been rotated away.
    ///
    /// The lock stays held until [`Self::finish_write`] so no operation
    /// received after the reconciliation merges before the write. One could
    /// otherwise add a member that lacks `Read` in this replica's
    /// certificates. If preparing fails, the write is finished here.
    async fn prepare_to_write(&self, doc: DocumentId) -> Result<Writing<'_>, EncryptError> {
        let reconciled = self.certificates.reconciled.lock().await;
        let mut fresh = Vec::new();
        let prepared = async {
            self.reconcile_before_writing(&reconciled, doc, &mut fresh)
                .await?;
            if self.own_key_is_a_retired_prekey(doc).await {
                let (op, _) = self.rotate_own_key(doc).await?;
                fresh.push(Arc::new(op));
            }
            Ok(())
        }
        .await;
        let writing = Writing { reconciled, fresh };
        match prepared {
            Ok(()) => Ok(writing),
            Err(error) => {
                self.finish_write(writing).await;
                Err(error)
            }
        }
    }

    /// Release a write's insert lock, then, after dropping the lock,
    /// tell the listener about the CGKA operations it issued.
    async fn finish_write(&self, writing: Writing<'_>) {
        let Writing { reconciled, fresh } = writing;
        drop(reconciled);
        for op in &fresh {
            self.event_listener.on_cgka_op(op).await;
        }
    }

    /// Whether this identity's key in `doc_id`'s CGKA group is a prekey it
    /// has since rotated away. The adder chooses that key, and a key proof
    /// shows only that the member once published it, so a malicious member
    /// could add someone under a key that leaked. Writing rotates such a key
    /// first.
    async fn own_key_is_a_retired_prekey(&self, doc_id: DocumentId) -> bool {
        let Some(state) = self.document_state(doc_id).await else {
            return false;
        };
        let Some(key) = state.lock().await.cgka().owner_leaf_key() else {
            return false;
        };
        let individual = self.active.individual();
        let locked = individual.lock().await;
        locked
            .prekey_ops()
            .values()
            .any(|op| matches!(op.as_ref(), KeyOp::Rotate(r) if r.payload().old == key))
    }

    /// Issue the CGKA operations this replica's certificates imply for
    /// `doc_id`. Issues a remove if a member of the CGKA group lacks `Read`
    /// in the next operation's certificate set, then an add, with a key proof,
    /// for each reader who is not currently a CGKA member and whose prekeys
    /// this replica has locally.
    ///
    /// Each operation is issued only if this replica has `Read` in its signing
    /// set according to Keyline.
    ///
    /// Appends the operations stored to `fresh`.
    async fn issue_implied_cgka_ops(
        &self,
        _reconciled: &Reconciled<'_>,
        doc_id: DocumentId,
        doc: Identifier,
        state: &Arc<Mutex<DocumentState<T>>>,
        fresh: &mut Vec<Arc<Verified<CgkaOperation>>>,
    ) -> Result<ImpliedCgkaOpsOutcome, CgkaSyncError<K::Error>> {
        let signer = self.active.signer.clone();
        // Settle first. A replay evicts the answers cached before it, which
        // would include the next operation's.
        let members = self.cgka_group_members(doc, state).await?;
        // Every insert through this keyhive takes the insert lock, so the first
        // operation issued cites everything new and the rest cite nothing. Only
        // an operation that cites something changes what the next one cites and
        // whether this replica may sign it, so only then is that recomputed,
        // before the next operation.
        let NextCitations {
            mut cited,
            readers,
            mut may_sign,
        } = self.next_citations(doc, state).await?;
        let triggers_removes = members
            .iter()
            .any(|member| !readers.contains(&Identifier::from(*member)));
        if !may_sign {
            return Ok(if triggers_removes {
                ImpliedCgkaOpsOutcome::RemoveBlocked
            } else {
                ImpliedCgkaOpsOutcome::Success
            });
        }
        let mut stale = false;
        if triggers_removes {
            // The remove may cite this replica's own revocation.
            stale = !cited.is_empty();
            let remove_op = state
                .lock()
                .await
                .remove_cgka_members_by_citations(std::mem::take(&mut cited), &signer)
                .await?;
            fresh.push(Arc::new(remove_op));
        }
        for reader in readers.iter().map(|id| IndividualId::from(*id)) {
            if members.contains(&reader) {
                continue;
            }
            let Some((prekey, key_proof)) = self.addable_key(reader, doc_id).await else {
                continue;
            };
            if std::mem::take(&mut stale) {
                NextCitations {
                    cited,
                    may_sign,
                    ..
                } = self.next_citations(doc, state).await?;
            }
            if !may_sign {
                break;
            }
            stale = !cited.is_empty();
            let made = state
                .lock()
                .await
                .add_cgka_member(
                    reader,
                    prekey,
                    Some(key_proof),
                    std::mem::take(&mut cited),
                    &signer,
                )
                .await?;
            fresh.extend(made.into_iter().map(Arc::new));
        }
        Ok(ImpliedCgkaOpsOutcome::Success)
    }

    /// The prekey `reader` would be added to `doc_id` with, and the encoded
    /// prekey operation proving it, if this replica has both.
    async fn addable_key(
        &self,
        reader: IndividualId,
        doc_id: DocumentId,
    ) -> Option<(ShareKey, Vec<u8>)> {
        let individual = self.individual_state(reader).await?;
        let prekey = individual.lock().await.pick_prekey(doc_id).copied()?;
        let key_proof = self.key_proof(reader, &prekey).await?;
        Some((prekey, key_proof))
    }

    /// What the next CGKA operation on `doc` cites and what follows
    /// from that.
    async fn next_citations(
        &self,
        doc: Identifier,
        state: &Arc<Mutex<DocumentState<T>>>,
    ) -> Result<NextCitations, KeylineStorageError<K::Error>> {
        let predecessor_set = {
            let locked = state.lock().await;
            let cgka = locked.cgka();
            // Every head is in the CGKA graph.
            self.certificate_sets
                .lock()
                .await
                .predecessor_set(cgka, cgka.heads())
                .unwrap_or_default()
        };
        let cited = self.citations_for(doc, &predecessor_set).await?;
        // The signing set is all predecessor citations plus any delegations
        // this operation cites.
        let mut signing_set = predecessor_set;
        {
            let citations = self.certificates.cited.lock();
            signing_set.extend(
                cited
                    .iter()
                    .filter(|c| citations.delegation(c).is_some())
                    .copied(),
            );
        }
        let may_sign = self
            .is_reader_over(&signing_set, doc, self.active.id().into())
            .await?;
        let mut certificate_set = signing_set;
        certificate_set.extend(cited.iter().copied());
        let readers = self.readers_over(&certificate_set, doc).await?;
        Ok(NextCitations {
            cited,
            readers,
            may_sign,
        })
    }

    /// What an operation on `doc` cites when its predecessor set is
    /// `predecessor_set`, i.e., every certificate of `closure(doc)` not
    /// in that predecessor set.
    async fn citations_for(
        &self,
        doc: Identifier,
        predecessor_set: &CitationSet,
    ) -> Result<BTreeSet<CitationId>, KeylineStorageError<K::Error>> {
        let closure = self
            .keyline()
            .closure(doc)
            .await
            .map_err(KeylineStorageError::new)?
            .value;
        let cited: Vec<_> = closure
            .iter()
            .filter(|cert| !predecessor_set.contains(&citation_of(cert.id())))
            .collect();
        // The store can contain certificates this keyhive never inserted, such
        // as those it had when the keyhive was rebuilt from an archive.
        let unrecorded: Vec<_> = {
            let recorded = self.certificates.cited.lock();
            cited
                .iter()
                .filter(|cert| !recorded.contains(&citation_of(cert.id())))
                .map(|cert| (*cert).clone())
                .collect()
        };
        if !unrecorded.is_empty() {
            // The store verified them on insert. Verifying again is the only
            // way back to a `Verified` delegation, which authorization reads.
            let verified: Vec<_> = unrecorded
                .into_iter()
                .filter_map(|cert| cert.verify().ok())
                .collect();
            self.certificates.cited.lock().insert_multiple(&verified);
        }
        // A certificate that does not verify is not cited.
        let recorded = self.certificates.cited.lock();
        Ok(cited
            .iter()
            .map(|cert| citation_of(cert.id()))
            .filter(|citation| recorded.contains(citation))
            .collect())
    }

    /// Make sure every certificate `op` cites is recorded in
    /// [`CitedCertificates`], fetching any missing one from the Keyline
    /// store. Returns `false` if the store lacks one.
    async fn record_citations(
        &self,
        op: &CgkaOperation,
    ) -> Result<bool, KeylineStorageError<K::Error>> {
        for citation in op.citations() {
            let recorded = self.certificates.cited.lock().contains(citation);
            if recorded {
                continue;
            }
            let Some(cert) = self.stored_certificate(citation).await? else {
                return Ok(false);
            };
            self.certificates.cited.lock().insert(&cert);
        }
        Ok(true)
    }

    /// The certificate `citation` refers to, if the Keyline store has it.
    async fn stored_certificate(
        &self,
        citation: &CitationId,
    ) -> Result<Option<VerifiedCertificate<ContentHeads<T>>>, KeylineStorageError<K::Error>> {
        let ids = [
            CertificateId::Delegation(Digest::from(citation.0)),
            CertificateId::Revocation(Digest::from(citation.0)),
        ];
        for id in ids {
            let cert = self
                .keyline()
                .get(id)
                .await
                .map_err(KeylineStorageError::new)?
                .value;
            if let Some(cert) = cert {
                // The store verified it on insert. Verifying again is the only
                // way back to a `Verified` delegation, which authorization
                // reads.
                return Ok(cert.verify().ok());
            }
        }
        Ok(None)
    }

    /// The encoded prekey operation in which `who` published `pk`, if this
    /// replica has it.
    async fn key_proof(&self, who: IndividualId, pk: &ShareKey) -> Option<Vec<u8>> {
        let state = if who == self.active.id() {
            self.active.individual()
        } else {
            self.individual_state(who).await?
        };
        let state = state.lock().await;
        state
            .prekey_ops()
            .values()
            .find(|op| op.new_key() == pk)
            .map(|op| op.to_key_proof())
    }

    /// Tell the listener about CGKA operations this replica wrote. They are
    /// already in its CGKA graph.
    async fn record_cgka_ops<I: IntoIterator<Item = Arc<Verified<CgkaOperation>>>>(&self, ops: I) {
        for op in ops {
            self.event_listener.on_cgka_op(&op).await;
        }
    }

    /// Tell the listener about a certificate this replica holds for the first
    /// time. Called with no lock held, so the listener may call back in.
    async fn notify(&self, cert: &VerifiedCertificate<ContentHeads<T>>) {
        match cert {
            VerifiedCertificate::Delegation(d) => self.event_listener.on_delegation(d).await,
            VerifiedCertificate::Revocation(r) => self.event_listener.on_revocation(r).await,
        }
    }

    /// Insert `batch` and issue the CGKA operations it implies for every
    /// document held here whose readers it changed, through
    /// [`Self::issue_implied_cgka_ops`]. Every such document, not only the one
    /// written: a document can be a member of
    /// another, so writing to one changes the readers of those it reaches.
    ///
    /// The insert lock is held throughout, so the diff is exactly this batch's
    /// effect, and concurrent writes on this keyhive reach its CGKA graphs in
    /// the order they reached the store. That does not hold between a fork and
    /// its trunk, which share the store but not the CGKA graphs (see
    /// [`ForkAsync`] for `Keyhive`). Each operation is collected as soon as it
    /// is made, so the listener hears of every operation a CGKA graph took,
    /// together with the new certificates, once the lock is released, whether
    /// or not reconciliation finished. A document a failure left behind gets
    /// its operations from the next member to write to it ([`Self::reconcile_before_writing`]).
    async fn insert_and_reconcile<E: From<KeylineStorageError<K::Error>>>(
        &self,
        batch: &[VerifiedCertificate<ContentHeads<T>>],
    ) -> Result<Vec<Verified<CgkaOperation>>, E> {
        let mut fresh = Vec::new();
        let mut ops = Vec::new();
        let result = {
            let mut reconciled = self.certificates.reconciled.lock().await;
            self.reconcile_locked::<E>(&mut reconciled, batch, &mut fresh, &mut ops)
                .await
        };
        // Listeners run with no lock held, so they may call back in.
        for cert in &fresh {
            self.notify(cert).await;
        }
        for op in &ops {
            self.event_listener.on_cgka_op(op).await;
        }
        result.map(|()| ops.iter().map(|op| op.as_ref().clone()).collect())
    }

    /// [`Self::insert_and_reconcile`] with the insert lock held. Appends the
    /// certificates it inserts to `fresh` and the operations it stores to
    /// `ops`, including when it fails partway.
    ///
    /// Each document whose readers the batch changed gets the operations
    /// [`Self::issue_implied_cgka_ops`] issues.
    async fn reconcile_locked<E: From<KeylineStorageError<K::Error>>>(
        &self,
        reconciled: &mut Reconciled<'_>,
        batch: &[VerifiedCertificate<ContentHeads<T>>],
        fresh: &mut Vec<VerifiedCertificate<ContentHeads<T>>>,
        ops: &mut Vec<Arc<Verified<CgkaOperation>>>,
    ) -> Result<(), E> {
        let docs: Vec<(DocumentId, Identifier, Arc<Mutex<DocumentState<T>>>)> = self
            .documents
            .lock()
            .await
            .iter()
            .map(|(id, d)| (*id, Identifier::from(*id), d.dupe()))
            .collect();

        let mut before = Vec::with_capacity(docs.len());
        for (doc_id, doc, _) in &docs {
            let (version, readers) = self.readers(*doc).await?;
            if reconciled.is_some_and(|v| v != version) {
                tracing::warn!(%doc_id, "the Keyline store changed outside this keyhive");
            }
            before.push(readers);
        }
        *fresh = self.insert_fresh(reconciled, batch).await?;
        if fresh.is_empty() {
            return Ok(());
        }
        for ((doc_id, doc, state), before) in docs.into_iter().zip(before) {
            // Inserting is not refused for a remove this replica may not
            // sign. The next write to the document refuses instead.
            let issued = match self.readers(doc).await {
                Ok((_, readers)) if readers == before => continue,
                Ok(_) => self
                    .issue_implied_cgka_ops(reconciled, doc_id, doc, &state, ops)
                    .await
                    .map(|_| ()),
                Err(e) => Err(e.into()),
            };
            if let Err(error) = issued {
                tracing::warn!(%doc_id, %error, "could not issue the CGKA operations the certificates imply");
            }
        }
        Ok(())
    }

    /// Everyone who can read `doc` in Keyline, and the store version read.
    /// Groups and documents are among them. Only individuals can be members
    /// of a CGKA group, and only those whose prekeys this replica has can be
    /// added.
    async fn readers(
        &self,
        doc: Identifier,
    ) -> Result<(Version, BTreeSet<IndividualId>), KeylineStorageError<K::Error>> {
        let answer = self
            .keyline()
            .members(doc)
            .await
            .map_err(KeylineStorageError::new)?;
        let readers = answer
            .value
            .into_iter()
            .filter(|(_, power)| power.is_reader())
            .map(|(id, _)| IndividualId(id))
            .collect();
        Ok((answer.version, readers))
    }

    /// The watermark a revocation of a delegation about `subject` records: the
    /// content heads of each held document that `subject` is or stands over,
    /// the documents whose readers the revocation can change. The content layer
    /// compares later content from the revoked member against it. The heads are
    /// those last set with [`Self::set_content_heads`]; a document with none is
    /// left out.
    async fn content_watermark(
        &self,
        subject: Identifier,
    ) -> Result<BTreeMap<Identifier, ContentHeads<T>>, KeylineStorageError<K::Error>> {
        let documents: Vec<_> = {
            self.documents
                .lock()
                .await
                .iter()
                .map(|(id, state)| (*id, state.dupe()))
                .collect()
        };
        let mut retain = BTreeMap::new();
        for (doc_id, state) in documents {
            let doc = Identifier::from(doc_id);
            if doc != subject && self.positive_power(doc, subject).await?.is_none() {
                continue;
            }
            let heads: ContentHeads<T> = state.lock().await.content_heads.iter().cloned().collect();
            // No heads known here: say nothing, rather than "keep none".
            if !heads.is_empty() {
                retain.insert(doc, heads);
            }
        }
        Ok(retain)
    }

    /// Adoption: the delegations that keep `removed`'s admissions alive once
    /// `removed` is revoked from `subject`. Each live delegation `removed`
    /// issued about `subject` is re-issued from `revoker` with the same
    /// audience, at its power but no more than the `held` power the revoker
    /// has over `subject`.
    ///
    /// The members they admitted then keep their standing, and so does
    /// everything those members admitted in turn.
    async fn adopt(
        &self,
        subject: Identifier,
        removed: Identifier,
        revoker: Identifier,
        held: Power,
    ) -> Result<Vec<Delegation>, KeylineStorageError<K::Error>> {
        let closure = self
            .keyline()
            .closure(subject)
            .await
            .map_err(KeylineStorageError::new)?
            .value;

        let mut adopted = Vec::new();
        for cert in closure {
            let Certificate::Delegation(signed) = cert else {
                continue;
            };
            let (admitted_issuer, admitted): (Identifier, Delegation) = decode_stored(&signed)?;
            if admitted_issuer != removed
                || admitted.subject != subject
                || admitted.audience == removed
                || admitted.audience == revoker
            {
                continue;
            }
            let live = self
                .keyline()
                .is_live(signed.digest())
                .await
                .map_err(KeylineStorageError::new)?
                .value;
            if !live {
                continue;
            }

            let adoption = Delegation::new(admitted.audience, subject, admitted.power.min(held));
            adopted.push(self.unrevoked(revoker, adoption).await?);
        }
        Ok(adopted)
    }

    /// `d` as `issuer` would sign it, or a re-issue of it that no revocation
    /// names. A delegation
    /// byte-identical to a revoked one would be that same, dead, certificate,
    /// so it is re-issued citing the revocation; if that re-issue was revoked
    /// in turn, it cites that revocation instead, and so on. Each revocation
    /// names one digest, so no two candidates share a first revocation, and
    /// the walk ends.
    async fn unrevoked(
        &self,
        issuer: Identifier,
        mut d: Delegation,
    ) -> Result<Delegation, KeylineStorageError<K::Error>> {
        loop {
            let revocations = self
                .keyline()
                .revocations_of(Digest::of(&issuer, &d.encode()))
                .await
                .map_err(KeylineStorageError::new)?
                .value;
            match revocations.first() {
                Some(revocation) => d = d.reissue(*revocation),
                None => return Ok(d),
            }
        }
    }

    /// Sign a Keyline certificate with the active signer. Inside the crate
    /// only: a certificate reaches the store through [`Keyhive`]'s writes.
    #[cfg(not(any(test, feature = "test_utils")))]
    pub(crate) async fn sign_certificate<V: Signable>(
        &self,
        value: &V,
    ) -> Result<Verified<V>, CertificateError> {
        let signer = { self.active.signer.clone() };
        Ok(Verified::sign::<F, S>(value, &signer).await?)
    }

    /// Sign a Keyline certificate with the active signer; public for tests
    /// that forge certificates.
    #[cfg(any(test, feature = "test_utils"))]
    pub async fn sign_certificate<V: Signable>(
        &self,
        value: &V,
    ) -> Result<Verified<V>, CertificateError> {
        let signer = { self.active.signer.clone() };
        Ok(Verified::sign::<F, S>(value, &signer).await?)
    }

    /// Generate a document: root edges as for a group, and a CGKA group
    /// containing every reader they admit whose prekey operation this replica
    /// has.
    #[instrument(skip_all)]
    pub async fn generate_doc(
        &self,
        coparents: Vec<Identifier>,
        initial_content_heads: NonEmpty<T>,
    ) -> Result<DocumentId, GenerateDocError<K::Error>> {
        let (doc_id, roots) = self.found::<GenerateDocError<K::Error>>(coparents).await?;
        let doc_id = DocumentId(doc_id);
        let mut fresh = Vec::new();
        let mut ops = Vec::new();
        let result = {
            let mut reconciled = self.certificates.reconciled.lock().await;
            self.generate_doc_locked(
                &mut reconciled,
                doc_id,
                &roots,
                initial_content_heads,
                &mut fresh,
                &mut ops,
            )
            .await
        };
        // Listeners run with no lock held, so they may call back in.
        for cert in &fresh {
            self.notify(cert).await;
        }
        for op in &ops {
            self.event_listener.on_cgka_op(op).await;
        }
        result.map(|()| doc_id)
    }

    /// [`Self::generate_doc`] with the insert lock held, so that a concurrent
    /// write either reaches the new document's readers before it is founded or
    /// finds it among the held documents. Appends the root edges it inserts to
    /// `fresh` and the operations it stores to `ops`.
    async fn generate_doc_locked(
        &self,
        reconciled: &mut Option<Version>,
        doc_id: DocumentId,
        roots: &[VerifiedCertificate<ContentHeads<T>>],
        initial_content_heads: NonEmpty<T>,
        fresh: &mut Vec<VerifiedCertificate<ContentHeads<T>>>,
        ops: &mut Vec<Arc<Verified<CgkaOperation>>>,
    ) -> Result<(), GenerateDocError<K::Error>> {
        *fresh = self.insert_fresh(reconciled, roots).await?;

        let doc_kl = Identifier::from(doc_id);
        let (signer, owner, owner_pk) = {
            let active = &self.active;
            let owner_pk = active.pick_prekey(doc_id).await;
            (active.signer.clone(), active.id(), owner_pk)
        };
        let owner_pk = owner_pk.ok_or(GenerateDocError::OwnerHoldsNoPrekeySecret)?;
        let owner_sk = *self
            .active
            .key_pairs
            .lock()
            .await
            .get(&owner_pk)
            .ok_or(GenerateDocError::OwnerHoldsNoPrekeySecret)?;

        // The owner's add has no predecessors, so it cites the whole closure,
        // root edges included, and every later add has it as an ancestor.
        // The founders are the readers included in that set.
        let cited = self.citations_for(doc_kl, &CitationSet::default()).await?;
        let readers: Vec<IndividualId> = self
            .readers_over(&cited.iter().copied().collect(), doc_kl)
            .await?
            .into_iter()
            .map(IndividualId::from)
            .collect();
        if !readers.contains(&owner) {
            return Err(GenerateDocError::OwnerCannotRead);
        }
        let mut founders = Vec::with_capacity(readers.len());
        for reader in readers {
            let (prekey, key_proof) = if reader == owner {
                let key_proof = self
                    .key_proof(owner, &owner_pk)
                    .await
                    .ok_or(GenerateDocError::OwnerPrekeyUnproven)?;
                (owner_pk, key_proof)
            } else {
                let Some(addable) = self.addable_key(reader, doc_id).await else {
                    continue; // no live prekeys to add them with
                };
                addable
            };
            founders.push((reader, prekey, Some(key_proof), BTreeSet::new()));
        }
        // The owner first, so that the CGKA graph's causal root is its creator's.
        founders.sort_by_key(|(id, _, _, _)| (*id != owner, *id));
        let mut founders = NonEmpty::from_vec(founders).ok_or(GenerateDocError::OwnerCannotRead)?;
        founders.head.3 = cited;

        let (doc, made) = {
            let mut csprng = self.csprng.lock().await;
            DocumentState::generate::<F, S, R, K::Error>(
                doc_id,
                founders,
                owner_sk,
                self.implicit_removes_protocol(doc_kl),
                initial_content_heads,
                &signer,
                &mut *csprng,
            )
            .await?
        };
        self.documents
            .lock()
            .await
            .insert(doc_id, Arc::new(Mutex::new(doc)));
        ops.extend(made.into_iter().map(Arc::new));
        Ok(())
    }

    /// Generate a new contact card, rotating a prekey in the process.
    ///
    /// Use [`Keyhive::get_existing_contact_card`] to read a current contact card without
    /// generating one.
    #[instrument(skip_all)]
    pub async fn generate_contact_card(&self) -> Result<ContactCard, SignError> {
        let rot_key_op = self
            .active
            .generate_private_prekey(self.csprng.dupe())
            .await?;

        Ok(ContactCard(KeyOp::Rotate(rot_key_op)))
    }

    #[instrument(skip_all)]
    pub async fn get_existing_contact_card(&self) -> ContactCard {
        self.active.individual().lock().await.contact_card()
    }

    /// Receive `contact_card`, and report who it belongs to.
    #[instrument(skip_all)]
    pub async fn receive_contact_card(
        &self,
        contact_card: &ContactCard,
    ) -> Result<IndividualId, ReceivePrekeyOpError> {
        if let Some(indie) = self.individual_state(contact_card.id()).await {
            indie
                .lock()
                .await
                .receive_prekey_op(contact_card.op().dupe())?;
        } else {
            self.register_individual(IndividualState::from(contact_card))
                .await;
        };

        match contact_card.op() {
            KeyOp::Add(add_op) => {
                self.event_listener
                    .on_prekeys_expanded(add_op.signed())
                    .await;
            }
            KeyOp::Rotate(rot_op) => {
                self.event_listener.on_prekey_rotated(rot_op.signed()).await;
            }
        }

        Ok(contact_card.id())
    }

    #[instrument(skip_all)]
    pub async fn rotate_prekey(
        &self,
        prekey: ShareKey,
    ) -> Result<Verified<RotateKeyOp>, SignError> {
        self.active.rotate_prekey(prekey, self.csprng.dupe()).await
    }

    #[instrument(skip_all)]
    pub async fn expand_prekeys(&self) -> Result<Verified<AddKeyOp>, SignError> {
        self.active.expand_prekeys(self.csprng.dupe()).await
    }

    /// Sign opaque bytes on behalf of an application, under [`Kind::BYTES`].
    ///
    /// [`Kind::BYTES`]: keyhive_crypto::signable::Kind::BYTES
    #[instrument(skip_all)]
    pub async fn sign_bytes(&self, bytes: Vec<u8>) -> Result<Verified<Bytes>, SignError> {
        Verified::sign::<F, S>(&Bytes::from(bytes), &self.active.signer).await
    }

    /// Sign a CGKA operation as this identity, whatever it says, in wire
    /// form: for tests that forge or replay operations. Beekem signs the
    /// operations this replica issues itself.
    #[cfg(any(test, feature = "test_utils"))]
    #[instrument(skip_all)]
    pub async fn sign_cgka_op(
        &self,
        op: CgkaOperation,
    ) -> Result<verified::Signed<CgkaOperation>, SignError> {
        let signer = self.active.signer.clone();
        let verified = Verified::sign::<F, _>(&op, &signer).await?;
        Ok(verified.signed().as_ref().clone())
    }

    #[instrument(skip_all)]
    /// Add an individual to the table. `false`, and nothing changes, if it is
    /// already there.
    pub async fn register_individual(&self, individual: IndividualState) -> bool {
        match self.individuals.lock().await.entry(individual.id()) {
            Entry::Occupied(_) => false,
            Entry::Vacant(entry) => {
                entry.insert(Arc::new(Mutex::new(individual)));
                true
            }
        }
    }

    /// Delegate `to_add` `can` access to `resource`.
    ///
    /// Returns an error if we have never heard of `to_add` or `resource`.
    pub async fn add_member(
        &self,
        to_add: impl Into<Identifier>,
        resource: impl Into<MemberedId>,
        can: Power,
    ) -> Result<AddMemberUpdate, AddMemberError<K::Error>> {
        let resource = resource.into();

        let to_add = to_add.into();
        if !self.is_known(to_add).await? {
            return Err(NotFound::new(to_add).into());
        }
        self.ensure_known::<AddMemberError<K::Error>>(resource)
            .await?;

        let issuer = Identifier::from(self.id());
        let subject = Identifier::from(resource);
        let held = self
            .keyline()
            .effective_power(subject, issuer)
            .await
            .map_err(KeylineStorageError::new)?
            .value
            .ok_or(AddMemberError::NoAuthority)?;
        if can > held {
            return Err(AddMemberError::Escalation { wanted: can, held });
        }

        let certificate = Delegation::new(to_add, subject, can);
        let certificate = self.unrevoked(issuer, certificate).await?;
        let delegation = Arc::new(self.sign_certificate(&certificate).await?);

        let cgka_ops = self
            .insert_and_reconcile::<AddMemberError<K::Error>>(&[VerifiedCertificate::Delegation(
                delegation.dupe(),
            )])
            .await?;

        Ok(AddMemberUpdate {
            delegation,
            cgka_ops,
        })
    }

    /// Revoke `to_revoke`'s membership in `resource`.
    ///
    /// With `retain_all_other_members`, the members `to_revoke` had admitted keep their
    /// access, because their delegations are re-issued under the revoker.
    ///
    /// Each revocation records the content heads of every held document `resource` is
    /// or stands over, as last set with [`Self::set_content_heads`], so the content layer
    /// can tell what `to_revoke` wrote after it.
    ///
    /// Errors if this instance has never received `resource`.
    #[allow(clippy::type_complexity)]
    #[instrument(skip_all)]
    pub async fn revoke_member(
        &self,
        to_revoke: impl Into<Identifier>,
        retain_all_other_members: bool,
        resource: impl Into<MemberedId>,
    ) -> Result<RevokeMemberUpdate<T>, RevokeMemberError<K::Error>> {
        let to_revoke = to_revoke.into();
        let resource = resource.into();
        self.ensure_known::<RevokeMemberError<K::Error>>(resource)
            .await?;
        let issuer = Identifier::from(self.id());
        let subject = Identifier::from(resource);
        let audience = to_revoke;

        // An Admin's revocation reaches every route through the resource; a
        // lesser member's, only the delegations it issued itself.
        let held = self
            .keyline()
            .effective_power(subject, issuer)
            .await
            .map_err(KeylineStorageError::new)?
            .value
            .ok_or(RevokeMemberError::NoAuthority)?;
        // Every Keyline delegation from the resource to the member, live or
        // not, so that a later re-grant of a dead one stays dead.
        let delegations = self
            .keyline()
            .delegations_to(subject, audience)
            .await
            .map_err(KeylineStorageError::new)?
            .value;
        let revocable: Vec<_> = delegations
            .iter()
            .filter(|(_, (d_issuer, _))| held == Power::Admin || *d_issuer == issuer)
            .map(|(digest, _)| *digest)
            .collect();
        if delegations.is_empty() {
            return Err(RevokeMemberError::NotADirectMember(to_revoke));
        }
        if revocable.is_empty() {
            return Err(RevokeMemberError::NoAuthority);
        }

        // Adoption, read before the revocations make it unreadable.
        let adopted = if retain_all_other_members {
            self.adopt(subject, audience, issuer, held).await?
        } else {
            Vec::new()
        };

        let retain = self.content_watermark(subject).await?;
        let mut revocations = Vec::with_capacity(revocable.len());
        for digest in revocable {
            let revocation: Revocation<ContentHeads<T>> =
                Revocation::new(digest).retaining(retain.clone());
            revocations.push(Arc::new(self.sign_certificate(&revocation).await?));
        }
        let mut redelegations = Vec::with_capacity(adopted.len());
        for adoption in &adopted {
            redelegations.push(Arc::new(self.sign_certificate(adoption).await?));
        }

        // One batch, so no query sees the members cut off before adoption.
        let batch: Vec<VerifiedCertificate<ContentHeads<T>>> = revocations
            .iter()
            .map(|r| VerifiedCertificate::Revocation(r.dupe()))
            .chain(
                redelegations
                    .iter()
                    .map(|d| VerifiedCertificate::Delegation(d.dupe())),
            )
            .collect();
        let cgka_ops = self
            .insert_and_reconcile::<RevokeMemberError<K::Error>>(&batch)
            .await?;

        Ok(RevokeMemberUpdate {
            revocations,
            redelegations,
            cgka_ops,
        })
    }

    /// Whether this replica knows `id`: an individual, a document, or a Keyline
    /// subject (a group).
    async fn is_known(&self, id: Identifier) -> Result<bool, KeylineStorageError<K::Error>> {
        if self.has_individual(IndividualId(id)).await || self.has_document(DocumentId(id)).await {
            return Ok(true);
        }
        Ok(self
            .keyline()
            .subjects()
            .await
            .map_err(KeylineStorageError::new)?
            .value
            .contains(&id))
    }

    /// Returns `NotFound` error if this replica does not know `resource`.
    async fn ensure_known<E: From<NotFound> + From<KeylineStorageError<K::Error>>>(
        &self,
        resource: MemberedId,
    ) -> Result<(), E> {
        if !self.is_known(resource.into()).await? {
            return Err(NotFound::new(resource).into());
        }
        Ok(())
    }

    /// Record `heads` as `doc`'s current content heads: the watermark this
    /// replica's revocations record for the document. Keyhive does not follow
    /// content itself, so the application sets the heads it has seen. An empty
    /// set means none are known, and revocations leave the document out.
    ///
    /// Errors if this replica has not joined `doc`'s CGKA group: it is not a
    /// member, or its invitation has not merged yet.
    pub async fn set_content_heads<I: IntoIterator<Item = T>>(
        &self,
        doc: DocumentId,
        heads: I,
    ) -> Result<(), NotFound> {
        let state = self.document_by_id(doc).await?;
        state.lock().await.content_heads = heads.into_iter().collect();
        Ok(())
    }

    /// Encrypt `content` into `doc` after `pred_refs`, with the key this document has for
    /// each, from content it has written or read. A reader who opens the result can then
    /// open each predecessor and traverse back from there with
    /// [`Keyhive::try_causal_decrypt_content`] or [`Keyhive::try_causal_decrypt_from_keys`].
    /// If a content ref appears more than once in `pred_refs`, it is one predecessor.
    ///
    /// Fails with [`EncryptContentError::NoKeyForPredecessor`] if this document has no key
    /// for one of `pred_refs`, because this `Keyhive` has not written that content or read
    /// it.
    #[instrument(skip_all)]
    pub async fn try_encrypt_content(
        &self,
        doc: DocumentId,
        content_ref: &T,
        pred_refs: &[T],
        content: &[u8],
    ) -> Result<EncryptedContentWithUpdate<T>, EncryptContentError<T>> {
        Ok(self
            .try_encrypt_content_keyed(doc, content_ref, pred_refs, content)
            .await?
            .0)
    }

    /// [`Keyhive::try_encrypt_content`], also returning the application secret the content
    /// was encrypted under.
    #[instrument(skip_all)]
    pub async fn try_encrypt_content_keyed(
        &self,
        doc: DocumentId,
        content_ref: &T,
        pred_refs: &[T],
        content: &[u8],
    ) -> Result<(EncryptedContentWithUpdate<T>, SymmetricKey), EncryptContentError<T>> {
        let writing = self.prepare_to_write(doc).await?;
        let encrypted = async {
            let handle = self.document_by_id(doc).await?;
            let signer = { self.active.signer.clone() };
            let mut locked_csprng = self.csprng.lock().await;
            let mut locked = handle.lock().await;
            self.settle_for_write(doc, &mut locked).await?;
            let ancestors = locked
                .predecessor_keys(pred_refs)
                .map_err(EncryptContentError::NoKeyForPredecessor)?;
            locked
                .try_encrypt_content_keyed(
                    content_ref,
                    content,
                    &ancestors,
                    &signer,
                    &mut *locked_csprng,
                )
                .await
                .map_err(EncryptContentError::from)
        }
        .await;
        self.finish_write(writing).await;
        let (encrypted_content, application_secret_key, rotation) = encrypted?;
        let update_op = self.record_rotation(rotation).await;
        Ok((
            EncryptedContentWithUpdate {
                encrypted_content,
                update_op,
            },
            application_secret_key,
        ))
    }

    /// Keep what a write's rotation produced: its new key among the secrets this
    /// identity's other instances can import. Its update is already in the CGKA
    /// graph.
    /// Returns the update, for the caller to send.
    async fn record_rotation(
        &self,
        rotation: Option<(Verified<CgkaOperation>, LeafKeyPair)>,
    ) -> Option<Verified<CgkaOperation>> {
        let (op, (pk, sk)) = rotation?;
        self.active.insert_rotated_secret(pk, sk).await;
        self.record_cgka_ops([Arc::new(op.clone())]).await;
        Some(op)
    }

    /// The members of `doc`'s CGKA group. Returns `None` if this replica holds
    /// its CGKA graph unjoined, or if Keyline cannot answer a membership
    /// question a replay of its CGKA graph requires.
    ///
    /// Returns an error if `doc` is not known.
    #[cfg(any(test, feature = "test_utils"))]
    pub async fn cgka_members_for(
        &self,
        doc: DocumentId,
    ) -> Result<Option<BTreeSet<IndividualId>>, NotFound> {
        let Some(state) = self.member_document(doc).await? else {
            return Ok(None);
        };
        Ok(self.cgka_group_members(doc.into(), &state).await.ok())
    }

    /// The hash of `doc`'s current PCS key. Returns `None` if it has no key to hash.
    pub async fn try_pcs_key_hash(&self, doc: DocumentId) -> Option<Digest<PcsKey>> {
        let handle = self.document_state(doc).await?;
        let hash = handle.lock().await.cgka_mut().try_pcs_key_hash().ok();
        hash
    }

    /// Try causal decrypt from more than one entrypoint at once.
    ///
    /// [`Keyhive::try_causal_decrypt_content`] takes a single entrypoint.
    /// Remembers the key of each block read, as
    /// [`Keyhive::try_causal_decrypt_from_keys`] does.
    #[cfg(any(test, feature = "test_utils"))]
    pub async fn try_causal_decrypt_from(
        &self,
        doc: DocumentId,
        entrypoints: &[(Arc<EncryptedContent<P, T>>, SymmetricKey)],
    ) -> Result<CausalDecryptionState<T, P>, CausalDecryptionError<F, T, P, C>>
    where
        P: Clone + Encode + Decode,
    {
        let mut to_walk = entrypoints.to_vec();
        let traversed = CiphertextStoreExt::<F, T, P>::try_causal_decrypt(
            &self.ciphertext_store,
            doc.into(),
            &mut to_walk,
        )
        .await;
        if let Some(state) = self.document_state(doc).await {
            state.lock().await.remember_traversed_keys(&traversed);
        }
        traversed
    }

    /// Traverse back over `store` from `start`, each entry a block's content ref
    /// and the key that opens it, as
    /// [`CiphertextStoreExt::try_causal_decrypt_from_keys`] does. If this replica
    /// is a member of `doc`, it remembers the key of each block read so a later
    /// write can refer to that block as a predecessor.
    pub async fn try_causal_decrypt_from_keys<G, Store, Q>(
        &self,
        doc: DocumentId,
        start: &[(T, SymmetricKey)],
        store: &Store,
    ) -> Result<CausalDecryptionState<T, Q>, CausalDecryptionError<G, T, Q, Store>>
    where
        G: FutureForm,
        Store: CiphertextStore<G, T, Q> + CiphertextStoreExt<G, T, Q>,
        Q: Clone + Encode + Decode,
    {
        let traversed = store.try_causal_decrypt_from_keys(doc.into(), start).await;
        if let Some(state) = self.document_state(doc).await {
            state.lock().await.remember_traversed_keys(&traversed);
        }
        traversed
    }

    /// Decrypt `encrypted` out of `doc`.
    pub async fn try_decrypt_content(
        &self,
        doc: DocumentId,
        encrypted: &EncryptedContent<P, T>,
    ) -> Result<Envelope<T, Vec<u8>>, DecryptError> {
        Ok(self.try_decrypt_content_keyed(doc, encrypted).await?.0)
    }

    /// Whether decryption succeeds.
    ///
    /// `Ok(false)` means this instance holds no key for the content, or holds one that does
    /// not authenticate it. Not knowing about `doc` at all is an error.
    #[cfg(any(test, feature = "test_utils"))]
    pub async fn can_decrypt_content(
        &self,
        doc: DocumentId,
        encrypted: &EncryptedContent<P, T>,
    ) -> Result<bool, DecryptError> {
        match self.try_decrypt_content(doc, encrypted).await {
            Ok(_) => Ok(true),
            Err(
                DecryptError::KeyNotFound
                | DecryptError::SivMismatch
                | DecryptError::DecryptionFailed(_),
            ) => Ok(false),
            Err(other) => Err(other),
        }
    }

    /// [`Keyhive::try_decrypt_content`], also returning the application secret that was
    /// used.
    pub async fn try_decrypt_content_keyed(
        &self,
        doc: DocumentId,
        encrypted: &EncryptedContent<P, T>,
    ) -> Result<(Envelope<T, Vec<u8>>, SymmetricKey), DecryptError> {
        let Some(state) = self.member_document(doc).await? else {
            return Err(DecryptError::KeyNotFound); // invited, no keys yet
        };
        let mut locked = state.lock().await;
        let key = self.decryption_key(doc, &mut locked, encrypted).await?;
        Ok((locked.try_decrypt_content_with(encrypted, key)?, key))
    }

    /// The key for `encrypted` in `doc`'s CGKA, fetching any membership answer
    /// needed to replay its CGKA graph up to an earlier update. The CGKA
    /// records the root secret it derives.
    async fn decryption_key<Q>(
        &self,
        doc: DocumentId,
        state: &mut DocumentState<T>,
        encrypted: &EncryptedContent<Q, T>,
    ) -> Result<SymmetricKey, DecryptError> {
        self.require_keyline_answers(doc.into(), state.cgka_mut(), |cgka| {
            cgka.decryption_key_for(encrypted)
        })
        .await
        .map_err(|e| DecryptError::KeylineStorage(e.to_string()))?
        .map_err(|_| DecryptError::KeyNotFound)
    }

    /// Walk back from `encrypted` through the ancestors it lists. Remembers the key of
    /// each block read so a later write can list it as a predecessor.
    pub async fn try_causal_decrypt_content(
        &self,
        doc: DocumentId,
        encrypted: &EncryptedContent<P, T>,
    ) -> Result<CausalDecryptionState<T, P>, CausalDecryptError<F, T, P, C>>
    where
        P: Encode + Clone,
    {
        let Some(state) = self.member_document(doc).await? else {
            // Invited, no keys yet.
            return Err(DocCausalDecryptionError::from(DecryptError::KeyNotFound).into());
        };
        let out = {
            let mut locked = state.lock().await;
            // The traversal derives the entrypoint's key itself. Deriving it here
            // first fetches any required membership answer and records it.
            if let Err(e @ DecryptError::KeylineStorage(_)) =
                self.decryption_key(doc, &mut locked, encrypted).await
            {
                return Err(DocCausalDecryptionError::from(e).into());
            }
            locked
                .try_causal_decrypt_content(encrypted, self.ciphertext_store.clone())
                .await
        };
        Ok(out?)
    }

    /// Rotate this identity's key in `doc`'s CGKA group, after first issuing
    /// the CGKA operations this replica's certificates imply for the document.
    #[instrument(skip_all)]
    pub async fn force_pcs_update(
        &self,
        doc: DocumentId,
    ) -> Result<(Verified<CgkaOperation>, LeafKeyPair), EncryptError> {
        let mut writing = self.prepare_to_write(doc).await?;
        let rotated = self.rotate_own_key(doc).await;
        if let Ok((op, _)) = &rotated {
            writing.fresh.push(Arc::new(op.clone()));
        }
        self.finish_write(writing).await;
        rotated
    }

    /// Rotate this identity's key in `doc`'s CGKA group and keep the new
    /// secret. The caller tells the listener about the update.
    async fn rotate_own_key(
        &self,
        doc: DocumentId,
    ) -> Result<(Verified<CgkaOperation>, LeafKeyPair), EncryptError> {
        let handle = self.document_by_id(doc).await?;
        let signer = { self.active.signer.clone() };
        let (op, new_key_pair) = {
            let mut locked_csprng = self.csprng.lock().await;
            let mut locked = handle.lock().await;
            self.settle_for_write(doc, &mut locked).await?;
            locked.pcs_update(&signer, &mut *locked_csprng).await?
        };
        let (pk, sk) = new_key_pair;
        self.active.insert_rotated_secret(pk, sk).await;
        Ok((op, new_key_pair))
    }

    /// Every document the active individual reaches and at what access level.
    #[instrument(skip_all)]
    pub async fn reachable_docs(
        &self,
    ) -> Result<BTreeMap<DocumentId, Power>, KeylineStorageError<K::Error>> {
        Ok(self
            .reachable_doc_handles()
            .await?
            .into_iter()
            .map(|(doc_id, (_, can))| (doc_id, can))
            .collect())
    }

    /// Like [`Keyhive::reachable_docs`] but returning each document's handle instead
    /// of id.
    #[allow(clippy::type_complexity)]
    #[instrument(skip_all)]
    pub async fn reachable_doc_handles(
        &self,
    ) -> Result<BTreeMap<DocumentId, (Document<Self>, Power)>, KeylineStorageError<K::Error>> {
        let id = { self.active.id().into() };
        Ok(self
            .standing_of(id)
            .await?
            .into_iter()
            .filter_map(|(id, can)| match id {
                MemberedId::DocumentId(doc_id) => {
                    Some((doc_id, (Document::new(self.clone(), doc_id), can)))
                }
                MemberedId::GroupId(_) => None,
            })
            .collect())
    }

    /// The documents `who` reaches and at what access level.
    ///
    /// Empty for a principal we have not heard of.
    #[instrument(skip_all)]
    pub async fn docs_reachable_by_agent(
        &self,
        who: impl Into<Identifier>,
    ) -> Result<BTreeMap<DocumentId, Power>, KeylineStorageError<K::Error>> {
        Ok(self
            .standing_of(who.into())
            .await?
            .into_iter()
            .filter_map(|(id, can)| match id {
                MemberedId::DocumentId(doc_id) => Some((doc_id, can)),
                MemberedId::GroupId(_) => None,
            })
            .collect())
    }

    /// The groups and documents `who` reaches and at what access level.
    ///
    /// Empty for a principal we have not heard of.
    #[instrument(skip_all)]
    pub async fn membered_reachable_by_agent(
        &self,
        who: impl Into<Identifier>,
    ) -> Result<BTreeMap<MemberedId, Power>, KeylineStorageError<K::Error>> {
        self.standing_of(who.into()).await
    }

    /// Everyone who reaches `membered`, including through nested groups.
    ///
    /// Empty for a `membered` we have not heard of.
    #[instrument(skip_all)]
    pub async fn reachable_members(
        &self,
        membered: impl Into<MemberedId>,
    ) -> Result<BTreeMap<Identifier, Power>, KeylineStorageError<K::Error>> {
        self.members_of(Identifier::from(membered.into())).await
    }

    /// The live delegations whose subject is `subject`: its direct members,
    /// each with the certificate that admits it. Empty for a subject we have
    /// not heard of.
    #[instrument(skip_all)]
    pub async fn delegations_about(
        &self,
        subject: impl Into<Identifier>,
    ) -> Result<Vec<Arc<verified::Signed<Delegation>>>, KeylineStorageError<K::Error>> {
        let subject = subject.into();
        let mut live = Vec::new();
        for cert in self.closure(subject).await? {
            let Certificate::Delegation(signed) = cert else {
                continue;
            };
            let (_, d): (Identifier, Delegation) = decode_stored(&signed)?;
            if d.subject != subject {
                continue;
            }
            if self
                .keyline()
                .is_live(signed.digest())
                .await
                .map_err(KeylineStorageError::new)?
                .value
            {
                live.push(signed);
            }
        }
        Ok(live)
    }

    /// Everyone a delegation about `membered` once admitted, whose delegation
    /// was revoked, and who is no longer a member by any route; each at the
    /// best power a revoked delegation had named.
    ///
    /// Empty for a `membered` we have not heard of.
    #[instrument(skip_all)]
    pub async fn revoked_members(
        &self,
        membered: impl Into<MemberedId>,
    ) -> Result<BTreeMap<Identifier, Power>, KeylineStorageError<K::Error>> {
        let subject = Identifier::from(membered.into());
        let members = self
            .keyline()
            .members(subject)
            .await
            .map_err(KeylineStorageError::new)?
            .value;
        let mut revoked: BTreeMap<Identifier, Power> = BTreeMap::new();
        for cert in self.closure(subject).await? {
            let Certificate::Delegation(signed) = cert else {
                continue;
            };
            let (_, d): (Identifier, Delegation) = decode_stored(&signed)?;
            if d.subject != subject || members.contains_key(&d.audience) {
                continue;
            }
            let revocations = self
                .keyline()
                .revocations_of(signed.digest())
                .await
                .map_err(KeylineStorageError::new)?
                .value;
            if !revocations.is_empty() {
                let best = revoked.entry(d.audience).or_insert(d.power);
                *best = (*best).max(d.power);
            }
        }
        Ok(revoked)
    }

    /// Keyline's members of `subject`, by identifier.
    pub(crate) async fn members_of(
        &self,
        subject: Identifier,
    ) -> Result<BTreeMap<Identifier, Power>, KeylineStorageError<K::Error>> {
        Ok(self
            .keyline()
            .members(subject)
            .await
            .map_err(KeylineStorageError::new)?
            .value
            .into_iter()
            .collect())
    }

    /// `who`'s power over every subject in Keyline other than itself. A
    /// subject is a document when this replica holds its CGKA graph, joined
    /// or not (as a relay does), and a group otherwise.
    async fn standing_of(
        &self,
        who: Identifier,
    ) -> Result<BTreeMap<MemberedId, Power>, KeylineStorageError<K::Error>> {
        let audience = who;
        let subjects = self
            .keyline()
            .subjects()
            .await
            .map_err(KeylineStorageError::new)?
            .value;
        let mut standing = BTreeMap::new();
        for subject in subjects.into_iter().filter(|s| *s != audience) {
            let Some(can) = self
                .keyline()
                .effective_power(subject, audience)
                .await
                .map_err(KeylineStorageError::new)?
                .value
            else {
                continue;
            };
            let id = subject;
            let kind = if self.contains_cgka_graph(DocumentId(id)).await {
                MemberedId::DocumentId(DocumentId(id))
            } else {
                MemberedId::GroupId(GroupId(id))
            };
            standing.insert(kind, can);
        }
        Ok(standing)
    }

    #[instrument(skip_all)]
    pub async fn pending_event_hashes(&self) -> HashSet<Digest<StaticEvent<T>>> {
        self.pending_events
            .lock()
            .await
            .iter()
            .map(|event| event.digest())
            .collect()
    }

    #[allow(clippy::type_complexity)]
    #[instrument(skip_all)]
    pub async fn events_for_agent(
        &self,
        who: impl Into<Identifier>,
    ) -> Result<HashMap<Digest<Event<T>>, Event<T>>, KeylineStorageError<K::Error>> {
        let (certs, cgka_ops, prekeys) = self.ops_for_agent(who.into()).await?;
        let mut ops = HashMap::new();

        for key_op in prekeys.values().flatten() {
            let op = Event::<T>::from(key_op.as_ref().dupe());
            ops.insert(op.digest(), op);
        }

        for cgka_op in cgka_ops {
            let op = Event::<T>::from(cgka_op);
            ops.insert(op.digest(), op);
        }

        for cert in certs {
            let op = Event::from(cert);
            ops.insert(op.digest(), op);
        }

        Ok(ops)
    }

    /// The certificates, CGKA operations and prekey operations `who` is sent,
    /// each computed once.
    #[allow(clippy::type_complexity)]
    async fn ops_for_agent(
        &self,
        who: Identifier,
    ) -> Result<
        (
            Vec<Certificate<ContentHeads<T>>>,
            Vec<Arc<Verified<CgkaOperation>>>,
            KeyOps,
        ),
        KeylineStorageError<K::Error>,
    > {
        let certs = self.certificates_for_agent(who).await?;
        let cgka_ops = self.cgka_ops_reachable_by_agent(who).await?;
        let prekeys = self
            .prekey_ops_referenced_by(who, &certs, &cgka_ops)
            .await?;
        Ok((certs, cgka_ops, prekeys))
    }

    /// The prekey operations of `who` and of every agent `certs` or `cgka_ops`
    /// reference: what a recipient of those needs to check each CGKA add's key
    /// against the added member's published prekeys.
    async fn prekey_ops_referenced_by(
        &self,
        who: Identifier,
        certs: &[Certificate<ContentHeads<T>>],
        cgka_ops: &[Arc<Verified<CgkaOperation>>],
    ) -> Result<KeyOps, KeylineStorageError<K::Error>> {
        let mut referenced = BTreeSet::from([who]);
        for cert in certs {
            referenced.extend(referenced_by(cert)?);
        }
        for op in cgka_ops {
            referenced.extend(referenced_by_cgka_op(op));
        }

        let mut map: HashMap<Identifier, CaMap<KeyOp>> = HashMap::new();
        for id in referenced {
            if let Some(state) = self.individual_state(IndividualId(id)).await {
                map.insert(id, state.lock().await.prekey_ops().clone());
            }
        }
        Ok(map.into())
    }

    /// The subjects in Keyline `who` stands over, split by whether it still
    /// does: those it has effective standing over (itself included), and
    /// those it has only positive standing over, having been cut off.
    async fn standing_over(
        &self,
        who: Identifier,
    ) -> Result<(Vec<Identifier>, Vec<Identifier>), KeylineStorageError<K::Error>> {
        let audience = who;
        let (mut live, mut cut) = (Vec::new(), Vec::new());
        for subject in self.subjects().await? {
            let effective = self
                .keyline()
                .effective_power(subject, audience)
                .await
                .map_err(KeylineStorageError::new)?
                .value;
            if subject == audience || effective.is_some() {
                live.push(subject);
            } else if self.positive_power(subject, audience).await?.is_some() {
                cut.push(subject);
            }
        }
        Ok((live, cut))
    }

    /// Every subject in Keyline.
    async fn subjects(&self) -> Result<BTreeSet<Identifier>, KeylineStorageError<K::Error>> {
        Ok(self
            .keyline()
            .subjects()
            .await
            .map_err(KeylineStorageError::new)?
            .value)
    }

    /// For each subject in Keyline: its closure, its live members, and for
    /// each principal cut off from it, the certificates that explain that.
    /// What selection for every principal is computed from, once per subject.
    async fn subject_views(&self) -> Result<Vec<SubjectView<T>>, KeylineStorageError<K::Error>> {
        let mut views = Vec::new();
        for subject in self.subjects().await? {
            let closure = self.closure(subject).await?;
            let live: BTreeSet<Identifier> = self.members_of(subject).await?.into_keys().collect();
            let mut referenced: BTreeSet<Identifier> = BTreeSet::new();
            for cert in &closure {
                referenced.extend(referenced_by(cert)?);
            }
            let mut cut = Vec::new();
            for audience in referenced {
                let id = audience;
                if audience == subject
                    || live.contains(&id)
                    || self.positive_power(subject, audience).await?.is_none()
                {
                    continue;
                }
                let explained = explanation(self.keyline(), subject, audience).await?;
                cut.push((id, explained));
            }
            views.push(SubjectView {
                subject,
                closure,
                live,
                cut,
            });
        }
        Ok(views)
    }

    /// The closure of a subject: every certificate that can affect an answer
    /// about it.
    async fn closure(
        &self,
        subject: Identifier,
    ) -> Result<Vec<Certificate<ContentHeads<T>>>, KeylineStorageError<K::Error>> {
        Ok(self
            .keyline()
            .closure(subject)
            .await
            .map_err(KeylineStorageError::new)?
            .value)
    }

    /// The certificates `who` should hold: the closure of every subject it
    /// stands over, and for each subject it was cut off from, only the
    /// certificates that explain that, so it learns of its removal and of
    /// nothing that happens after.
    pub async fn certificates_for_agent(
        &self,
        who: Identifier,
    ) -> Result<Vec<Certificate<ContentHeads<T>>>, KeylineStorageError<K::Error>> {
        let mut certs = BTreeMap::new();
        let (live, cut) = self.standing_over(who).await?;
        for subject in live {
            for cert in self.closure(subject).await? {
                certs.insert(cert.id(), cert);
            }
        }
        let audience = who;
        for subject in cut {
            for cert in explanation(self.keyline(), subject, audience).await? {
                certs.insert(cert.id(), cert);
            }
        }

        Ok(certs.into_values().collect())
    }

    #[instrument(skip_all)]
    pub async fn static_events_for_agent(
        &self,
        who: impl Into<Identifier>,
    ) -> Result<HashMap<Digest<StaticEvent<T>>, StaticEvent<T>>, KeylineStorageError<K::Error>>
    {
        Ok(self
            .events_for_agent(who.into())
            .await?
            .into_iter()
            .map(|(k, v)| (k.coerce(), v.into()))
            .collect())
    }

    /// The CGKA operations of every document whose CGKA graph this replica
    /// holds and that `who` stands over, relays included: the operations are
    /// signed, and their secrets are encrypted to the CGKA group's members,
    /// which a relay never becomes.
    #[instrument(skip_all)]
    pub async fn cgka_ops_reachable_by_agent(
        &self,
        who: impl Into<Identifier>,
    ) -> Result<Vec<Arc<Verified<CgkaOperation>>>, KeylineStorageError<K::Error>> {
        let standing = self.standing_of(who.into()).await?;
        let mut ops = Vec::new();
        for id in standing.into_keys() {
            let MemberedId::DocumentId(doc_id) = id else {
                continue;
            };
            ops.extend(self.cgka_ops_for_doc(&doc_id).await.into_iter().flatten());
        }
        Ok(ops)
    }

    /// Every CGKA operation in this replica's CGKA graph for `doc`, joined or
    /// not. Returns `None` if it holds none.
    #[instrument(skip_all)]
    pub async fn cgka_ops_for_doc(
        &self,
        doc: &DocumentId,
    ) -> Option<Vec<Arc<Verified<CgkaOperation>>>> {
        if let Some(state) = self.document_state(*doc).await {
            let ops = cgka_ops_for(state.lock().await.cgka());
            return Some(ops);
        }
        self.unjoined.lock().await.get(doc).map(cgka_ops_for)
    }

    /// Every prekey op `who` is sent, grouped by the identifier they belong
    /// to: its own, and those of every agent referenced by the certificates and
    /// CGKA operations it is sent.
    #[instrument(skip_all)]
    pub async fn reachable_prekey_ops_for_agent(
        &self,
        who: impl Into<Identifier>,
    ) -> Result<KeyOps, KeylineStorageError<K::Error>> {
        Ok(self.ops_for_agent(who.into()).await?.2)
    }

    /// [`Self::reachable_prekey_ops_for_agent`] for every principal, in one pass.
    ///
    /// Returns an [`AllReachablePrekeyOps`] containing:
    /// - `ops`: key ops per identifier, computed once and shared
    /// - `index`: for each principal, the identifiers in `ops` whose prekey ops
    ///   it is sent
    #[instrument(skip_all)]
    pub async fn reachable_prekey_ops_for_all_agents(
        &self,
    ) -> Result<AllReachablePrekeyOps, KeylineStorageError<K::Error>> {
        let views = self.subject_views().await?;
        let all_cgka = self.cgka_ops_for_all_agents().await?;
        self.prekey_ops_for_views(&views, &all_cgka).await
    }

    /// The bulk form of [`Self::prekey_ops_referenced_by`]: each principal is sent
    /// its own prekey ops and those of every agent referenced by what it is sent,
    /// the closures of the subjects it stands over, its explanations, and the
    /// CGKA operations of the documents it reads.
    async fn prekey_ops_for_views(
        &self,
        views: &[SubjectView<T>],
        all_cgka: &AllCgkaOps,
    ) -> Result<AllReachablePrekeyOps, KeylineStorageError<K::Error>> {
        let active_id: Identifier = { self.active.id().into() };

        // What each source references.
        let mut referenced_by_closure: HashMap<Identifier, BTreeSet<Identifier>> = HashMap::new();
        let mut referenced_by_explanation: HashMap<Identifier, BTreeSet<Identifier>> =
            HashMap::new();
        let mut sources: HashMap<Identifier, BTreeSet<Identifier>> = HashMap::new();
        for view in views {
            let referenced = referenced_by_closure.entry(view.subject).or_default();
            for cert in &view.closure {
                referenced.extend(referenced_by(cert)?);
            }
            for member in view.live.iter().chain([&view.subject]) {
                sources.entry(*member).or_default().insert(view.subject);
            }
            for (who, certs) in &view.cut {
                let referenced = referenced_by_explanation.entry(*who).or_default();
                for cert in certs {
                    referenced.extend(referenced_by(cert)?);
                }
            }
        }
        let referenced_by_cgka: HashMap<Identifier, BTreeSet<Identifier>> = all_cgka
            .ops
            .iter()
            .map(|(doc, ops)| {
                (
                    *doc,
                    ops.iter()
                        .flat_map(|op| referenced_by_cgka_op(op))
                        .collect(),
                )
            })
            .collect();

        // Every principal that is sent anything, and everyone this replica knows.
        let mut agents: BTreeSet<Identifier> = self
            .individuals
            .lock()
            .await
            .keys()
            .map(|id| (*id).into())
            .collect();
        agents.insert(active_id);
        agents.extend(sources.keys().copied());
        agents.extend(referenced_by_explanation.keys().copied());
        agents.extend(all_cgka.index.keys().copied());

        let mut index: HashMap<Identifier, HashSet<Identifier>> = HashMap::new();
        for agent in &agents {
            let needs = index.entry(*agent).or_default();
            needs.insert(*agent);
            for subject in sources.get(agent).into_iter().flatten() {
                needs.extend(referenced_by_closure.get(subject).into_iter().flatten());
            }
            needs.extend(referenced_by_explanation.get(agent).into_iter().flatten());
            for doc in all_cgka.index.get(agent).into_iter().flatten() {
                needs.extend(referenced_by_cgka.get(doc).into_iter().flatten());
            }
        }

        let mut key_ops_cache: HashMap<Identifier, CaMap<KeyOp>> = HashMap::new();
        let candidates: BTreeSet<Identifier> = index.values().flatten().copied().collect();
        for id in candidates {
            if let Some(state) = self.individual_state(IndividualId(id)).await {
                key_ops_cache.insert(id, state.lock().await.prekey_ops().clone());
            }
        }
        for needs in index.values_mut() {
            needs.retain(|id| key_ops_cache.contains_key(id));
        }

        Ok(AllReachablePrekeyOps {
            ops: KeyOps::from(key_ops_cache),
            index,
        })
    }

    /// Compute CGKA ops for all principals in a single pass: the operations of
    /// each CGKA graph this replica holds, joined or not, sent to every member
    /// of the document, relays included.
    #[instrument(skip_all)]
    pub async fn cgka_ops_for_all_agents(
        &self,
    ) -> Result<AllCgkaOps, KeylineStorageError<K::Error>> {
        let mut ops: HashMap<Identifier, Vec<Arc<Verified<CgkaOperation>>>> = HashMap::new();
        let mut index: HashMap<Identifier, HashSet<Identifier>> = HashMap::new();

        let docs: Vec<(DocumentId, Arc<Mutex<DocumentState<T>>>)> = {
            let documents = self.documents.lock().await;
            documents
                .iter()
                .map(|(id, doc)| (*id, doc.dupe()))
                .collect()
        };
        let mut held = Vec::with_capacity(docs.len());
        for (doc_id, doc) in docs {
            held.push((doc_id, cgka_ops_for(doc.lock().await.cgka())));
        }
        held.extend(
            self.unjoined
                .lock()
                .await
                .iter()
                .map(|(doc_id, cgka)| (*doc_id, cgka_ops_for(cgka))),
        );

        for (doc_id, doc_ops) in held {
            if doc_ops.is_empty() {
                continue;
            }
            let source_id: Identifier = doc_id.into();
            for agent_id in self.members_of(source_id).await?.into_keys() {
                index.entry(agent_id).or_default().insert(source_id);
            }
            ops.insert(source_id, doc_ops);
        }

        Ok(AllCgkaOps { ops, index })
    }

    /// Every event `agent` is sent, under the digests they are sent by.
    pub async fn event_digests_for_agent(
        &self,
        agent: impl Into<Identifier>,
    ) -> Result<HashSet<EventDigest<T>>, KeylineStorageError<K::Error>> {
        let (certs, cgka_ops, prekeys) = self.ops_for_agent(agent.into()).await?;
        let mut digests = HashSet::new();

        for key_op in prekeys.values().flatten() {
            let event: Event<T> = Event::from(key_op.as_ref().clone());
            digests.insert(event.digest());
        }
        for cgka_op in cgka_ops {
            let event: Event<T> = Event::from(cgka_op);
            digests.insert(event.digest());
        }
        for cert in certs {
            let event: Event<T> = Event::from(cert);
            digests.insert(event.digest());
        }

        Ok(digests)
    }

    /// Every event each principal is sent, gathered once and deduplicated.
    pub async fn all_agent_events(
        &self,
    ) -> Result<AllAgentEvents<T>, KeylineStorageError<K::Error>> {
        let views = self.subject_views().await?;
        let all_cgka = self.cgka_ops_for_all_agents().await?;
        let all_prekey = self.prekey_ops_for_views(&views, &all_cgka).await?;

        let mut events = HashMap::new();

        let mut prekey_sources = HashMap::new();
        for (source_id, key_ops) in all_prekey.ops {
            let mut digests = Vec::with_capacity(key_ops.len());
            for key_op in key_ops {
                let event: Event<T> = Event::from(key_op.as_ref().clone());
                let digest = event.digest();
                digests.push(digest);
                events.entry(digest).or_insert(event);
            }
            prekey_sources.insert(source_id, digests);
        }

        let mut cgka_sources = HashMap::new();
        for (source_id, cgka_ops) in all_cgka.ops {
            let mut digests = Vec::with_capacity(cgka_ops.len());
            for cgka_op in cgka_ops {
                let event: Event<T> = Event::from(cgka_op);
                let digest = event.digest();
                digests.push(digest);
                events.entry(digest).or_insert(event);
            }
            cgka_sources.insert(source_id, digests);
        }

        // Certificates: per subject, its closure; per principal, the subjects it
        // stands over, itself included, and for those it was cut off from,
        // what explains that.
        let mut membership_sources = HashMap::new();
        let mut membership_index: HashMap<Identifier, HashSet<Identifier>> = HashMap::new();
        let mut explained: HashMap<Identifier, HashSet<EventDigest<T>>> = HashMap::new();
        for view in views {
            for (who, certs) in view.cut {
                let digests = explained.entry(who).or_default();
                for cert in certs {
                    let event: Event<T> = Event::from(cert);
                    let digest = event.digest();
                    digests.insert(digest);
                    events.entry(digest).or_insert(event);
                }
            }
            let mut digests = Vec::with_capacity(view.closure.len());
            for cert in view.closure {
                let event: Event<T> = Event::from(cert);
                let digest = event.digest();
                digests.push(digest);
                events.entry(digest).or_insert(event);
            }
            for member in view.live.iter().chain([&view.subject]) {
                membership_index
                    .entry(*member)
                    .or_default()
                    .insert(view.subject);
            }
            membership_sources.insert(view.subject, digests);
        }

        Ok(AllAgentEvents {
            events,
            membership_sources,
            explanations: explained
                .into_iter()
                .map(|(who, digests)| (who, digests.into_iter().collect()))
                .collect(),
            prekey_sources,
            cgka_sources,
            membership_index,
            prekey_index: all_prekey.index,
            cgka_index: all_cgka.index,
        })
    }

    #[instrument(skip_all)]
    /// Any identifier, as this replica knows it: a transient handle, built on
    /// demand.
    pub fn get_principal(&self, id: Identifier) -> Principal<Self> {
        Principal::new(self.clone(), id)
    }

    /// An individual this replica holds prekeys for.
    #[instrument(skip_all)]
    pub async fn get_individual(&self, id: IndividualId) -> Option<Individual<Self>> {
        self.has_individual(id)
            .await
            .then(|| Individual::new(self.clone(), id))
    }

    /// A group: a Keyline subject this replica knows as neither an individual
    /// nor a document.
    #[instrument(skip_all)]
    pub async fn get_group(
        &self,
        id: GroupId,
    ) -> Result<Option<Group<Self>>, KeylineStorageError<K::Error>> {
        Ok(self
            .has_group(id)
            .await?
            .then(|| Group::new(self.clone(), id)))
    }

    /// A document this replica holds: it is a member whose creation or
    /// invitation has merged.
    #[instrument(skip_all)]
    pub async fn get_document(&self, id: DocumentId) -> Option<Document<Self>> {
        self.has_document(id)
            .await
            .then(|| Document::new(self.clone(), id))
    }

    pub(crate) async fn individual_state(
        &self,
        id: IndividualId,
    ) -> Option<Arc<Mutex<IndividualState>>> {
        self.individuals.lock().await.get(&id).duped()
    }

    /// This replica's state for a document it is a member of.
    #[allow(clippy::type_complexity)]
    pub(crate) async fn document_state(
        &self,
        id: DocumentId,
    ) -> Option<Arc<Mutex<DocumentState<T>>>> {
        self.documents.lock().await.get(&id).duped()
    }

    /// Whether this replica holds the document: it is a member, and its
    /// creation or invitation has merged into its CGKA graph. To a replica that does
    /// not, such as a relay, a document is a Keyline subject like a group.
    #[instrument(skip_all)]
    pub async fn has_document(&self, id: DocumentId) -> bool {
        self.documents.lock().await.contains_key(&id)
    }

    /// Whether this replica holds `id`'s CGKA graph, joined or not.
    async fn contains_cgka_graph(&self, id: DocumentId) -> bool {
        self.has_document(id).await || self.unjoined.lock().await.contains_key(&id)
    }

    /// Whether a group with this id is known: a Keyline subject that is
    /// neither an individual nor a document here.
    #[instrument(skip_all)]
    pub async fn has_group(&self, id: GroupId) -> Result<bool, KeylineStorageError<K::Error>> {
        let ident = Identifier::from(id);
        if self.has_individual(IndividualId(ident)).await
            || self.has_document(DocumentId(ident)).await
        {
            return Ok(false);
        }
        let subject = ident;
        Ok(self.subjects().await?.contains(&subject))
    }

    /// Whether an individual with this id is known.
    #[instrument(skip_all)]
    pub async fn has_individual(&self, id: IndividualId) -> bool {
        self.individuals.lock().await.contains_key(&id)
    }

    /// Receive a prekey operation. It is a [`KeyOp`], so its signature was
    /// checked against its issuer:
    /// [`SignedKeyOp::verify`](crate::principal::individual::op::SignedKeyOp::verify)
    /// makes one from what a peer sent.
    #[instrument(skip_all)]
    pub async fn receive_prekey_op(&self, key_op: &KeyOp) -> Result<(), ReceivePrekeyOpError> {
        let id = key_op.issuer();
        // Prekeys are an individual's, whatever else its identifier names.
        // The active individual is in the table too.
        match self.individual_state(IndividualId(id)).await {
            Some(indie) => indie.lock().await.receive_prekey_op(key_op.clone())?,
            None => {
                self.register_individual(IndividualState::new(key_op.clone()))
                    .await;
            }
        }

        Ok(())
    }

    #[instrument(skip_all)]
    pub async fn receive_static_event(
        &self,
        static_event: StaticEvent<T>,
    ) -> Result<(), ReceiveStaticEventError<K::Error>> {
        match static_event {
            StaticEvent::PrekeysExpanded(add_op) => {
                let key_op = KeyOp::Add(add_op.verify().map_err(ReceivePrekeyOpError::from)?);
                self.receive_prekey_op(&key_op).await?
            }
            StaticEvent::PrekeyRotated(rot_op) => {
                let key_op = KeyOp::Rotate(rot_op.verify().map_err(ReceivePrekeyOpError::from)?);
                self.receive_prekey_op(&key_op).await?
            }
            StaticEvent::CgkaOperation(cgka_op) => {
                self.receive_cgka_op(*cgka_op).await?;
            }
            StaticEvent::Delegated(d) => {
                self.receive_certificate(Certificate::Delegation(Arc::new(d)))
                    .await?
            }
            StaticEvent::Revoked(r) => {
                self.receive_certificate(Certificate::Revocation(Arc::new(r)))
                    .await?
            }
        }
        Ok(())
    }

    /// Verify a Keyline certificate and insert it. Never pending: a
    /// certificate needs nothing else to arrive first.
    #[instrument(skip_all)]
    pub async fn receive_certificate(
        &self,
        cert: Certificate<ContentHeads<T>>,
    ) -> Result<(), ReceiveCertificateError<K::Error>> {
        self.insert_certificates(&[cert.verify()?]).await?;
        Ok(())
    }

    /// Whether `signed_op` is authorized on this document, evaluated over that
    /// op's certificate sets.
    ///
    /// Denied if a predecessor was already denied. Otherwise pending until every
    /// predecessor is in the CGKA graph, then denied if its citations are not
    /// in strictly ascending order, and otherwise pending until every cited
    /// certificate is recorded. After that the verdict depends only on the
    /// operation and its causal past, so it is final and deterministic.
    ///
    /// Conditions:
    /// * Its signer has `Read` or higher in its signing set (i.e., the predecessor
    ///   set plus the delegations it cites). The revocations it cites are left
    ///   out, so a member can cite the revocation of their own access.
    /// * An operation with no predecessors cites a root certificate of the
    ///   document whose audience is its signer or a node its signer has
    ///   `Admin` over in its signing set.
    /// * An add's `key_proof` is a prekey operation, signed by the added
    ///   member, whose key is the add's, and the added member has `Read` or
    ///   higher in the add's certificate set.
    /// * A remove does not list any specific members. Its effect comes only
    ///   from the removals implied by its citations.
    /// * An update rotates its signer's own key in the CGKA group.
    async fn cgka_op_is_authorized(
        &self,
        signed_op: &Verified<CgkaOperation>,
        doc_id: DocumentId,
    ) -> Result<Result<(), CgkaUnauthorized>, KeylineStorageError<K::Error>> {
        use CgkaUnauthorized::{Denied, Pending};

        let doc = Identifier::from(doc_id);
        let signer = signed_op.issuer();
        let op = signed_op.payload();

        let predecessors = op.predecessors();
        // An operation is authorized only if all its predecessors are.
        let any_denied = {
            let sets = self.certificate_sets.lock().await;
            predecessors.iter().any(|p| sets.is_denied(p))
        };
        if any_denied {
            return Ok(Err(Denied));
        }
        let Some(predecessor_set) = self.predecessor_set(doc_id, &predecessors).await else {
            return Ok(Err(Pending));
        };

        let cited = op.citations();
        if !self.record_citations(op).await? {
            return Ok(Err(Pending));
        }

        let (signing_set, root_audiences) = {
            let citations = self.certificates.cited.lock();
            let mut signing_set = predecessor_set;
            signing_set.extend(
                cited
                    .iter()
                    .filter(|c| citations.delegation(c).is_some())
                    .copied(),
            );
            let root_audiences: Vec<Identifier> = cited
                .iter()
                .filter_map(|c| citations.delegation(c))
                .filter(|(issuer, d)| *issuer == doc && d.subject == doc)
                .map(|(_, d)| d.audience)
                .collect();
            (signing_set, root_audiences)
        };
        if !self.is_reader_over(&signing_set, doc, signer).await? {
            return Ok(Err(Denied));
        }
        if predecessors.is_empty() {
            let mut is_root_to_signer = root_audiences.contains(&signer);
            if !is_root_to_signer {
                for audience in &root_audiences {
                    let over = self.members_over(&signing_set, *audience).await?;
                    if over.get(&signer) == Some(&Power::Admin) {
                        is_root_to_signer = true;
                        break;
                    }
                }
            }
            if !is_root_to_signer {
                return Ok(Err(Denied));
            }
        }

        match &op.change {
            // The leaf an update rotates is its signer's.
            CgkaChange::Update { .. } => {}
            CgkaChange::Add {
                added_id,
                pk,
                key_proof,
                ..
            } => {
                if !proves_key(key_proof.as_deref(), added_id, pk) {
                    return Ok(Err(Denied));
                }
                let mut certificate_set = signing_set;
                certificate_set.extend(cited.iter().copied());
                if !self
                    .is_reader_over(&certificate_set, doc, added_id.id())
                    .await?
                {
                    return Ok(Err(Denied));
                }
            }
            CgkaChange::Remove { removed, .. } => {
                // The members to remove are inferred from the cited certificates
                // and not from an explicit list.
                if !removed.is_empty() {
                    return Ok(Err(Denied));
                }
                // Not a condition. Merging the remove queries which members its
                // certificate set removes and that answer is cached.
                let mut certificate_set = signing_set;
                certificate_set.extend(cited.iter().copied());
                self.members_over(&certificate_set, doc).await?;
            }
        }
        Ok(Ok(()))
    }

    /// Everything the operations `heads` and their causal ancestors cite, from
    /// this replica's CGKA graph for `doc_id`, whether it has joined it or
    /// not. Returns `None` if that graph lacks any of them.
    async fn predecessor_set(
        &self,
        doc_id: DocumentId,
        heads: &Set<Digest<CgkaOperation>>,
    ) -> Option<CitationSet> {
        if heads.is_empty() {
            return Some(CitationSet::default());
        }
        if let Some(doc) = self.document_state(doc_id).await {
            let locked = doc.lock().await;
            let mut sets = self.certificate_sets.lock().await;
            return sets.predecessor_set(locked.cgka(), heads);
        }
        let unjoined = self.unjoined.lock().await;
        let cgka = unjoined.get(&doc_id)?;
        let mut sets = self.certificate_sets.lock().await;
        sets.predecessor_set(cgka, heads)
    }

    /// `audience`'s power over `subject` in Keyline's positive graph, which
    /// ignores revocations and so only ever rises.
    async fn positive_power(
        &self,
        subject: Identifier,
        audience: Identifier,
    ) -> Result<Option<Power>, KeylineStorageError<K::Error>> {
        Ok(self
            .keyline()
            .positive_power(subject, audience)
            .await
            .map_err(KeylineStorageError::new)?
            .value)
    }

    /// Whether `who` has ever had any power over `doc`. Positive power, so
    /// operations from before a revocation still merge.
    async fn ever_stands_over(
        &self,
        doc: Identifier,
        who: Identifier,
    ) -> Result<bool, KeylineStorageError<K::Error>> {
        Ok(self.positive_power(doc, who).await?.is_some())
    }

    #[instrument(skip_all)]
    pub async fn receive_cgka_op(
        &self,
        signed_op: verified::Signed<CgkaOperation>,
    ) -> Result<(), ReceiveCgkaOpError<K::Error>> {
        // The digest covers the issuer and the payload, not the signature, so
        // an operation already in the CGKA graph is skipped before its
        // signature is checked again.
        let digest = signed_op.digest();
        let payload: CgkaOperation = signed_op.encoded().decode().map_err(VerifyError::from)?;
        if self
            .has_cgka_op(DocumentId::from(payload.doc_id), digest)
            .await
        {
            return Ok(());
        }
        let signed_op = signed_op.verify()?;
        let doc_id = DocumentId::from(signed_op.payload().doc_id);

        // Authorization reads the certificates and this replica's CGKA graph.
        // This replica need not be a member of the CGKA group.
        match self.cgka_op_is_authorized(&signed_op, doc_id).await? {
            Ok(()) => {}
            Err(CgkaUnauthorized::Pending) => {
                return Err(ReceiveCgkaOpError::PendingCgkaAuthorization(Box::new(
                    doc_id,
                )))
            }
            Err(CgkaUnauthorized::Denied) => {
                self.certificate_sets.lock().await.deny(digest);
                return Err(ReceiveCgkaOpError::UnauthorizedCgkaOp(Box::new(doc_id)));
            }
        }

        let op = Arc::new(signed_op);
        let me = self.active.id();
        let secrets: BTreeMap<ShareKey, ShareSecretKey> = {
            let pairs = self.active.key_pairs.lock().await;
            own_cgka_keys(&op, me)
                .into_iter()
                .filter_map(|pk| pairs.get(&pk).map(|sk| (pk, *sk)))
                .collect()
        };
        let merged = {
            // Serialized with writes, which choose an operation's citations
            // from the CGKA graph's heads and then sign it on those same heads.
            let _reconciled = self.certificates.reconciled.lock().await;
            self.merge_received(doc_id, op.dupe(), me, &secrets).await
        };
        let merged = match merged {
            Ok(merged) => merged,
            // `is_final` drops the event, so it never enters the CGKA graph
            // and an operation built on it would wait for it forever. Deny
            // those instead.
            Err(ReceiveCgkaOpError::CgkaError(e)) if never_merges(&e) => {
                self.certificate_sets.lock().await.deny(op.digest());
                return Err(ReceiveCgkaOpError::CgkaError(e));
            }
            Err(e) => return Err(e),
        };
        if merged {
            self.event_listener.on_cgka_op(&op).await;
        }
        Ok(())
    }

    /// Whether the CGKA graph for `doc_id` has the operation `digest`.
    async fn has_cgka_op(&self, doc_id: DocumentId, digest: Digest<CgkaOperation>) -> bool {
        let has_digest = |cgka: &Cgka<KeylineImplicitRemovesProtocol>| cgka.op(&digest).is_some();
        if let Some(state) = self.document_state(doc_id).await {
            return has_digest(state.lock().await.cgka());
        }
        self.unjoined
            .lock()
            .await
            .get(&doc_id)
            .is_some_and(has_digest)
    }

    /// Merge an authorized operation, whose predecessors the CGKA graph
    /// already has, into this replica's CGKA for `doc_id`. `true` if the graph
    /// did not have it. For a document whose CGKA group this replica has not
    /// joined, the operation goes into its unjoined CGKA graph, or fails with
    /// `UnknownDocument` if this replica has never stood over the document.
    async fn merge_received(
        &self,
        doc_id: DocumentId,
        op: Arc<Verified<CgkaOperation>>,
        me: IndividualId,
        secrets: &BTreeMap<ShareKey, ShareSecretKey>,
    ) -> Result<bool, ReceiveCgkaOpError<K::Error>> {
        let doc = Identifier::from(doc_id);
        if let Some(state) = self.document_state(doc_id).await {
            let mut locked = state.lock().await;
            return self
                .require_keyline_answers(doc, locked.cgka_mut(), |cgka| {
                    merge_one(cgka, op.dupe(), me, secrets)
                })
                .await?;
        }

        // Not a member. If this replica has ever stood over the document, its
        // operations merge into an unjoined CGKA in causal order. A reader's
        // becomes its document once its invitation merges; starting on the
        // first operation, not the invitation, lets every arriving one make
        // progress. A relay's stays unjoined, and is served from there.
        let stands_over =
            invites(op.payload(), me) || self.ever_stands_over(doc, me.into()).await?;
        let (merged, joined) = {
            let mut unjoined = self.unjoined.lock().await;
            let cgka = match unjoined.entry(doc_id) {
                Entry::Occupied(entry) => entry.into_mut(),
                Entry::Vacant(entry) if stands_over => {
                    let cgka = Cgka::new(
                        doc_id,
                        me,
                        ShareKeyMap::new(),
                        self.implicit_removes_protocol(doc),
                    );
                    entry.insert(cgka)
                }
                Entry::Vacant(_) => {
                    return Err(ReceiveCgkaOpError::UnknownDocument(Box::new(doc_id)))
                }
            };
            let merged = self
                .require_keyline_answers(doc, cgka, |cgka| merge_one(cgka, op.dupe(), me, secrets))
                .await??;
            let joined = if invites(op.payload(), me) {
                unjoined.remove(&doc_id)
            } else {
                None
            };
            (merged, joined)
        };
        if let Some(cgka) = joined {
            self.documents
                .lock()
                .await
                .entry(doc_id)
                .or_insert_with(|| {
                    Arc::new(Mutex::new(DocumentState::with_cgka(
                        doc_id,
                        cgka,
                        HashSet::new(),
                        HashSet::new(),
                    )))
                });
        }
        Ok(merged)
    }

    /// Add this identity to `doc_id`'s CGKA group, for a reader who is not a
    /// member because no writer has its prekeys. Returns whether it did.
    ///
    /// Does nothing if this identity is already a member, if an add of it is
    /// waiting to be applied (that add may contain an invitation, which a
    /// self-add ordered ahead of it would lose), or if the add's certificate
    /// set would not give this identity `Read`.
    ///
    /// The new member can read content from the next update by another member
    /// onwards, since an add of oneself wraps no root secrets.
    pub async fn add_self_to(&self, doc_id: DocumentId) -> Result<bool, CgkaSyncError<K::Error>> {
        let me = self.active.id();
        let (doc, my_id) = (Identifier::from(doc_id), Identifier::from(me));
        let Some(prekey) = self.active.pick_prekey(doc_id).await else {
            return Ok(false);
        };
        let sk = { self.active.key_pairs.lock().await.get(&prekey).copied() };
        let (Some(sk), Some(key_proof)) = (sk, self.key_proof(me, &prekey).await) else {
            return Ok(false);
        };
        let waiting_add = self.pending_events.lock().await.iter().any(|event| {
            let StaticEvent::CgkaOperation(op) = event.as_ref() else {
                return false;
            };
            op.encoded().decode().is_ok_and(|op: CgkaOperation| {
                DocumentId::from(op.doc_id) == doc_id && invites(&op, me)
            })
        });
        if waiting_add {
            return Ok(false);
        }

        let mut fresh = Vec::new();
        {
            // Held throughout, so no operation is received into the unjoined
            // CGKA graph while it becomes a document.
            let _reconciled = self.certificates.reconciled.lock().await;
            let held = self.document_state(doc_id).await;
            let state = match &held {
                Some(state) => state.dupe(),
                None => {
                    let Some(cgka) = self.unjoined.lock().await.get(&doc_id).cloned() else {
                        return Ok(false);
                    };
                    Arc::new(Mutex::new(DocumentState::with_cgka(
                        doc_id,
                        cgka,
                        HashSet::new(),
                        HashSet::new(),
                    )))
                }
            };
            if self.cgka_group_members(doc, &state).await?.contains(&me) {
                return Ok(false);
            }
            let NextCitations { cited, readers, .. } = self.next_citations(doc, &state).await?;
            if !readers.contains(&my_id) {
                return Ok(false);
            }
            let signer = self.active.signer.clone();
            let made = {
                let mut locked = state.lock().await;
                locked.cgka_mut().owner_sks_mut().insert(prekey, sk);
                locked
                    .add_cgka_member(me, prekey, Some(key_proof), cited, &signer)
                    .await?
            };
            if held.is_none() {
                self.unjoined.lock().await.remove(&doc_id);
                self.documents.lock().await.insert(doc_id, state);
            }
            fresh.extend(made.into_iter().map(Arc::new));
        }
        for op in &fresh {
            self.event_listener.on_cgka_op(op).await;
        }
        Ok(true)
    }

    /// Adopt into every held `Cgka` the secrets this identity holds for its own
    /// keys, as after importing secrets from another instance.
    async fn adopt_all_cgka_secrets(&self) {
        let (me, secrets) = {
            let active = &self.active;
            let secrets = active.key_pairs.lock().await.clone();
            (active.id(), secrets)
        };
        let docs: Vec<_> = { self.documents.lock().await.values().cloned().collect() };
        for doc in docs {
            adopt_own_cgka_secrets(doc.lock().await.cgka_mut(), me, &secrets);
        }
    }

    /// Export prekey secrets as an opaque blob for backup/migration.
    ///
    /// # Security
    ///
    /// The returned bytes contain unencrypted secret key material.
    /// Callers are responsible for protecting this data at rest and in transit.
    pub async fn export_prekey_secrets(&self) -> Vec<u8> {
        self.active.export_prekey_secrets().await
    }

    /// Import prekey secrets from a previously exported blob, extending the existing set.
    ///
    /// After importing, any pending events that were stuck due to missing
    /// prekey secrets are automatically retried.
    pub async fn import_prekey_secrets(
        &self,
        bytes: &[u8],
    ) -> Result<Vec<Arc<StaticEvent<T>>>, ImportPrekeySecretsError> {
        self.active.import_prekey_secrets(bytes).await?;
        self.adopt_all_cgka_secrets().await;
        Ok(self.ingest_unsorted_static_events(vec![]).await)
    }

    /// Everything this replica cannot recompute, for persistence. Fails if
    /// the certificate set cannot be read: an archive without it would lose
    /// every group and grant.
    #[instrument(skip_all)]
    pub async fn into_archive(&self) -> Result<Archive<T>, KeylineStorageError<K::Error>> {
        let mut archive = self.archive_state().await;
        archive.certificates = self
            .keyline()
            .certificates()
            .await
            .map_err(KeylineStorageError::new)?
            .value;
        Ok(archive)
    }

    /// [`Self::into_archive`] without the certificate set: what a fork needs,
    /// since it shares the store.
    async fn archive_state(&self) -> Archive<T> {
        let active = { self.active.into_archive().await };

        let mut individuals = HashMap::new();
        for (id, indie) in self.individuals.lock().await.iter() {
            individuals.insert(*id, indie.lock().await.clone());
        }

        // The operations of every CGKA graph: each held document's, and each
        // unjoined one (awaiting an invitation, or relayed), whose operations
        // are no longer pending.
        let mut docs = HashMap::new();
        let mut cgka_ops: Vec<verified::Signed<CgkaOperation>> = Vec::new();
        for (id, doc) in self.documents.lock().await.iter() {
            let locked = doc.lock().await;
            docs.insert(*id, locked.into_archive());
            cgka_ops.extend(
                cgka_ops_for(locked.cgka())
                    .iter()
                    .map(|op| op.signed().as_ref().clone()),
            );
        }
        for cgka in self.unjoined.lock().await.values() {
            cgka_ops.extend(
                cgka_ops_for(cgka)
                    .iter()
                    .map(|op| op.signed().as_ref().clone()),
            );
        }

        let pending_events = self
            .pending_events
            .lock()
            .await
            .iter()
            .map(|event| event.as_ref().clone())
            .collect();

        Archive {
            active,
            individuals,
            docs,
            cgka_ops,
            certificates: Vec::new(),
            pending_events,
        }
    }

    /// Rebuild a replica from its archive. The certificates are inserted into
    /// `keyline` (a no-op for those it already holds), and each document's
    /// `Cgka` is rebuilt from its archived operations. As with [`Self::generate`],
    /// `keyline` becomes this keyhive's own.
    #[instrument(skip_all)]
    pub async fn try_from_archive(
        archive: &Archive<T>,
        signer: S,
        ciphertext_store: C,
        listener: L,
        keyline: K,
        csprng: Arc<Mutex<R>>,
    ) -> Result<Self, TryFromArchiveError<K::Error>> {
        let certificates = Arc::new(Certificates {
            store: keyline,
            reconciled: async_lock::Mutex::new(None),
            cited: SharedCitations::default(),
        });
        Self::from_archive_sharing(
            archive,
            signer,
            ciphertext_store,
            listener,
            certificates,
            csprng,
        )
        .await
    }

    /// [`Self::try_from_archive`] over certificates shared with another keyhive:
    /// a fork and its trunk.
    async fn from_archive_sharing(
        archive: &Archive<T>,
        signer: S,
        ciphertext_store: C,
        listener: L,
        shared: Arc<Certificates<K>>,
        csprng: Arc<Mutex<R>>,
    ) -> Result<Self, TryFromArchiveError<K::Error>> {
        let signer_id = IndividualId::try_from(signer.verifying_key())?;
        if signer_id != archive.id() {
            return Err(TryFromArchiveError::NotTheSigner {
                archive: archive.id(),
                signer: signer_id,
            });
        }
        let raw_active = Active::from_archive(&archive.active, signer, listener.clone())?;

        let mut individuals = HashMap::new();
        for indie in archive.individuals.values() {
            // Keyed by the issuer of its verified operations, not the
            // archive's key for it.
            individuals.insert(indie.id(), Arc::new(Mutex::new(indie.clone())));
        }
        individuals.insert(archive.active.individual.id(), raw_active.individual.dupe());

        let verified: Vec<_> = archive
            .certificates
            .iter()
            .cloned()
            .map(Certificate::verify)
            .collect::<Result<Vec<_>, _>>()?;
        shared.cited.lock().insert_multiple(&verified);
        // A fork's archive holds none: it shares the store.
        if !verified.is_empty() {
            let mut last = shared.reconciled.lock().await;
            *last = Some(
                shared
                    .store
                    .insert(verified)
                    .await
                    .map_err(KeylineStorageError::new)?,
            );
        }

        let me = raw_active.id();
        let secrets = raw_active.key_pairs.lock().await.clone();
        let hive = Keyhive(Arc::new(KeyhiveState {
            active: raw_active,
            individuals: Mutex::new(individuals),
            documents: Mutex::new(HashMap::new()),
            unjoined: Mutex::new(HashMap::new()),
            certificate_sets: Mutex::new(CertificateSets::new()),
            pending_events: Mutex::new(
                archive
                    .pending_events
                    .iter()
                    .cloned()
                    .map(Arc::new)
                    .collect(),
            ),
            csprng,
            ciphertext_store,
            event_listener: listener,
            certificates: shared,
            _plaintext_phantom: PhantomData,
        }));

        // Each document's CGKA is rebuilt from its operations, with the
        // certificates above recorded for its implicit removes protocol. It becomes a
        // held document if its invitation (or creation) has merged, and
        // otherwise stays unjoined: awaiting it, or relayed.
        let mut by_doc: HashMap<DocumentId, Vec<Arc<Verified<CgkaOperation>>>> = HashMap::new();
        let mut deferred = HashSet::new();
        for signed in archive.cgka_ops.iter().cloned() {
            let op = match signed.verify() {
                Ok(op) => Arc::new(op),
                Err(e) => {
                    tracing::warn!(error = %e, "an archived CGKA operation does not verify");
                    continue;
                }
            };
            if !hive.record_citations(op.payload()).await? {
                // Kept, to apply once the certificate arrives.
                deferred.insert(op.digest());
                hive.pending_events
                    .lock()
                    .await
                    .push(Arc::new(StaticEvent::CgkaOperation(Box::new(
                        op.signed().as_ref().clone(),
                    ))));
                continue;
            }
            let doc_id = DocumentId::from(op.payload().doc_id);
            by_doc.entry(doc_id).or_default().push(op);
        }
        let mut documents = HashMap::new();
        let mut unjoined = HashMap::new();
        for (doc_id, ops) in by_doc {
            let invitations: HashSet<_> = ops
                .iter()
                .filter(|op| invites(op.payload(), me))
                .map(|op| op.digest())
                .collect();
            let (cgka, mut unapplied) = hive.cgka_from_ops(doc_id, ops, me, &secrets).await;
            // Operations that descend from a deferred operation are deferred with it.
            let mut has_progressed = true;
            while has_progressed {
                has_progressed = false;
                let mut pending = hive.pending_events.lock().await;
                unapplied.retain(|op| {
                    let should_wait = op
                        .payload()
                        .predecessors()
                        .iter()
                        .any(|p| deferred.contains(p));
                    if should_wait {
                        deferred.insert(op.digest());
                        pending.push(Arc::new(StaticEvent::CgkaOperation(Box::new(
                            op.signed().as_ref().clone(),
                        ))));
                        has_progressed = true;
                    }
                    !should_wait
                });
            }
            for op in &unapplied {
                tracing::warn!(
                    %doc_id,
                    op = %op.digest(),
                    "an archived operation's predecessors are missing or did not apply"
                );
            }
            if invitations.is_empty() || !cgka.contains_predecessors(&invitations) {
                unjoined.insert(doc_id, cgka);
                continue;
            }
            let mut doc = DocumentState::with_cgka(doc_id, cgka, HashSet::new(), HashSet::new());
            if let Some(archived) = archive.docs.get(&doc_id) {
                doc.content_heads = archived.content_heads.clone();
                doc.content_state = archived.content_state.clone();
                for (content_ref, key) in &archived.content_keys {
                    doc.remember_key(AncestorKey::from_trusted_storage(
                        content_ref.clone(),
                        doc_id.into(),
                        *key,
                    ));
                }
            }
            documents.insert(doc_id, Arc::new(Mutex::new(doc)));
        }
        for doc_id in archive.docs.keys() {
            if documents.contains_key(doc_id) {
                continue;
            }
            tracing::warn!(%doc_id, "the archived CGKA graph does not rebuild from its operations");
        }
        *hive.documents.lock().await = documents;
        *hive.unjoined.lock().await = unjoined;

        Ok(hive)
    }

    #[allow(clippy::type_complexity)]
    #[instrument(level = "trace", skip_all)]
    pub async fn ingest_archive(
        &self,
        archive: Archive<T>,
    ) -> Result<Vec<Arc<StaticEvent<T>>>, ReceiveStaticEventError<K::Error>> {
        tracing::debug!("Keyhive::ingest_archive()");
        self.active
            .key_pairs
            .lock()
            .await
            .extend(archive.active.key_pairs);
        // The archive's own individual goes through the table like the rest:
        // ours is there too, sharing the active individual's state, so an
        // archive of this identity merges into it, and another identity's
        // adds one more individual rather than merging into ours.
        let archived = archive
            .individuals
            .into_values()
            .chain(std::iter::once(archive.active.individual));
        for indie in archived {
            let id = indie.id();
            let mut locked_indies = self.individuals.lock().await;
            if let Some(our_indie) = locked_indies.get_mut(&id) {
                our_indie.merge_async(indie).await;
            } else {
                locked_indies.insert(id, Arc::new(Mutex::new(indie)));
            }
        }
        self.adopt_all_cgka_secrets().await;

        let events = archive
            .certificates
            .into_iter()
            .map(|cert| StaticEvent::from(Event::from(cert)))
            .chain(
                archive
                    .cgka_ops
                    .into_iter()
                    .map(|op| StaticEvent::CgkaOperation(Box::new(op))),
            )
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
        tracing::debug!("Keyhive::ingest_unsorted_static_events()");
        use std::collections::{HashMap, HashSet};
        let mut replayed_pending: HashSet<Digest<StaticEvent<T>>> = HashSet::new();
        for event in self.pending_events.lock().await.iter() {
            replayed_pending.insert(event.digest());
            events.push(event.as_ref().clone());
        }

        // Deduplicate events by hash
        let mut unique_events: HashMap<Digest<StaticEvent<T>>, StaticEvent<T>> = HashMap::new();
        for event in events {
            let hash = event.digest();
            unique_events.entry(hash).or_insert(event);
        }
        let mut epoch: Vec<StaticEvent<T>> = unique_events.into_values().collect();

        loop {
            let mut next_epoch = vec![];
            let mut err = None;
            let epoch_len = epoch.len();

            for event in epoch {
                if let Err(e) = self.receive_static_event(event.clone()).await {
                    if e.is_final() {
                        tracing::warn!(error = %e, "dropping an event that can never apply");
                    } else {
                        err = Some(e);
                        next_epoch.push(event);
                    }
                }
            }

            if next_epoch.is_empty() {
                tracing::debug!("Finished ingesting static events");
                self.pending_events
                    .lock()
                    .await
                    .retain(|e| !replayed_pending.contains(&e.digest()));
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
        events: HashMap<Digest<Event<T>>, Event<T>>,
    ) -> Result<(), ReceiveStaticEventError<K::Error>> {
        tracing::debug!("Keyhive::ingest_event_table");
        self.ingest_unsorted_static_events(
            events.values().cloned().map(Into::into).collect::<Vec<_>>(),
        )
        .await;
        Ok(())
    }

    pub async fn stats(&self) -> Stats {
        let active_prekey_count = self.active.individual.lock().await.prekey_ops().len() as u64;

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

        let mut cgka_operations = 0;
        let held: Vec<_> = { self.documents.lock().await.values().cloned().collect() };
        for doc in held {
            cgka_operations += doc.lock().await.cgka().ops_count() as u64;
        }
        // A relay or a reader awaiting its invitation holds a document's
        // CGKA graph unjoined. Its operations count too.
        for cgka in self.unjoined.lock().await.values() {
            cgka_operations += cgka.ops_count() as u64;
        }
        // Groups are the Keyline subjects that are neither individuals nor
        // documents here. `stats` cannot report a store failure; it is
        // logged, and counts none.
        let groups = match self.subjects().await {
            Ok(subjects) => {
                let individuals = self.individuals.lock().await;
                let documents = self.documents.lock().await;
                subjects
                    .into_iter()
                    .filter(|id| {
                        !individuals.contains_key(&IndividualId(*id))
                            && !documents.contains_key(&DocumentId(*id))
                    })
                    .count() as u64
            }
            Err(error) => {
                tracing::warn!(%error, "could not read subjects; counting no groups");
                0
            }
        };
        // `stats` cannot report a store failure; it is logged, and counts none.
        let (delegations, revocations) = match self.keyline().certificates().await {
            Ok(answer) => answer.value.iter().fold((0, 0), |(d, r), cert| match cert {
                Certificate::Delegation(_) => (d + 1, r),
                Certificate::Revocation(_) => (d, r + 1),
            }),
            Err(error) => {
                let error = KeylineStorageError::new(error);
                tracing::warn!(%error, "could not read certificates; counting none");
                (0, 0)
            }
        };

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
                    if IndividualId(signed.issuer()) == active_id {
                        pending_prekeys_expanded_by_active += 1;
                    }
                }
                StaticEvent::PrekeyRotated(signed) => {
                    pending_prekey_rotated += 1;
                    if IndividualId(signed.issuer()) == active_id {
                        pending_prekey_rotated_by_active += 1;
                    }
                }
                StaticEvent::CgkaOperation(signed) => {
                    pending_cgka_operation += 1;
                    if IndividualId(signed.issuer()) == active_id {
                        pending_cgka_operation_by_active += 1;
                    }
                }
                // A certificate never waits on another, so one is pending only
                // if it failed to verify.
                StaticEvent::Delegated(signed) => {
                    pending_delegated += 1;
                    if IndividualId::from(signed.issuer()) == active_id {
                        pending_delegated_by_active += 1;
                    }
                }
                StaticEvent::Revoked(signed) => {
                    pending_revoked += 1;
                    if IndividualId::from(signed.issuer()) == active_id {
                        pending_revoked_by_active += 1;
                    }
                }
            }
        }

        Stats {
            individuals: self.individuals.lock().await.len() as u64,
            groups,
            docs: self.documents.lock().await.len() as u64,
            delegations,
            revocations,
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

    /// What access `who` has for `doc`. Returns `None` for no access.
    ///
    /// `None` for a principal we have not heard of.
    pub async fn access_for_doc(
        &self,
        who: impl Into<Identifier>,
        doc: DocumentId,
    ) -> Result<Option<Power>, KeylineStorageError<K::Error>> {
        Ok(self.members_of(doc.into()).await?.get(&who.into()).copied())
    }

    pub(crate) async fn document_by_id(
        &self,
        id: DocumentId,
    ) -> Result<Arc<Mutex<DocumentState<T>>>, NotFound> {
        self.document_state(id)
            .await
            .ok_or_else(|| NotFound::new(id))
    }

    /// This replica's document for `id`, as a member of its CGKA group.
    /// Returns `None` if it holds the CGKA graph unjoined, so has no keys, and
    /// a `NotFound` error if it has nothing for it.
    async fn member_document(
        &self,
        id: DocumentId,
    ) -> Result<Option<Arc<Mutex<DocumentState<T>>>>, NotFound> {
        match self.document_state(id).await {
            Some(doc) => Ok(Some(doc)),
            // Held, but not joined: no keys.
            None if self.unjoined.lock().await.contains_key(&id) => Ok(None),
            None => Err(NotFound::new(id)),
        }
    }
}

impl<
        F: FutureForm,
        S: AsyncSigner<F> + Clone,
        T: ContentRef + Debug,
        P: Decode,
        C: CiphertextStore<F, T, P> + CiphertextStoreExt<F, T, P> + Clone,
        L: MembershipListener<F, T>,
        R: rand::CryptoRng + rand::RngCore,
        K: Keyline<F, RetentionWatermark = ContentHeads<T>>,
    > Debug for KeyhiveState<F, S, T, P, C, L, R, K>
{
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
        f.debug_struct("KeyhiveState")
            .field("active", &self.active)
            .field("individuals", &self.individuals)
            .field("documents", &self.documents)
            .field("ciphertext_store", &"<STORE>")
            .field("csprng", &"<CSPRNG>")
            .finish()
    }
}

impl<
        F: FutureForm,
        S: AsyncSigner<F> + Clone,
        T: ContentRef + Debug,
        P: Decode,
        C: CiphertextStore<F, T, P> + CiphertextStoreExt<F, T, P> + Clone,
        L: MembershipListener<F, T>,
        R: rand::CryptoRng + rand::RngCore,
        K: Keyline<F, RetentionWatermark = ContentHeads<T>>,
    > Debug for Keyhive<F, S, T, P, C, L, R, K>
{
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
        self.0.fmt(f)
    }
}

impl<
        F: FutureForm,
        S: AsyncSigner<F> + Clone,
        T: ContentRef + Clone,
        P: Decode + Clone,
        C: CiphertextStore<F, T, P> + CiphertextStoreExt<F, T, P> + Clone,
        L: MembershipListener<F, T>,
        R: rand::CryptoRng + rand::RngCore + Clone,
        K: Keyline<F, RetentionWatermark = ContentHeads<T>>,
    > ForkAsync for Keyhive<F, S, T, P, C, L, R, K>
where
    Log<T>: MembershipListener<F, T>,
    K::Error: Send + Sync + 'static,
{
    type AsyncForked = Keyhive<F, S, T, P, C, Log<T>, R, K>;

    /// A fork for [`transact_async`](crate::transact::transact_async). It
    /// copies this keyhive's state but _shares its Keyline store_, so a
    /// transaction on a `Keyhive` is neither isolated nor all-or-nothing for
    /// membership:
    ///
    /// - A certificate the fork writes takes effect in the trunk at once: a
    ///   delegation or revocation changes membership as soon as it is
    ///   inserted. It stays if the transaction fails, and the trunk's
    ///   listener is told of it only when the fork is merged.
    /// - The fork's `Cgka`s and their CGKA operations are its own and are dropped
    ///   if the transaction fails. A failed transaction that revoked a reader
    ///   can so leave them in the trunk's CGKA group while Keyline says they no
    ///   longer read.
    /// - Writes on the trunk while the fork is alive see the fork's
    ///   certificates but not its CGKA graphs; merging replays the fork's
    ///   operations, which can add a member the trunk has since revoked, or
    ///   remove one it has re-added.
    ///
    /// Use it only for transactions that do not change membership, or that
    /// cannot fail once they have.
    async fn fork_async(&self) -> Self::AsyncForked {
        let signer = { self.active.signer.clone() };
        Keyhive::from_archive_sharing(
            &self.archive_state().await,
            signer,
            self.ciphertext_store.clone(),
            Log::new(),
            self.certificates.dupe(),
            self.csprng.clone(),
        )
        .await
        .expect("an archive with no certificates verifies and inserts nothing")
    }
}

impl<
        F: FutureForm,
        S: AsyncSigner<F> + Clone,
        T: ContentRef + Clone,
        P: Decode + Clone,
        C: CiphertextStore<F, T, P> + CiphertextStoreExt<F, T, P> + Clone,
        L: MembershipListener<F, T>,
        R: rand::CryptoRng + rand::RngCore + Clone,
        K: Keyline<F, RetentionWatermark = ContentHeads<T>>,
    > MergeAsync for Arc<Mutex<Keyhive<F, S, T, P, C, L, R, K>>>
where
    Log<T>: MembershipListener<F, T>,
    K::Error: Send + Sync + 'static,
{
    async fn merge_async(&self, fork: Self::AsyncForked) {
        self.lock().await.absorb_fork(fork).await;
    }
}

impl<
        F: FutureForm,
        S: AsyncSigner<F> + Clone,
        T: ContentRef,
        P: Decode + Clone,
        C: CiphertextStore<F, T, P> + CiphertextStoreExt<F, T, P> + Clone,
        L: MembershipListener<F, T>,
        R: rand::CryptoRng + rand::RngCore + Clone,
        K: Keyline<F, RetentionWatermark = ContentHeads<T>>,
    > Keyhive<F, S, T, P, C, L, R, K>
where
    Log<T>: MembershipListener<F, T>,
    K::Error: Send + Sync + 'static,
{
    async fn absorb_fork(&self, fork: Keyhive<F, S, T, P, C, Log<T>, R, K>) {
        let forked_active = { fork.active.clone() };
        self.active.merge_async(forked_active).await;

        {
            let mut locked_fork_indies = fork.individuals.lock().await;
            let mut locked_indies = self.individuals.lock().await;
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
            let certificate = match event {
                // Merged with the individuals above.
                Event::PrekeysExpanded(_) | Event::PrekeyRotated(_) => continue,
                Event::Delegated(signed) => Some(Certificate::Delegation(signed.dupe())),
                Event::Revoked(signed) => Some(Certificate::Revocation(signed.dupe())),
                Event::CgkaOperation(_) => None,
            };
            // The fork shares the store, so the trunk already holds what the
            // fork wrote, and inserting it again announces nothing: tell the
            // trunk's listener here.
            if let Some(certificate) = certificate {
                match certificate.verify() {
                    Ok(verified) => self.notify(&verified).await,
                    Err(error) => tracing::warn!(%error, "a fork's certificate does not verify"),
                }
                continue;
            }

            // The trunk may have moved since the fork: an event that does not
            // apply yet waits like any other received one.
            if let Err(error) = self.receive_static_event(event.clone().into()).await {
                if error.is_final() {
                    tracing::warn!(%error, "dropping a fork's event that can never apply");
                } else {
                    self.pending_events
                        .lock()
                        .await
                        .push(Arc::new(event.clone().into()));
                }
            }
        }

        // A document the fork generated is rebuilt here from its operations,
        // which contain no content heads, so take the fork's heads when this
        // replica has none. For every document, add the keys of the content the
        // fork wrote or read where this replica has none for that ref, so a
        // later write here can list it as a predecessor.
        let forked_docs: Vec<_> = {
            fork.documents
                .lock()
                .await
                .iter()
                .map(|(id, doc)| (*id, doc.dupe()))
                .collect()
        };
        for (doc_id, forked) in forked_docs {
            let Some(doc) = self.document_state(doc_id).await else {
                continue;
            };
            let (heads, keys): (_, Vec<_>) = {
                let forked = forked.lock().await;
                (
                    forked.content_heads.clone(),
                    forked.keys().cloned().collect(),
                )
            };
            let mut locked = doc.lock().await;
            if locked.content_heads.is_empty() {
                locked.content_heads = heads;
            }
            for key in keys {
                locked.remember_key(key);
            }
        }
    }
}

impl<
        F: FutureForm,
        S: AsyncSigner<F> + Clone,
        T: ContentRef,
        P: Decode,
        C: CiphertextStore<F, T, P> + CiphertextStoreExt<F, T, P> + Clone,
        L: MembershipListener<F, T>,
        R: rand::CryptoRng + rand::RngCore,
        K: Keyline<F, RetentionWatermark = ContentHeads<T>>,
    > Verifiable for Keyhive<F, S, T, P, C, L, R, K>
{
    fn verifying_key(&self) -> ed25519_dalek::VerifyingKey {
        self.active.verifying_key()
    }
}

#[derive(Debug, Error)]
pub enum ReceiveStaticEventError<E: core::error::Error + 'static> {
    #[error(transparent)]
    ReceivePrekeyOpError(#[from] ReceivePrekeyOpError),

    #[error(transparent)]
    ReceiveCgkaOpError(#[from] ReceiveCgkaOpError<E>),

    #[error(transparent)]
    ReceiveCertificateError(#[from] ReceiveCertificateError<E>),
}

/// Why a received Keyline certificate was not inserted.
#[derive(Debug, Error)]
pub enum ReceiveCertificateError<E: core::error::Error + 'static> {
    /// It did not decode canonically, or its signature did not verify.
    #[error(transparent)]
    Verify(#[from] VerifyError),

    #[error(transparent)]
    KeylineStorage(#[from] KeylineStorageError<E>),
}

impl<E: core::error::Error + 'static> ReceiveStaticEventError<E> {
    pub fn is_missing_dependency(&self) -> bool {
        match self {
            Self::ReceivePrekeyOpError(_) => false,
            Self::ReceiveCgkaOpError(e) => e.is_missing_dependency(),
            Self::ReceiveCertificateError(_) => false,
        }
    }

    /// Whether the event can never be applied, however long it waits: a bad
    /// signature, or a CGKA operation nothing could authorize. Such
    /// an event is dropped rather than kept pending. A missing dependency, a
    /// missing membership answer or a store failure may resolve, so those are
    /// kept.
    pub fn is_final(&self) -> bool {
        match self {
            Self::ReceivePrekeyOpError(_) => true,
            Self::ReceiveCertificateError(ReceiveCertificateError::Verify(_)) => true,
            Self::ReceiveCertificateError(ReceiveCertificateError::KeylineStorage(_)) => false,
            Self::ReceiveCgkaOpError(e) => match e {
                ReceiveCgkaOpError::VerificationError(_)
                | ReceiveCgkaOpError::UnauthorizedCgkaOp(_) => true,
                ReceiveCgkaOpError::CgkaError(cgka) => never_merges(cgka),
                ReceiveCgkaOpError::UnknownDocument(_)
                | ReceiveCgkaOpError::UnknownInvitePrekey(_)
                | ReceiveCgkaOpError::PendingCgkaAuthorization(_)
                | ReceiveCgkaOpError::KeylineStorage(_) => false,
            },
        }
    }
}

/// Why a causal decryption named by identifier could not be carried out.
///
/// Separate from the other errors because it carries the store's own error type and
/// type parameters.
#[derive(Debug, Error)]
pub enum CausalDecryptError<F: FutureForm, T: ContentRef, P, C: CiphertextStore<F, T, P>> {
    #[error(transparent)]
    NotFound(#[from] NotFound),

    /// Boxed because it is far larger than the other variants
    #[error(transparent)]
    Document(Box<DocCausalDecryptionError<F, T, P, C>>),
}

impl<F: FutureForm, T: ContentRef, P, C: CiphertextStore<F, T, P>>
    From<DocCausalDecryptionError<F, T, P, C>> for CausalDecryptError<F, T, P, C>
{
    fn from(error: DocCausalDecryptionError<F, T, P, C>) -> Self {
        CausalDecryptError::Document(Box::new(error))
    }
}

/// Why an archive could not be loaded.
#[derive(Debug, Error)]
pub enum TryFromArchiveError<E: core::error::Error + 'static> {
    /// The signer's key is not a valid id.
    #[error("the signer's key is not a valid id: {0}")]
    InvalidSigner(#[from] InvalidIdentifier),

    /// A certificate in it did not verify.
    #[error(transparent)]
    Certificate(#[from] VerifyError),

    /// The archive is another identity's: only its own signer can load it.
    #[error("archive of {archive} cannot be loaded with the signer of {signer}")]
    NotTheSigner {
        archive: IndividualId,
        signer: IndividualId,
    },

    #[error(transparent)]
    KeylineStorage(#[from] KeylineStorageError<E>),
}

/// Why generating a group failed.
#[derive(Debug, Error)]
pub enum GenerateGroupError<E: core::error::Error + 'static> {
    #[error(transparent)]
    NotFound(#[from] NotFound),

    #[error(transparent)]
    Certificate(#[from] CertificateError),

    #[error(transparent)]
    KeylineStorage(#[from] KeylineStorageError<E>),
}

/// Every operation in `cgka`'s CGKA graph.
fn cgka_ops_for(cgka: &Cgka<KeylineImplicitRemovesProtocol>) -> Vec<Arc<Verified<CgkaOperation>>> {
    cgka.ops()
        .map(|batches| batches.into_iter().flatten().collect())
        .unwrap_or_default()
}

/// Whether `proof` is a prekey operation, signed by `member`, whose key is `pk`.
fn proves_key(proof: Option<&[u8]>, member: &MemberId, pk: &ShareKey) -> bool {
    proof.and_then(KeyOp::from_key_proof).is_some_and(|key_op| {
        key_op.issuer() == Identifier::from(*member) && key_op.new_key() == pk
    })
}

/// Merge one operation into `cgka`, adopting the secrets `me` has for the
/// keys it provides `me` in the CGKA group. `true` if the CGKA graph did not
/// have it.
///
/// Looks only at `op`, not the CGKA graph, so a merge costs the same however
/// large the graph is. `me`'s earlier keys were adopted when the operations
/// that provided them merged, or when the `Cgka` was rebuilt or secrets were
/// imported ([`adopt_own_cgka_secrets`]).
fn merge_one<E: core::error::Error + 'static>(
    cgka: &mut Cgka<KeylineImplicitRemovesProtocol>,
    op: Arc<Verified<CgkaOperation>>,
    me: IndividualId,
    secrets: &BTreeMap<ShareKey, ShareSecretKey>,
) -> Result<bool, ReceiveCgkaOpError<E>> {
    let keys = own_cgka_keys(&op, me);
    let merged = apply_one(cgka, op, me, secrets)?;
    adopt_cgka_secrets(cgka, keys, secrets);
    Ok(merged)
}

/// The keys `op` gives `me` in the CGKA group: an invitation's prekey, or
/// the keys of `me`'s own update. The only secrets merging `op` can need.
fn own_cgka_keys(op: &Verified<CgkaOperation>, me: IndividualId) -> Vec<ShareKey> {
    match &op.payload().change {
        CgkaChange::Add { added_id, pk, .. } if IndividualId::from(*added_id) == me => {
            vec![*pk]
        }
        CgkaChange::Update { new_path, .. } if IndividualId::from(op.issuer()) == me => {
            vec![new_path.leaf_pk]
        }
        _ => Vec::new(),
    }
}

/// Whether `op` invites `me`: an add of `me`.
fn invites(op: &CgkaOperation, me: IndividualId) -> bool {
    matches!(op.change, CgkaChange::Add { added_id, .. } if IndividualId::from(added_id) == me)
}

/// Merge one operation. An invitation (an add of `me`) is merged with the
/// secret for its prekey, from `secrets`. `true` if the CGKA graph did not
/// have it.
fn apply_one<E: core::error::Error + 'static, M: ImplicitRemovesProtocol>(
    cgka: &mut Cgka<M>,
    op: Arc<Verified<CgkaOperation>>,
    me: IndividualId,
    secrets: &BTreeMap<ShareKey, ShareSecretKey>,
) -> Result<bool, ReceiveCgkaOpError<E>> {
    if let CgkaChange::Add { added_id, pk, .. } = op.payload().change {
        let added = IndividualId::from(added_id);
        if added == me {
            let sk = secrets
                .get(&pk)
                .ok_or(ReceiveCgkaOpError::UnknownInvitePrekey(pk))?;
            return Ok(cgka.merge_invite(op, sk)?);
        }
    }
    Ok(cgka.merge_concurrent_operation(op)?)
}

/// Move into `cgka` every secret `me` holds for a key an operation in the CGKA
/// graph provided `me`: the current one, and those its own updates rotated in.
///
/// Walks the whole CGKA graph, so it is for rebuilding a `Cgka` or after
/// importing secrets, not for each merge ([`merge_one`] looks at the merged
/// operation only).
fn adopt_own_cgka_secrets<M: ImplicitRemovesProtocol>(
    cgka: &mut Cgka<M>,
    me: IndividualId,
    secrets: &BTreeMap<ShareKey, ShareSecretKey>,
) {
    let mut keys: Vec<ShareKey> = cgka.owner_leaf_key().into_iter().collect();
    if let Ok(batches) = cgka.ops() {
        for op in batches.iter().flat_map(|batch| batch.iter()) {
            keys.extend(own_cgka_keys(op, me));
        }
    }
    adopt_cgka_secrets(cgka, keys, secrets);
}

/// Move into `cgka` the secrets in `secrets` for `keys`, where it does
/// not have them yet.
fn adopt_cgka_secrets<M: ImplicitRemovesProtocol, I: IntoIterator<Item = ShareKey>>(
    cgka: &mut Cgka<M>,
    keys: I,
    secrets: &BTreeMap<ShareKey, ShareSecretKey>,
) {
    for pk in keys {
        if !cgka.owner_sks().contains_key(&pk) {
            if let Some(sk) = secrets.get(&pk) {
                cgka.owner_sks_mut().insert(pk, *sk);
            }
        }
    }
}

/// The Keyline store with the lock that serializes inserts into it. They are
/// one value so that whoever shares the store shares the lock: a fork and its
/// trunk.
struct Certificates<K> {
    store: K,

    /// The store version the CGKA graphs of the last keyhive to write reflect,
    /// or `None` before the first insert. Held across every insert and the
    /// CGKA changes that follow it, so a CGKA diff brackets exactly one batch
    /// and one keyhive's concurrent writes reach its CGKA graphs in store
    /// order.
    ///
    /// Also held while receiving a CGKA operation, throughout a write (from
    /// issuing the operations implied for the document through encrypting or
    /// rotating), and in [`Keyhive::add_self_to`], so an operation's citations
    /// are chosen and signed on the same heads, and no operation merges
    /// between a write's reconciliation and the write. A fork
    /// and its trunk share it but not their CGKA graphs (see [`ForkAsync`] for
    /// `Keyhive`). Level 0 in the lock order: nothing takes it while holding
    /// any other lock.
    reconciled: async_lock::Mutex<Option<Version>>,

    /// The certificates CGKA operations cite or may cite, for evaluating them
    /// over their own certificate sets. Every certificate inserted through a
    /// keyhive sharing this store is kept here, so forks and their trunk
    /// agree. A cited certificate missing here is fetched from the store.
    cited: SharedCitations,
}

/// One subject's share of selection: its closure, its live members,
/// and for each principal cut off from it, the certificates that explain
/// that.
struct SubjectView<T: ContentRef> {
    subject: Identifier,
    closure: Vec<Certificate<ContentHeads<T>>>,
    live: BTreeSet<Identifier>,
    cut: Vec<(Identifier, Vec<Certificate<ContentHeads<T>>>)>,
}

/// The identifiers a certificate references: a delegation's issuer, audience and
/// subject, and a revocation's issuer. Read without verifying: the store
/// verified it on insert. A revocation sent to anyone travels with the
/// delegation it revokes (both closures and explanations hold it), so that
/// delegation's audience is referenced too.
fn referenced_by<W, E: core::error::Error + 'static>(
    cert: &Certificate<W>,
) -> Result<Vec<Identifier>, KeylineStorageError<E>> {
    Ok(match cert {
        Certificate::Delegation(signed) => {
            let (issuer, d): (Identifier, Delegation) = decode_stored(signed)?;
            vec![issuer, d.audience, d.subject]
        }
        Certificate::Revocation(signed) => vec![signed.issuer()],
    })
}

/// The individuals a CGKA operation references: its issuer and, for an add, the
/// added member.
fn referenced_by_cgka_op(op: &Verified<CgkaOperation>) -> Vec<Identifier> {
    match &op.payload().change {
        CgkaChange::Add { added_id, .. } => vec![op.issuer(), added_id.id()],
        _ => vec![op.issuer()],
    }
}

#[derive(Debug, Error)]
pub enum ReceiveCgkaOpError<E: core::error::Error + 'static> {
    #[error(transparent)]
    CgkaError(#[from] CgkaError),

    #[error(transparent)]
    VerificationError(#[from] VerifyError),

    #[error("Unknown document recipient for received CGKA op: {0}")]
    UnknownDocument(Box<DocumentId>),

    #[error("Unknown invite prekey for received CGKA add op: {0}")]
    UnknownInvitePrekey(ShareKey),

    /// No certificate or CGKA op received in the future can authorize this op.
    #[error("CGKA op for {0} is not authorized by its certificate sets")]
    UnauthorizedCgkaOp(Box<DocumentId>),

    /// A predecessor or a certificate this op cites has not arrived yet.
    #[error("CGKA op for {0} waits for a predecessor or a certificate it cites")]
    PendingCgkaAuthorization(Box<DocumentId>),

    #[error(transparent)]
    KeylineStorage(#[from] KeylineStorageError<E>),
}

impl<E: core::error::Error + 'static> ReceiveCgkaOpError<E> {
    pub fn is_missing_dependency(&self) -> bool {
        match self {
            Self::CgkaError(e) => e.is_missing_dependency(),
            Self::VerificationError(_) => false,
            // The document's first add, or a prekey secret another instance
            // of this identity holds, may still arrive.
            Self::UnknownDocument(_) => true,
            Self::UnknownInvitePrekey(_) => true,
            Self::UnauthorizedCgkaOp(_) => false,
            Self::PendingCgkaAuthorization(_) => true,
            Self::KeylineStorage(_) => false,
        }
    }
}

/// An error that may say a CGKA lacked a membership answer
/// ([`CgkaError::MembershipUnknown`]).
trait LacksKeylineAnswer {
    /// The cited certificates the CGKA lacked Keyline's answer for.
    fn lacked(&self) -> Option<&BTreeSet<CitationId>>;
}

impl LacksKeylineAnswer for CgkaError {
    fn lacked(&self) -> Option<&BTreeSet<CitationId>> {
        match self {
            CgkaError::MembershipUnknown(cited) => Some(cited),
            _ => None,
        }
    }
}

impl<E: core::error::Error + 'static> LacksKeylineAnswer for ReceiveCgkaOpError<E> {
    fn lacked(&self) -> Option<&BTreeSet<CitationId>> {
        match self {
            ReceiveCgkaOpError::CgkaError(e) => e.lacked(),
            _ => None,
        }
    }
}

/// Whether an operation whose merge failed with `error` is never retried.
/// A missing dependency or membership answer may still arrive. Any other
/// error is taken as final.
fn never_merges(error: &CgkaError) -> bool {
    !error.is_missing_dependency() && error.lacked().is_none()
}

/// A write in progress ([`Keyhive::prepare_to_write`]): the insert lock,
/// held until the write is finished, and the CGKA operations issued for it,
/// for the listener once the lock is released.
struct Writing<'a> {
    reconciled: Reconciled<'a>,
    fresh: Vec<Arc<Verified<CgkaOperation>>>,
}

/// The held insert lock ([`Certificates::reconciled`]). A function that
/// must run under it takes this as an argument.
type Reconciled<'a> = async_lock::MutexGuard<'a, Option<Version>>;

/// Whether all CGKA ops implied by a certificate set were issued.
#[must_use]
enum ImpliedCgkaOpsOutcome {
    /// Every implied operation this replica may sign was issued.
    Success,
    /// A member of the CGKA group lacks `Read` in the queried certificate
    /// set but this replica may not sign the remove.
    RemoveBlocked,
}

/// What the next CGKA operation on a document cites, and what follows.
struct NextCitations {
    /// The certificates it cites.
    cited: BTreeSet<CitationId>,
    /// The readers of the document according to its certificate set.
    readers: BTreeSet<Identifier>,
    /// Whether this replica has `Read` in its signing set, which receivers
    /// require of its signer.
    may_sign: bool,
}

/// Why issuing the CGKA operations a replica's certificates imply for a
/// document, or [`Keyhive::add_self_to`], failed.
#[derive(Debug, Error)]
pub enum CgkaSyncError<E: core::error::Error + 'static> {
    /// The Keyline store failed.
    #[error(transparent)]
    KeylineStorage(#[from] KeylineStorageError<E>),

    /// The CGKA refused an operation or signing one failed.
    #[error(transparent)]
    Cgka(#[from] CgkaError),
}

/// Why [`Keyhive::cgka_op_is_authorized`] denies a CGKA op.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CgkaUnauthorized {
    /// A predecessor or a cited certificate has not arrived yet.
    Pending,

    /// No certificate or CGKA op received in the future can authorize it.
    Denied,
}

#[derive(Debug, Error)]
pub enum EncryptContentError<T: ContentRef> {
    #[error(transparent)]
    NotFound(#[from] NotFound),

    #[error(transparent)]
    EncryptError(#[from] EncryptError),

    #[error("Error signing Cgka op: {0}")]
    SignCgkaOpError(SigningError),

    /// This document has no key for this predecessor because this `Keyhive` has not
    /// written that content or read it.
    #[error("no key for predecessor {0:?}")]
    NoKeyForPredecessor(T),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        certificate::route_through,
        listener::no_listener::NoListener,
        test_utils::{has_remove_citing_its_revocation, Hive},
        transact::transact_async,
    };
    use future_form::Sendable;
    use keyhive_codec::traits::Decode;
    use keyhive_content::store::memory::MemoryCiphertextStore;
    use keyhive_crypto::{signer::memory::MemorySigner, verifiable::Verifiable};
    use keyline::power::Power;
    use keyline_memory::MemoryKeyline;
    use nonempty::nonempty;
    use pretty_assertions::assert_eq;
    use testresult::TestResult;

    type TestKeyhive = Keyhive<
        Sendable,
        MemorySigner,
        [u8; 32],
        Vec<u8>,
        Arc<Mutex<MemoryCiphertextStore<[u8; 32], Vec<u8>>>>,
        NoListener,
        rand::rngs::OsRng,
        MemoryKeyline<ContentHeads<[u8; 32]>>,
    >;

    // `Hive` (in-memory store, no listener, `OsRng`) is a cheap `Dupe`: an O(1)
    // refcount clone. This fails to compile if a field stops being `Dupe`.
    const fn assert_dupe<T: Dupe>() {}
    const _: () = assert_dupe::<Hive>();

    async fn make_keyhive() -> TestKeyhive {
        let sk = MemorySigner::generate(&mut rand::rngs::OsRng);
        let store: MemoryCiphertextStore<[u8; 32], Vec<u8>> = MemoryCiphertextStore::new();
        Keyhive::generate(
            sk,
            Arc::new(Mutex::new(store)),
            NoListener,
            MemoryKeyline::new(),
            rand::rngs::OsRng,
        )
        .await
        .expect("a keyhive generates")
    }

    /// Register a peer keyhive as an individual on `owner` and return its id.
    async fn introduce(owner: &TestKeyhive, peer: &TestKeyhive) -> IndividualId {
        let add_op = peer.expand_prekeys().await.expect("prekeys expand");
        let indie = IndividualState::new(KeyOp::Add(add_op));
        let id = indie.id();
        assert!(owner.register_individual(indie).await);
        id
    }

    /// Keyline's members of `subject`, by Keyhive identifier.
    async fn keyline_members(
        hive: &TestKeyhive,
        subject: impl Into<Identifier>,
    ) -> BTreeMap<Identifier, Power> {
        let subject = subject.into();
        Keyline::<Sendable>::members(hive.keyline(), subject)
            .await
            .expect("the memory store does not fail")
            .value
            .into_iter()
            .collect()
    }

    /// The active identity signs the bytes as they are, and the frame reads
    /// back and verifies as bytes it issued.
    #[tokio::test]
    async fn sign_bytes_signs_as_the_active_identity() -> TestResult {
        let hive = make_keyhive().await;
        let signed = hive.sign_bytes(b"hello".to_vec()).await?;
        assert_eq!(signed.payload().as_slice(), b"hello");
        assert_eq!(signed.issuer(), Identifier::from(hive.id()));

        let frame = signed.signed().encode();
        let read = verified::Signed::<Bytes>::decode(frame.as_bytes())?.verify()?;
        assert_eq!(read.payload(), signed.payload());
        Ok(())
    }

    /// Creating a group or document writes its root edges, and a grant writes
    /// a delegation, and Keyline's members reflect each.
    #[tokio::test]
    async fn writes_produce_certificates() -> TestResult {
        let hive = make_keyhive().await;
        let (bob, carol) = (make_keyhive().await, make_keyhive().await);
        let bob_id: Identifier = introduce(&hive, &bob).await.into();
        let carol_id: Identifier = introduce(&hive, &carol).await.into();
        let me: Identifier = hive.id().into();

        let group_id = hive.generate_group(vec![bob_id]).await?;
        assert_eq!(
            keyline_members(&hive, group_id).await,
            BTreeMap::from([(me, Power::Admin), (bob_id, Power::Admin)]),
            "the group's root edges name both creators"
        );

        let doc_id = hive.generate_doc(vec![], nonempty![[1u8; 32]]).await?;
        assert_eq!(
            keyline_members(&hive, doc_id).await,
            BTreeMap::from([(me, Power::Admin)])
        );

        hive.add_member(carol_id, doc_id, Power::Read).await?;
        hive.add_member(group_id, doc_id, Power::Edit).await?;
        let members = keyline_members(&hive, doc_id).await;
        assert_eq!(members.get(&carol_id), Some(&Power::Read));
        assert_eq!(members.get(&Identifier::from(group_id)), Some(&Power::Edit));
        assert_eq!(
            members.get(&bob_id),
            Some(&Power::Edit),
            "membership composes through the group"
        );
        Ok(())
    }

    /// A revocation records the content heads of the documents whose readers
    /// it can change: those the resource is or stands over, and no others.
    #[tokio::test]
    async fn revocations_retain_the_heads_they_bound() -> TestResult {
        let hive = make_keyhive().await;
        let bob = make_keyhive().await;
        let bob_id: Identifier = introduce(&hive, &bob).await.into();

        let group_id = hive.generate_group(vec![]).await?;
        let shared = hive.generate_doc(vec![], nonempty![[1u8; 32]]).await?;
        let unrelated = hive.generate_doc(vec![], nonempty![[2u8; 32]]).await?;
        hive.add_member(group_id, shared, Power::Read).await?;
        hive.add_member(bob_id, group_id, Power::Read).await?;
        hive.add_member(bob_id, unrelated, Power::Read).await?;

        let heads = |h: [u8; 32]| ContentHeads::from_iter([h]);
        let from_group = hive.revoke_member(bob_id, false, group_id).await?;
        assert_eq!(
            from_group.revocations()[0].payload().retain,
            BTreeMap::from([(Identifier::from(shared), heads([1u8; 32]))]),
        );
        let from_doc = hive.revoke_member(bob_id, false, unrelated).await?;
        assert_eq!(
            from_doc.revocations()[0].payload().retain,
            BTreeMap::from([(Identifier::from(unrelated), heads([2u8; 32]))]),
        );
        Ok(())
    }

    /// Send `to` the events `from` would send it, optionally without prekey
    /// operations, and ingest them.
    async fn send(from: &TestKeyhive, to: &TestKeyhive, with_prekeys: bool) -> TestResult {
        let events: Vec<_> = from
            .static_events_for_agent(to.id())
            .await?
            .into_values()
            .filter(|event| {
                with_prekeys
                    || !matches!(
                        event,
                        StaticEvent::PrekeysExpanded(_) | StaticEvent::PrekeyRotated(_)
                    )
            })
            .collect();
        to.ingest_unsorted_static_events(events).await;
        Ok(())
    }

    #[tokio::test]
    async fn certificate_sets_evicted_from_long_concurrent_branches_are_rebuilt_unchanged(
    ) -> TestResult {
        let (owner, bob, carol) = (
            make_keyhive().await,
            make_keyhive().await,
            make_keyhive().await,
        );
        let bob_id = introduce(&owner, &bob).await;
        let carol_id = introduce(&owner, &carol).await;
        let doc = owner.generate_doc(vec![], nonempty![[1u8; 32]]).await?;
        owner.add_member(bob_id, doc, Power::Read).await?;
        send(&owner, &bob, true).await?;
        for i in 0..6 {
            if i == 3 {
                owner.add_member(carol_id, doc, Power::Read).await?;
            }
            owner.force_pcs_update(doc).await?;
            bob.force_pcs_update(doc).await?;
        }
        send(&bob, &owner, false).await?;
        owner.force_pcs_update(doc).await?;

        let state = owner
            .document_state(doc)
            .await
            .ok_or("has not joined the CGKA group")?;
        let locked = state.lock().await;
        let cgka = locked.cgka();
        let heads: Vec<_> = cgka.heads().iter().collect();
        let [merge] = heads[..] else {
            return Err("the last update merges both branches".into());
        };
        let predecessors = cgka
            .op(merge)
            .ok_or("the CGKA graph lacks its head")?
            .payload()
            .predecessors()
            .into_iter()
            .collect::<Vec<_>>();
        let [left, right] = predecessors[..] else {
            return Err("the last update merges both branches".into());
        };
        assert_ne!(
            CertificateSets::new().predecessor_set(cgka, [&left]),
            CertificateSets::new().predecessor_set(cgka, [&right]),
            "the branches cite the same certificates"
        );
        let ops: Vec<Digest<CgkaOperation>> = cgka
            .ops()?
            .iter()
            .flat_map(|batch| batch.iter().map(|op| op.digest()))
            .collect();

        // Fewer sets kept than either branch has operations.
        let mut sets = CertificateSets::retaining(4, 1024);
        sets.predecessor_set(cgka, [merge])
            .ok_or("the CGKA graph lacks an op")?;
        for op in &ops {
            assert_eq!(
                sets.predecessor_set(cgka, [op]),
                CertificateSets::new().predecessor_set(cgka, [op]),
                "{op}"
            );
        }
        Ok(())
    }

    /// A lost reader is removed from the CGKA group even when this replica
    /// never received their prekeys: a removal does not need them.
    #[tokio::test]
    async fn a_lost_reader_is_removed_without_their_prekeys() -> TestResult {
        let (owner, alice, bob) = (
            make_keyhive().await,
            make_keyhive().await,
            make_keyhive().await,
        );
        let alice_id = introduce(&owner, &alice).await;
        introduce(&alice, &owner).await;
        let bob_id = introduce(&alice, &bob).await;
        let doc = owner.generate_doc(vec![], nonempty![[1u8; 32]]).await?;
        owner.add_member(alice_id, doc, Power::Admin).await?;
        send(&owner, &alice, true).await?;
        alice.add_member(bob_id, doc, Power::Read).await?;
        send(&alice, &owner, false).await?;

        let members = |hive: &TestKeyhive| {
            let hive = hive.clone();
            async move {
                hive.cgka_members_for(doc)
                    .await
                    .expect("knows the document")
                    .expect("has joined the CGKA group")
            }
        };
        assert!(members(&owner).await.contains(&bob_id), "alice added bob");
        assert!(
            !owner.has_individual(bob_id).await,
            "owner has no prekeys for bob"
        );

        let update = owner.revoke_member(alice_id, false, doc).await?;
        assert!(has_remove_citing_its_revocation(&update));
        assert!(!members(&owner).await.contains(&bob_id));
        Ok(())
    }

    #[tokio::test]
    async fn revoking_a_reader_who_is_not_a_cgka_member_issues_no_remove() -> TestResult {
        let hive = make_keyhive().await;
        let group_id = hive.generate_group(vec![]).await?;
        let doc = hive.generate_doc(vec![], nonempty![[1u8; 32]]).await?;
        hive.add_member(group_id, doc, Power::Read).await?;

        let update = hive.revoke_member(group_id, false, doc).await?;
        assert!(!update
            .cgka_ops()
            .iter()
            .any(|op| matches!(op.payload().change, CgkaChange::Remove { .. })));
        Ok(())
    }

    /// A revoked member is sent what explains its removal, and nothing about
    /// the subject that comes after: not later members, not their prekeys.
    #[tokio::test]
    async fn a_revoked_member_learns_of_its_removal_and_nothing_after() -> TestResult {
        let alice = make_keyhive().await;
        let (bob, carol) = (make_keyhive().await, make_keyhive().await);
        let bob_id = introduce(&alice, &bob).await;
        let carol_id = introduce(&alice, &carol).await;
        let doc = alice.generate_doc(vec![], nonempty![[1u8; 32]]).await?;
        alice.add_member(bob_id, doc, Power::Read).await?;
        let revoked = alice.revoke_member(bob_id, false, doc).await?;
        let carols = alice.add_member(carol_id, doc, Power::Read).await?;

        let sent: BTreeSet<CertificateId> = alice
            .certificates_for_agent(bob_id.into())
            .await?
            .iter()
            .map(Certificate::id)
            .collect();
        let revocation = VerifiedCertificate::Revocation(revoked.revocations()[0].dupe()).id();
        let grant =
            VerifiedCertificate::<ContentHeads<[u8; 32]>>::Delegation(carols.delegation.dupe())
                .id();
        assert!(sent.contains(&revocation), "bob is sent his revocation");
        assert!(!sent.contains(&grant), "bob is not sent carol's grant");

        let prekeys = alice.reachable_prekey_ops_for_agent(bob_id).await?;
        assert!(
            prekeys.get(&Identifier::from(carol_id)).is_none(),
            "bob is not sent carol's prekeys"
        );
        Ok(())
    }

    /// A replica that knows no heads for a document leaves it out of the
    /// watermark, rather than recording an empty set, which would read as
    /// "keep none of its content".
    #[tokio::test]
    async fn a_revocation_omits_documents_whose_heads_are_unknown() -> TestResult {
        let (alice, bob, carol) = (
            make_keyhive().await,
            make_keyhive().await,
            make_keyhive().await,
        );
        let bob_id = introduce(&alice, &bob).await;
        introduce(&bob, &alice).await;
        let carol_id = introduce(&bob, &carol).await;
        let doc = alice.generate_doc(vec![], nonempty![[1u8; 32]]).await?;
        alice.add_member(bob_id, doc, Power::Admin).await?;
        send(&alice, &bob, true).await?;

        bob.add_member(carol_id, doc, Power::Read).await?;
        let update = bob.revoke_member(carol_id, false, doc).await?;
        assert!(
            update.revocations()[0].payload().retain.is_empty(),
            "bob, invited, knows no heads for the document"
        );
        Ok(())
    }

    /// An event that can never apply is dropped, not kept pending, so a peer
    /// cannot grow the pending list with forgeries.
    #[tokio::test]
    async fn an_event_that_can_never_apply_is_not_kept_pending() -> TestResult {
        let alice = make_keyhive().await;
        let carol = make_keyhive().await;
        alice.generate_doc(vec![], nonempty![[1u8; 32]]).await?;
        let certs = Keyline::<Sendable>::certificates(alice.keyline())
            .await?
            .value;
        let mut bytes = Encode::encode(&certs[0]).into_bytes();
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        let tampered: Certificate<ContentHeads<[u8; 32]>> = Decode::decode(&bytes)?;

        let stuck = carol
            .ingest_unsorted_static_events(vec![StaticEvent::from(Event::from(tampered))])
            .await;
        assert!(stuck.is_empty(), "nothing is left waiting");
        assert!(carol.pending_event_hashes().await.is_empty());
        Ok(())
    }

    /// A revocation records the heads the application last set for each
    /// document, including on a replica that was invited and so started with
    /// none. A document whose CGKA group this replica has not joined is
    /// refused.
    #[tokio::test]
    async fn revocations_retain_the_heads_the_application_sets() -> TestResult {
        let (alice, bob, carol) = (
            make_keyhive().await,
            make_keyhive().await,
            make_keyhive().await,
        );
        let bob_id = introduce(&alice, &bob).await;
        introduce(&bob, &alice).await;
        let carol_id = introduce(&bob, &carol).await;
        let doc = alice.generate_doc(vec![], nonempty![[1u8; 32]]).await?;
        alice.add_member(bob_id, doc, Power::Admin).await?;
        send(&alice, &bob, true).await?;

        let doc_kl = Identifier::from(doc);
        let heads = [[7u8; 32], [8u8; 32]];
        bob.set_content_heads(doc, heads).await?;
        bob.add_member(carol_id, doc, Power::Read).await?;
        let update = bob.revoke_member(carol_id, false, doc).await?;
        assert_eq!(
            update.revocations()[0].payload().retain,
            BTreeMap::from([(doc_kl, ContentHeads::from_iter(heads))]),
        );

        let unknown = make_keyhive().await;
        assert!(unknown.set_content_heads(doc, heads).await.is_err());
        Ok(())
    }

    /// Revoking a member revokes every Keyline delegation to them.
    #[tokio::test]
    async fn revocation_writes_revocations() -> TestResult {
        let hive = make_keyhive().await;
        let bob = make_keyhive().await;
        let bob_id: Identifier = introduce(&hive, &bob).await.into();
        let doc_id = hive.generate_doc(vec![], nonempty![[1u8; 32]]).await?;

        hive.add_member(bob_id, doc_id, Power::Read).await?;
        assert!(keyline_members(&hive, doc_id).await.contains_key(&bob_id));

        hive.revoke_member(bob_id, true, doc_id).await?;
        assert!(!keyline_members(&hive, doc_id).await.contains_key(&bob_id));

        let subject = Identifier::from(doc_id);
        let to_bob = Keyline::<Sendable>::delegations_to(hive.keyline(), subject, bob_id)
            .await?
            .value;
        assert_eq!(to_bob.len(), 1);
        for digest in to_bob.keys() {
            assert!(
                !Keyline::<Sendable>::is_live(hive.keyline(), *digest)
                    .await?
                    .value
            );
            let revocations = Keyline::<Sendable>::revocations_of(hive.keyline(), *digest)
                .await?
                .value;
            assert_eq!(revocations.len(), 1);
        }
        Ok(())
    }

    /// Certificates travel as events: a replica that receives them answers as
    /// the writer does, duplicates change nothing, and a tampered certificate
    /// is refused.
    #[tokio::test]
    async fn received_certificates_converge() -> TestResult {
        let alice = make_keyhive().await;
        let bob = make_keyhive().await;
        let bob_id: Identifier = introduce(&alice, &bob).await.into();
        let doc_id = alice.generate_doc(vec![], nonempty![[1u8; 32]]).await?;
        alice.add_member(bob_id, doc_id, Power::Read).await?;

        let certs = Keyline::<Sendable>::certificates(alice.keyline())
            .await?
            .value;
        assert_eq!(certs.len(), 2, "the root edge and the grant");
        for cert in certs.iter().chain(&certs) {
            bob.receive_static_event(StaticEvent::from(Event::from(cert.clone())))
                .await?;
        }
        assert_eq!(
            keyline_members(&bob, doc_id).await,
            keyline_members(&alice, doc_id).await
        );
        assert_eq!(
            Keyline::<Sendable>::digest(bob.keyline()).await?.value,
            Keyline::<Sendable>::digest(alice.keyline()).await?.value
        );

        let mut bytes = Encode::encode(&certs[0]).into_bytes();
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        let tampered: Certificate<ContentHeads<[u8; 32]>> = Decode::decode(&bytes)?;
        let carol = make_keyhive().await;
        assert!(matches!(
            carol
                .receive_static_event(StaticEvent::from(Event::from(tampered)))
                .await,
            Err(ReceiveStaticEventError::ReceiveCertificateError(
                ReceiveCertificateError::Verify(_)
            ))
        ));
        Ok(())
    }

    /// Revoking with `retain_all_other_members` adopts: the members the
    /// revoked member admitted keep their access, re-issued by the revoker.
    /// Without it the revocation cascades and they lose it too.
    #[tokio::test]
    async fn revocation_adopts_when_asked() -> TestResult {
        for adopt in [true, false] {
            let alice = make_keyhive().await;
            let bob = make_keyhive().await;
            let carol = make_keyhive().await;
            let bob_id: Identifier = introduce(&alice, &bob).await.into();
            let carol_id: Identifier = introduce(&alice, &carol).await.into();
            introduce(&bob, &carol).await;
            let group_id = alice.generate_group(vec![]).await?;
            alice.add_member(bob_id, group_id, Power::Admin).await?;

            // Bob admits Carol, from his own replica.
            for cert in Keyline::<Sendable>::certificates(alice.keyline())
                .await?
                .value
            {
                bob.receive_certificate(cert).await?;
            }
            let carol_by_bob = Delegation::new(carol_id, Identifier::from(group_id), Power::Read);
            let signed = bob.sign_certificate(&carol_by_bob).await?;
            alice
                .receive_certificate(VerifiedCertificate::from(signed).into_certificate())
                .await?;
            assert_eq!(
                keyline_members(&alice, group_id).await.get(&carol_id),
                Some(&Power::Read)
            );

            alice.revoke_member(bob_id, adopt, group_id).await?;
            let members = keyline_members(&alice, group_id).await;
            assert!(!members.contains_key(&bob_id), "Bob is out either way");
            assert_eq!(
                members.get(&carol_id).copied(),
                adopt.then_some(Power::Read),
                "Carol stays only with adoption"
            );
        }
        Ok(())
    }

    /// Once a CGKA operation is authorized, no later insert unauthorizes it:
    /// the rules read only the operation's own certificate sets, which later
    /// certificates do not change. Revoking the member it added changes
    /// nothing.
    #[tokio::test]
    async fn cgka_authorization_is_monotone() -> TestResult {
        let alice = make_keyhive().await;
        let (bob, carol) = (make_keyhive().await, make_keyhive().await);
        let bob_id: Identifier = introduce(&alice, &bob).await.into();
        let carol_id: Identifier = introduce(&alice, &carol).await.into();
        let doc_id = alice.generate_doc(vec![], nonempty![[1u8; 32]]).await?;
        alice.add_member(bob_id, doc_id, Power::Read).await?;

        let ops = alice
            .cgka_ops_for_doc(&doc_id)
            .await
            .ok_or("this replica has joined the document's CGKA group")?;
        assert!(!ops.is_empty());
        for op in &ops {
            assert_eq!(alice.cgka_op_is_authorized(op, doc_id).await?, Ok(()));
        }

        alice.add_member(carol_id, doc_id, Power::Edit).await?;
        alice.revoke_member(bob_id, false, doc_id).await?;
        alice.revoke_member(carol_id, true, doc_id).await?;
        for op in &ops {
            assert_eq!(
                alice.cgka_op_is_authorized(op, doc_id).await?,
                Ok(()),
                "an authorized operation stays authorized"
            );
        }
        Ok(())
    }

    /// `route_through` covers both cascades a revocation causes: members of
    /// the revoked delegation's audience, and audiences of delegations that
    /// audience issued. It does not invent routes through other delegations.
    #[tokio::test]
    async fn route_through_covers_both_cascades() -> TestResult {
        let alice = make_keyhive().await;
        let (bob, carol, group, dave) = (
            make_keyhive().await,
            make_keyhive().await,
            make_keyhive().await,
            make_keyhive().await,
        );
        let id = |kh: &TestKeyhive| Identifier::from(kh.id());
        let doc_id = alice.generate_doc(vec![], nonempty![[1u8; 32]]).await?;
        let doc = Identifier::from(doc_id);

        let to_bob = Delegation::new(id(&bob), doc, Power::Admin);
        let bob_to_carol = Delegation::new(id(&carol), doc, Power::Read);
        let to_group = Delegation::new(id(&group), doc, Power::Read);
        let dave_in_group = Delegation::new(id(&dave), id(&group), Power::Read);
        for (signer, d) in [
            (&alice, &to_bob),
            (&bob, &bob_to_carol),
            (&alice, &to_group),
            (&group, &dave_in_group),
        ] {
            let signed = signer.sign_certificate(d).await?;
            alice
                .receive_certificate(VerifiedCertificate::from(signed).into_certificate())
                .await?;
        }

        assert!(
            route_through::<Sendable, _>(alice.keyline(), doc, id(&alice), &to_bob, id(&bob))
                .await?,
            "the audience"
        );
        assert!(
            route_through::<Sendable, _>(alice.keyline(), doc, id(&alice), &to_bob, id(&carol))
                .await?,
            "someone the audience admitted"
        );
        assert!(
            route_through::<Sendable, _>(alice.keyline(), doc, id(&alice), &to_group, id(&dave))
                .await?,
            "a member of the audience"
        );
        assert!(
            !route_through::<Sendable, _>(alice.keyline(), doc, id(&alice), &to_bob, id(&dave))
                .await?,
            "Dave's route does not pass through the grant to Bob"
        );
        assert!(
            !route_through::<Sendable, _>(alice.keyline(), doc, id(&alice), &to_group, id(&carol))
                .await?,
            "nor Carol's through the grant to the group"
        );
        Ok(())
    }

    /// An archive carries the certificate set: loading it into an empty store
    /// gives the same set and the same answers.
    #[tokio::test]
    async fn archives_carry_certificates() -> TestResult {
        let hive = make_keyhive().await;
        let bob = make_keyhive().await;
        let bob_id: Identifier = introduce(&hive, &bob).await.into();
        let doc_id = hive.generate_doc(vec![], nonempty![[1u8; 32]]).await?;
        hive.add_member(bob_id, doc_id, Power::Read).await?;

        let signer = hive.active.signer.clone();
        let loaded: TestKeyhive = Keyhive::try_from_archive(
            &hive.into_archive().await?,
            signer,
            Arc::new(Mutex::new(MemoryCiphertextStore::new())),
            NoListener,
            MemoryKeyline::new(),
            Arc::new(Mutex::new(rand::rngs::OsRng)),
        )
        .await?;

        assert_eq!(
            Keyline::<Sendable>::digest(loaded.keyline()).await?.value,
            Keyline::<Sendable>::digest(hive.keyline()).await?.value
        );
        assert_eq!(
            keyline_members(&loaded, doc_id).await,
            keyline_members(&hive, doc_id).await
        );
        Ok(())
    }

    #[tokio::test]
    async fn an_archived_operation_built_on_one_awaiting_a_certificate_waits_with_it() -> TestResult
    {
        let hive = make_keyhive().await;
        let bob = make_keyhive().await;
        let bob_id = introduce(&hive, &bob).await;
        let doc_id = hive.generate_doc(vec![], nonempty![[1u8; 32]]).await?;
        hive.add_member(Identifier::from(bob_id), doc_id, Power::Read)
            .await?;
        hive.force_pcs_update(doc_id).await?;

        let mut archive = hive.into_archive().await?;
        let bob_member = beekem::id::MemberId::from(bob_id);
        let ops = archive
            .cgka_ops
            .iter()
            .map(|op| op.clone().verify())
            .collect::<Result<Vec<_>, _>>()?;
        let add_of_bob = ops
            .iter()
            .find(|op| matches!(op.payload().change, CgkaChange::Add { added_id, .. } if added_id == bob_member))
            .ok_or("bob was added")?;
        let cited: BTreeSet<CitationId> =
            add_of_bob.payload().citations().iter().copied().collect();
        let update = ops
            .iter()
            .find(|op| op.payload().predecessors.contains(&add_of_bob.digest()))
            .ok_or("an update follows the add of bob")?
            .digest();
        archive
            .certificates
            .retain(|cert| !cited.contains(&citation_of(cert.id())));

        let signer = hive.active.signer.clone();
        let loaded: TestKeyhive = Keyhive::try_from_archive(
            &archive,
            signer,
            Arc::new(Mutex::new(MemoryCiphertextStore::new())),
            NoListener,
            MemoryKeyline::new(),
            Arc::new(Mutex::new(rand::rngs::OsRng)),
        )
        .await?;

        let pending = loaded.pending_events.lock().await;
        assert!(
            pending.iter().any(
                |event| matches!(event.as_ref(), StaticEvent::CgkaOperation(op) if op.digest() == update)
            ),
            "the update built on the add of bob was discarded"
        );
        Ok(())
    }

    #[tokio::test]
    async fn membership_predicates_consult_correct_registry() -> TestResult {
        let hive = make_keyhive().await;
        let peer = make_keyhive().await;
        let indie_id = introduce(&hive, &peer).await;
        let group_id = hive.generate_group(vec![indie_id.into()]).await?;

        assert!(hive.has_group(group_id).await?);
        let indie_id_from_group_id = IndividualId::new(group_id.into());
        assert!(!hive.has_individual(indie_id_from_group_id).await);

        assert!(hive.has_individual(indie_id).await);
        let group_id_from_indie_id = GroupId::new(indie_id.into());
        assert!(!hive.has_group(group_id_from_indie_id).await?);

        Ok(())
    }

    #[tokio::test]
    async fn test_archival_round_trip() -> TestResult {
        test_utils::init_logging();

        let mut csprng = rand::rngs::OsRng;

        let sk = MemorySigner::generate(&mut csprng);
        let store = Arc::new(Mutex::new(MemoryCiphertextStore::<[u8; 32], String>::new()));
        let hive: Keyhive<Sendable, MemorySigner, [u8; 32], String, _, NoListener, _, _> =
            Keyhive::generate(
                sk.clone(),
                store.clone(),
                NoListener,
                MemoryKeyline::new(),
                rand::rngs::OsRng,
            )
            .await?;

        let indie_sk = MemorySigner::generate(&mut csprng);
        let indie = IndividualState::generate::<Sendable, _, _>(&indie_sk, &mut csprng).await?;
        let indie_id = indie.id();

        hive.register_individual(indie.clone()).await;
        hive.generate_group(vec![indie_id.into()]).await?;
        hive.generate_doc(vec![indie_id.into()], nonempty![[1u8; 32], [2u8; 32]])
            .await?;

        assert!(!hive.active.key_pairs.lock().await.is_empty());
        assert_eq!(
            hive.individuals.lock().await.len(),
            2,
            "the active individual and indie"
        );
        assert_eq!(hive.stats().await.groups, 1);
        assert_eq!(hive.documents.lock().await.len(), 1);
        assert_eq!(hive.stats().await.delegations, 4, "the root edges");
        assert_eq!(hive.stats().await.revocations, 0);

        let archive = hive.into_archive().await?;

        assert_eq!(hive.id(), archive.id());
        assert_eq!(archive.individuals.len(), 2);
        assert_eq!(archive.docs.len(), 1);
        assert_eq!(
            archive.certificates.len(),
            4,
            "the group's and the document's root edges, to the creator and to the individual"
        );
        assert_eq!(
            archive.cgka_ops.len(),
            3,
            "the document's adds of its two founders, and the creator's update"
        );

        let hive_from_archive: Keyhive<
            Sendable,
            MemorySigner,
            [u8; 32],
            String,
            _,
            NoListener,
            _,
            _,
        > = Keyhive::try_from_archive(
            &archive,
            sk,
            store,
            NoListener,
            MemoryKeyline::new(),
            Arc::new(Mutex::new(rand::rngs::OsRng)),
        )
        .await
        .unwrap();

        assert_eq!(
            hive.individuals.lock().await.len(),
            hive_from_archive.individuals.lock().await.len()
        );
        assert_eq!(
            hive.documents.lock().await.len(),
            hive_from_archive.documents.lock().await.len()
        );
        assert_eq!(
            Keyline::<Sendable>::digest(hive_from_archive.keyline())
                .await?
                .value,
            Keyline::<Sendable>::digest(hive.keyline()).await?.value,
            "the certificate set round-trips"
        );
        assert_eq!(
            hive_from_archive.stats().await.cgka_operations,
            hive.stats().await.cgka_operations,
            "and so do the CGKA operations"
        );
        let pcs_hash = |h: &Arc<Mutex<DocumentState<_>>>| {
            let h = h.dupe();
            async move { h.lock().await.cgka_mut().try_pcs_key_hash() }
        };
        let doc_id = *hive
            .documents
            .lock()
            .await
            .keys()
            .next()
            .expect("one document");
        let original = hive.document_state(doc_id).await.expect("held");
        let rebuilt = hive_from_archive
            .document_state(doc_id)
            .await
            .expect("held");
        assert_eq!(
            pcs_hash(&rebuilt).await?,
            pcs_hash(&original).await?,
            "the CGKA group rebuilt from the operations derives the same key"
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_loading_archive_after_revoking_delegation() -> TestResult {
        test_utils::init_logging();

        let mut csprng = rand::rngs::OsRng;
        let sk = MemorySigner::generate(&mut csprng);
        let store = Arc::new(Mutex::new(MemoryCiphertextStore::<[u8; 32], String>::new()));
        let kh: Keyhive<Sendable, MemorySigner, [u8; 32], String, _, NoListener, _, _> =
            Keyhive::generate(
                sk.clone(),
                store.clone(),
                NoListener,
                MemoryKeyline::new(),
                rand::rngs::OsRng,
            )
            .await?;

        let indie_sk = MemorySigner::generate(&mut csprng);
        let indie = IndividualState::generate::<Sendable, _, _>(&indie_sk, &mut csprng).await?;
        kh.register_individual(indie.clone()).await;
        let doc_id = kh.generate_doc(vec![], nonempty![[1u8; 32]]).await?;

        // Delegate to an individual and then revoke
        let indie_id = indie.id();
        kh.add_member(indie_id, doc_id, Power::Edit).await?;
        kh.revoke_member(indie_id, true, doc_id).await?;

        // Create an archive and try to load it into a fresh Keyhive
        let archive = kh.into_archive().await?;
        let kh2: Keyhive<Sendable, MemorySigner, [u8; 32], String, _, NoListener, _, _> =
            Keyhive::try_from_archive(
                &archive,
                sk,
                Arc::new(Mutex::new(MemoryCiphertextStore::<[u8; 32], String>::new())),
                NoListener,
                MemoryKeyline::new(),
                Arc::new(Mutex::new(rand::rngs::OsRng)),
            )
            .await?;

        assert_eq!(
            kh2.verifying_key(),
            archive.active.individual.verifying_key()
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_transitive_ops_for_agent() -> TestResult {
        test_utils::init_logging();

        let left = make_keyhive().await;
        let middle = make_keyhive().await;
        let right = make_keyhive().await;
        // Middle reads the document; Right only relays it.
        let reader_card = middle.get_existing_contact_card().await;
        let reader = Identifier::from(left.receive_contact_card(&reader_card).await?);
        right.receive_contact_card(&reader_card).await?;

        // Two root edges: to Left and to the reader.
        let left_doc = left
            .generate_doc(vec![reader], nonempty![[0u8; 32]])
            .await?;
        // One root edge: to Left.
        let left_group_id = left.generate_group(vec![]).await?;

        let left_membered = left.membered_reachable_by_agent(reader).await?;
        assert_eq!(left_membered.len(), 1);
        assert!(left_membered.contains_key(&left_doc.into()));
        assert!(
            !left_membered.contains_key(&left_group_id.into()),
            "the reader is not a member of the group"
        );

        let delegations = |ops: &HashMap<_, Event<[u8; 32]>>| {
            ops.values()
                .filter(|e| matches!(e, Event::Delegated(_)))
                .count()
        };

        // The reader is sent the document's closure, and nothing of the group.
        let left_to_mid_ops = left.events_for_agent(reader).await?;
        assert_eq!(delegations(&left_to_mid_ops), 2);
        middle.ingest_event_table(left_to_mid_ops).await?;

        assert!(
            middle.documents.lock().await.contains_key(&left_doc),
            "the document's key agreement makes it known"
        );
        assert_eq!(
            middle.reachable_members(left_doc).await?,
            left.reachable_members(left_doc).await?,
            "Middle agrees with Left on the document"
        );
        assert!(middle.reachable_members(left_group_id).await?.is_empty());

        // Middle forwards what it received.
        let mid_to_right_ops = middle.events_for_agent(reader).await?;
        assert_eq!(delegations(&mid_to_right_ops), 2);
        right.ingest_event_table(mid_to_right_ops).await?;
        assert_eq!(
            right.reachable_members(left_doc).await?,
            left.reachable_members(left_doc).await?,
            "Right agrees too"
        );

        // The reader reaches Right's new group through the document it names as a
        // creator, so it gets the group's closure: both root edges of the
        // group (to Right and to the document) and both of the document.
        let right_group = right.generate_group(vec![left_doc.into()]).await?;
        let transitive_ops = right.events_for_agent(reader).await?;
        assert_eq!(delegations(&transitive_ops), 4);
        middle.ingest_event_table(transitive_ops).await?;
        assert_eq!(
            middle.reachable_members(right_group).await?,
            right.reachable_members(right_group).await?,
            "Middle learns the group from its certificates"
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_add_member() {
        test_utils::init_logging();

        let keyhive = make_keyhive().await;
        let reader_card = make_keyhive().await.get_existing_contact_card().await;
        let reader = keyhive
            .receive_contact_card(&reader_card)
            .await
            .expect("a fresh contact card is valid");
        let doc = keyhive
            .generate_doc(vec![], nonempty![[0u8; 32]])
            .await
            .unwrap();
        let dlg = keyhive.add_member(reader, doc, Power::Read).await.unwrap();

        assert_eq!(dlg.delegation.payload().subject, doc.into());
    }

    #[tokio::test]
    async fn test_peer_sees_other_peer_access_via_group() {
        test_utils::init_logging();

        // Create a keyhive and a doc
        let hive1 = make_keyhive().await;
        let group_id = hive1.generate_group(vec![]).await.unwrap();
        let doc = hive1
            .generate_doc(vec![group_id.into()], nonempty![[0u8; 32]])
            .await
            .unwrap();

        // Create two more keyhives
        let hive2 = make_keyhive().await;
        let hive2_on_hive1_id = introduce(&hive1, &hive2).await;

        let hive3 = make_keyhive().await;
        let hive3_on_hive1_id = introduce(&hive1, &hive3).await;

        // Add hive2 as a member of the doc
        hive1
            .add_member(hive2_on_hive1_id, doc, Power::Edit)
            .await
            .unwrap();

        // Add hive3 as a member of the group that was parent of the doc
        hive1
            .add_member(hive3_on_hive1_id, group_id, Power::Read)
            .await
            .unwrap();

        // Verify hive1 can see hive3's access to the doc
        let hive1_members = hive1
            .reachable_members(doc)
            .await
            .expect("hive1's store answers");
        assert!(
            hive1_members.contains_key(&hive3_on_hive1_id.into()),
            "hive1 should see hive3's access to the doc"
        );

        // Register hive3 with hive2
        let hive3_on_hive2_id = introduce(&hive2, &hive3).await;

        // Send keyhive events from hive1 to hive2
        let events_for_hive2_from_hive1 = hive1
            .events_for_agent(hive2_on_hive1_id)
            .await
            .expect("selects events");
        hive2
            .ingest_event_table(events_for_hive2_from_hive1)
            .await
            .unwrap();

        // Now verify hive2 can see hive3's access to the doc
        let members = hive2
            .reachable_members(doc)
            .await
            .expect("hive2's store answers");
        assert!(
            members.contains_key(&hive3_on_hive2_id.into()),
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
        let bob_on_alice = IndividualState::new(add_op.dupe());
        assert!(alice.register_individual(bob_on_alice.clone()).await);
        let bob_on_alice_id = bob_on_alice.id();
        alice
            .add_member(bob_on_alice_id, doc, Power::Read)
            .await
            .unwrap();

        // Now receive alices events
        let events = alice
            .events_for_agent(bob_on_alice_id)
            .await
            .expect("selects events");

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
        let bob_on_charlie = IndividualState::new(KeyOp::Rotate(rotate_op));
        assert!(charlie.register_individual(bob_on_charlie.clone()).await);
        let bob_on_charlie_id = bob_on_charlie.id();
        charlie
            .add_member(bob_on_charlie_id, doc2, Power::Read)
            .await
            .unwrap();

        let events = charlie
            .events_for_agent(bob_on_charlie_id)
            .await
            .expect("selects events");

        bob.ingest_event_table(events).await.unwrap();
    }

    #[tokio::test]
    async fn prekey_rotations_received_after_a_delegation_are_all_reachable() {
        test_utils::init_logging();

        let alice = make_keyhive().await;
        let bob = make_keyhive().await;

        let bob_add_op = bob.expand_prekeys().await.unwrap();
        let bob_rotate_op1 = bob
            .rotate_prekey(bob_add_op.payload().share_key)
            .await
            .unwrap();
        let bob_rotate_op2 = bob
            .rotate_prekey(bob_rotate_op1.payload().new)
            .await
            .unwrap();

        let bob_on_alice_for_delegation = IndividualState::new(KeyOp::Add(bob_add_op.clone()));
        assert!(
            alice
                .register_individual(bob_on_alice_for_delegation.clone())
                .await
        );
        let bob_id = bob_on_alice_for_delegation.id();

        let doc = alice
            .generate_doc(vec![], nonempty![[0u8; 32]])
            .await
            .unwrap();
        alice.add_member(bob_id, doc, Power::Read).await.unwrap();

        // Alice learns about the rotations the way she would in practice, by receiving the ops.
        alice
            .receive_prekey_op(&KeyOp::Rotate(bob_rotate_op1))
            .await
            .unwrap();
        alice
            .receive_prekey_op(&KeyOp::Rotate(bob_rotate_op2))
            .await
            .unwrap();

        let prekey_ops = alice
            .reachable_prekey_ops_for_agent(bob_id)
            .await
            .expect("selects events");

        let bob_prekeys = prekey_ops
            .get(&bob_id.into())
            .expect("bob's prekeys are reachable");
        assert_eq!(
            bob_prekeys.len(),
            3,
            "the add and both rotations are reachable"
        );
    }

    /// Test that reachable_prekey_ops_for_all_agents matches
    /// reachable_prekey_ops_for_agent for each agent.
    #[tokio::test]
    async fn test_reachable_prekey_ops_for_all_agents_matches_per_agent() -> TestResult {
        test_utils::init_logging();

        let alice = make_keyhive().await;
        let bob = make_keyhive().await;
        let carol = make_keyhive().await;
        let dan = make_keyhive().await;
        let eve = make_keyhive().await;

        // Register all individuals on alice, with varying numbers of prekey rotations
        // so that op counts differ across agents.
        let bob_add_op = bob.expand_prekeys().await?;
        let bob_rot1 = bob.rotate_prekey(bob_add_op.payload().share_key).await?;
        let bob_rot2 = bob.rotate_prekey(bob_rot1.payload().new).await?;
        let mut bob_individual = IndividualState::new(KeyOp::Add(bob_add_op));
        bob_individual.receive_prekey_op(KeyOp::Rotate(bob_rot1))?;
        bob_individual.receive_prekey_op(KeyOp::Rotate(bob_rot2))?;
        let bob_indie = bob_individual;
        assert!(alice.register_individual(bob_indie.clone()).await);
        let bob_id = bob_indie.id();

        let carol_add_op = carol.expand_prekeys().await?;
        let carol_rot1 = carol
            .rotate_prekey(carol_add_op.payload().share_key)
            .await?;
        let mut carol_individual = IndividualState::new(KeyOp::Add(carol_add_op));
        carol_individual.receive_prekey_op(KeyOp::Rotate(carol_rot1))?;
        let carol_indie = carol_individual;
        assert!(alice.register_individual(carol_indie.clone()).await);
        let carol_id = carol_indie.id();

        // Dan is known only by a contact card.
        let dan_id = alice
            .receive_contact_card(&dan.generate_contact_card().await?)
            .await?;

        let eve_add_op = eve.expand_prekeys().await?;
        let eve_rot1 = eve.rotate_prekey(eve_add_op.payload().share_key).await?;
        let eve_rot2 = eve.rotate_prekey(eve_rot1.payload().new).await?;
        let eve_rot3 = eve.rotate_prekey(eve_rot2.payload().new).await?;
        let mut eve_individual = IndividualState::new(KeyOp::Add(eve_add_op));
        eve_individual.receive_prekey_op(KeyOp::Rotate(eve_rot1))?;
        eve_individual.receive_prekey_op(KeyOp::Rotate(eve_rot2))?;
        eve_individual.receive_prekey_op(KeyOp::Rotate(eve_rot3))?;
        let eve_indie = eve_individual;
        assert!(alice.register_individual(eve_indie.clone()).await);
        let eve_id = eve_indie.id();

        // Frank: registered but not added to any doc or group, with extra ops
        let frank = make_keyhive().await;
        let frank_add_op = frank.expand_prekeys().await?;
        let frank_rot1 = frank
            .rotate_prekey(frank_add_op.payload().share_key)
            .await?;
        let frank_rot2 = frank.rotate_prekey(frank_rot1.payload().new).await?;
        let frank_indie = IndividualState::new(KeyOp::Add(frank_add_op));
        assert!(alice.register_individual(frank_indie.clone()).await);
        let frank_id = frank_indie.id();
        // Receive additional prekey ops after registration
        alice.receive_prekey_op(&KeyOp::Rotate(frank_rot1)).await?;
        alice.receive_prekey_op(&KeyOp::Rotate(frank_rot2)).await?;

        // Create doc1 with bob (3 ops) and carol (2 ops)
        let doc1_id = alice.generate_doc(vec![], nonempty![[0u8; 32]]).await?;
        alice.add_member(bob_id, doc1_id, Power::Read).await?;
        alice.add_member(carol_id, doc1_id, Power::Edit).await?;

        // Create doc2 with dan (1 op)
        let doc2 = alice.generate_doc(vec![], nonempty![[1u8; 32]]).await?;
        alice.add_member(dan_id, doc2, Power::Read).await?;

        // Create a group with carol (2 ops) and eve (4 ops), then add group to doc2
        let group_id = alice.generate_group(vec![]).await?;
        alice.add_member(carol_id, group_id, Power::Read).await?;
        alice.add_member(eve_id, group_id, Power::Edit).await?;
        alice.add_member(group_id, doc2, Power::Read).await?;
        // Without a revocation somewhere, neither traversal reaches the code that
        // provides a revoked member's keys, and the two agree vacuously.
        alice.revoke_member(carol_id, false, group_id).await?;

        // Get the all-agents result
        let all_results = alice.reachable_prekey_ops_for_all_agents().await?;

        // Verify no phantom agents: every agent in the index should match
        // a per-agent call. Count checked after all per-agent comparisons below.

        // Check the active individual
        let active_id: Identifier = alice.id().into();
        let active_all_ops = all_results.ops_for_agent(&active_id);
        assert!(
            active_all_ops.is_some(),
            "active agent should be in all_results"
        );
        let active_per_agent_ops = alice.reachable_prekey_ops_for_agent(active_id).await?;
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
        let agents: Vec<IndividualId> = vec![bob_id, carol_id, dan_id, eve_id, frank_id];
        for id in &agents {
            let agent_id: Identifier = (*id).into();
            expected_checked.insert(agent_id);

            let all_ops = all_results.ops_for_agent(&agent_id);
            assert!(all_ops.is_some(), "agent {:?} should be in all_results", id);

            let per_agent_ops = alice.reachable_prekey_ops_for_agent(*id).await?;

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
            let mut all_digests: Vec<_> = all_ops.unwrap().map(|op| op.digest()).collect();
            all_digests.sort();
            let mut per_agent_digests: Vec<_> = per_agent_ops
                .values()
                .flat_map(|ops| ops.iter())
                .map(|op| op.digest())
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
            if alice.get_individual((*agent_id).into()).await.is_some() {
                let per_agent_ops = alice.reachable_prekey_ops_for_agent(*agent_id).await?;
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

        Ok(())
    }

    /// Which receive failures may resolve and which never will: a missing
    /// dependency waits; a broken, forged or unauthorized event is dropped.
    #[test]
    fn receive_failures_are_classified() {
        use core::convert::Infallible;

        let doc = DocumentId::generate(&mut rand::rngs::OsRng);
        let cases: [(ReceiveStaticEventError<Infallible>, bool, bool); 6] = [
            (
                ReceiveCgkaOpError::UnknownDocument(Box::new(doc)).into(),
                true,
                false,
            ),
            (
                ReceiveCgkaOpError::CgkaError(CgkaError::OutOfOrderOperation).into(),
                true,
                false,
            ),
            (
                ReceiveCgkaOpError::CgkaError(CgkaError::InvalidPathLength).into(),
                false,
                true,
            ),
            (
                ReceiveCgkaOpError::CgkaError(CgkaError::MembershipUnknown(BTreeSet::new())).into(),
                false,
                false,
            ),
            (
                ReceiveCgkaOpError::UnauthorizedCgkaOp(Box::new(doc)).into(),
                false,
                true,
            ),
            (
                ReceiveCertificateError::Verify(VerifyError::BadSignature).into(),
                false,
                true,
            ),
        ];
        for (error, missing, finished) in cases {
            assert_eq!(error.is_missing_dependency(), missing, "{error}");
            assert_eq!(error.is_final(), finished, "{error}");
        }
    }

    /// `stats` counts groups (not documents or individuals) and each kind of
    /// certificate, and among the events waiting on something, each kind and
    /// how many of them the active identity issued.
    #[tokio::test]
    async fn stats_count_groups_certificates_and_pending_events() -> TestResult {
        use crate::principal::individual::op::{add_key::AddKeyOp, rotate_key::RotateKeyOp};
        use beekem::id::{MemberId, TreeId};
        use keyhive_crypto::share_key::ShareSecretKey;
        use rand::rngs::OsRng;

        let hive = make_keyhive().await;
        let group = hive.generate_group(vec![]).await?;
        hive.generate_group(vec![]).await?;
        let doc = hive.generate_doc(vec![], nonempty![[1u8; 32]]).await?;
        let indie_sk = MemorySigner::generate(&mut OsRng);
        let indie = IndividualState::generate::<Sendable, _, _>(&indie_sk, &mut OsRng).await?;
        hive.register_individual(indie.clone()).await;
        hive.add_member(indie.id(), group, Power::Read).await?;
        hive.revoke_member(indie.id(), false, group).await?;

        let share_key = || ShareSecretKey::generate(&mut OsRng).share_key();
        let pending_from = |signer: &MemorySigner| -> TestResult<Vec<StaticEvent<[u8; 32]>>> {
            let added = Verified::sign_sync(
                &AddKeyOp {
                    share_key: share_key(),
                },
                signer,
            )?;
            let rotated = Verified::sign_sync(
                &RotateKeyOp {
                    old: share_key(),
                    new: share_key(),
                },
                signer,
            )?;
            let cgka = Verified::sign_sync(
                &CgkaOperation {
                    doc_id: TreeId::from(doc),
                    predecessors: BTreeSet::new(),
                    change: CgkaChange::Add {
                        added_id: MemberId::from(&signer.0),
                        pk: share_key(),
                        leaf_index: 0,
                        invitation: None,
                        key_proof: None,
                        citations: BTreeSet::new(),
                    },
                },
                signer,
            )?;
            let delegation = Delegation::new(
                Identifier::from(indie.id()),
                Identifier::from(doc),
                Power::Read,
            );
            let delegated = Verified::sign_sync(&delegation, signer)?;
            let revocation: Revocation<ContentHeads<[u8; 32]>> =
                Revocation::new(delegated.digest());
            let revoked = Verified::sign_sync(&revocation, signer)?;
            Ok(vec![
                StaticEvent::PrekeysExpanded(added.signed().as_ref().clone()),
                StaticEvent::PrekeyRotated(rotated.signed().as_ref().clone()),
                StaticEvent::CgkaOperation(Box::new(cgka.signed().as_ref().clone())),
                StaticEvent::Delegated(delegated.signed().as_ref().clone()),
                StaticEvent::Revoked(revoked.signed().as_ref().clone()),
            ])
        };
        // Twice as many of the active identity's as anyone else's, so that
        // counting the wrong side changes every `_by_active` count.
        let mine = pending_from(&hive.active.signer)?;
        let mine_again = pending_from(&hive.active.signer)?;
        let theirs = pending_from(&MemorySigner::generate(&mut OsRng))?;
        hive.pending_events.lock().await.extend(
            mine.into_iter()
                .chain(mine_again)
                .chain(theirs)
                .map(Arc::new),
        );

        let stats = hive.stats().await;
        assert_eq!(stats.groups, 2, "two groups; a document is not one");
        assert_eq!(stats.revocations, 1);
        assert_eq!(
            (
                stats.pending_prekeys_expanded,
                stats.pending_prekeys_expanded_by_active
            ),
            (3, 2)
        );
        assert_eq!(
            (
                stats.pending_prekey_rotated,
                stats.pending_prekey_rotated_by_active
            ),
            (3, 2)
        );
        assert_eq!(
            (
                stats.pending_cgka_operation,
                stats.pending_cgka_operation_by_active
            ),
            (3, 2)
        );
        assert_eq!(
            (stats.pending_delegated, stats.pending_delegated_by_active),
            (3, 2)
        );
        assert_eq!(
            (stats.pending_revoked, stats.pending_revoked_by_active),
            (3, 2)
        );
        assert_eq!(stats.pending_total(), 15);
        Ok(())
    }

    #[tokio::test]
    async fn test_cgka_ops_for_all_agents_matches_per_agent() {
        test_utils::init_logging();

        let alice = make_keyhive().await;
        let bob = make_keyhive().await;
        let carol = make_keyhive().await;
        let dave = make_keyhive().await;
        let eve = make_keyhive().await;

        // Register all on alice
        let bob_id = introduce(&alice, &bob).await;
        let carol_id = introduce(&alice, &carol).await;
        let dave_id = introduce(&alice, &dave).await;
        let eve_id = introduce(&alice, &eve).await;

        // doc1: bob and carol are direct members
        // generate_doc creates initial CGKA ops; each add_member creates a CGKA Add op
        let doc1_id = alice
            .generate_doc(vec![], nonempty![[0u8; 32]])
            .await
            .unwrap();
        alice
            .add_member(bob_id, doc1_id, Power::Read)
            .await
            .unwrap();
        alice
            .add_member(carol_id, doc1_id, Power::Edit)
            .await
            .unwrap();

        // Sanity: doc1 should have CGKA ops from generate + 2 adds
        let doc1_ops = alice.cgka_ops_for_doc(&doc1_id).await.unwrap();
        assert!(
            doc1_ops.len() >= 3,
            "doc1 should have at least 3 CGKA ops (generate + 2 adds), got {}",
            doc1_ops.len()
        );

        // group: carol and dave
        let group_id = alice.generate_group(vec![]).await.unwrap();
        alice
            .add_member(carol_id, group_id, Power::Read)
            .await
            .unwrap();
        alice
            .add_member(dave_id, group_id, Power::Edit)
            .await
            .unwrap();

        // doc2: group is a member (so carol and dave reach doc2 transitively)
        let doc2 = alice
            .generate_doc(vec![], nonempty![[1u8; 32]])
            .await
            .unwrap();
        alice.add_member(group_id, doc2, Power::Read).await.unwrap();

        // eve: registered but not a member of any doc

        // --- Revoke bob from doc1 ---
        // After revocation, bob should no longer see doc1 CGKA ops (and has
        // no other docs), so both methods should agree he has zero.
        alice.revoke_member(bob_id, false, doc1_id).await.unwrap();

        // Get the all-agents result
        let all_results = alice
            .cgka_ops_for_all_agents()
            .await
            .expect("selects events");

        // Helper to collect flattened CGKA digests from the all-agents result
        let all_digests_for = |agent_id: &Identifier| -> Vec<_> {
            let mut digests: Vec<_> = all_results
                .ops_for_agent(agent_id)
                .map(|ops| ops.map(|op| op.digest()).collect())
                .unwrap_or_default();
            digests.sort();
            digests
        };

        // Helper macro to get sorted per-agent CGKA digests
        macro_rules! per_agent_digests {
            ($agent:expr) => {{
                let ops = alice
                    .cgka_ops_reachable_by_agent($agent)
                    .await
                    .expect("selects events");
                let mut digests: Vec<_> = ops.iter().map(|op| op.digest()).collect();
                digests.sort();
                digests
            }};
        }

        // Eve: registered but not on any doc and should not appear
        let eve_identifier: Identifier = eve_id.into();
        assert!(
            !all_results.index.contains_key(&eve_identifier),
            "eve should not be in all_results since she is not a member of any doc"
        );
        let eve_per_agent = per_agent_digests!(eve_id);
        assert!(
            eve_per_agent.is_empty(),
            "eve per-agent should also be empty"
        );

        // Bob: revoked from doc1, no other docs and should have zero CGKA ops
        let bob_identifier: Identifier = bob_id.into();
        let bob_all = all_digests_for(&bob_identifier);
        let bob_per_agent = per_agent_digests!(bob_id);
        assert_eq!(
            bob_all, bob_per_agent,
            "revoked bob should match (both empty)"
        );
        assert!(bob_all.is_empty(), "revoked bob should have no CGKA ops");

        // Carol: on doc1 directly + doc2 via group and should see ops from both
        let carol_identifier: Identifier = carol_id.into();
        let carol_all = all_digests_for(&carol_identifier);
        let carol_per_agent = per_agent_digests!(carol_id);
        assert_eq!(
            carol_all, carol_per_agent,
            "CGKA op digests should match for carol (multi-doc)"
        );
        // Carol should have ops from both doc1 and doc2
        let carol_doc_ids = &all_results.index[&carol_identifier];
        assert!(
            carol_doc_ids.contains(&doc1_id.into()) && carol_doc_ids.contains(&doc2.into()),
            "carol should reach both doc1 and doc2"
        );

        // Dave: only on doc2 via group
        let dave_identifier: Identifier = dave_id.into();
        let dave_all = all_digests_for(&dave_identifier);
        let dave_per_agent = per_agent_digests!(dave_id);
        assert_eq!(
            dave_all, dave_per_agent,
            "CGKA op digests should match for dave (group-transitive)"
        );
        let dave_doc_ids = &all_results.index[&dave_identifier];
        assert_eq!(dave_doc_ids.len(), 1, "dave should only reach doc2");
        assert!(
            dave_doc_ids.contains(&doc2.into()),
            "dave should reach doc2"
        );

        // Active agent (alice): should see all docs she owns
        let active_id: Identifier = alice.id().into();
        let active_all = all_digests_for(&active_id);
        let active_per_agent = per_agent_digests!(active_id);
        assert_eq!(
            active_all, active_per_agent,
            "CGKA op digests should match for active agent"
        );
    }

    #[tokio::test]
    async fn test_revoking_a_member_reports_the_removal_in_cgka_ops() -> TestResult {
        test_utils::init_logging();

        let alice = make_keyhive().await;
        let bob_kh = make_keyhive().await;
        let bob_id = introduce(&alice, &bob_kh).await;

        let doc = alice.generate_doc(vec![], nonempty![[0u8; 32]]).await?;
        alice.add_member(bob_id, doc, Power::Read).await?;

        let update = alice.revoke_member(bob_id, true, doc).await?;

        assert!(
            has_remove_citing_its_revocation(&update),
            "revoking Bob should report a CGKA remove citing it in the update"
        );
        assert!(
            !alice
                .cgka_members_for(doc)
                .await?
                .ok_or("has not joined the CGKA group")?
                .contains(&bob_id),
            "Bob is still in the CGKA group"
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_revoking_a_subgroup_reports_its_members_removals_in_cgka_ops() -> TestResult {
        test_utils::init_logging();

        let alice = make_keyhive().await;
        let dave_kh = make_keyhive().await;
        let eve_kh = make_keyhive().await;
        let dave_id = introduce(&alice, &dave_kh).await;
        let eve_id = introduce(&alice, &eve_kh).await;

        let inner_id = alice.generate_group(vec![]).await?;
        for who in [dave_id, eve_id] {
            alice.add_member(who, inner_id, Power::Read).await?;
        }
        let outer_id = alice.generate_group(vec![]).await?;
        alice.add_member(inner_id, outer_id, Power::Read).await?;

        let doc = alice.generate_doc(vec![], nonempty![[0u8; 32]]).await?;
        alice.add_member(outer_id, doc, Power::Read).await?;

        let update = alice.revoke_member(inner_id, true, outer_id).await?;

        assert!(
            has_remove_citing_its_revocation(&update),
            "revoking the subgroup should report a CGKA remove citing it in the update"
        );
        let members = alice
            .cgka_members_for(doc)
            .await?
            .ok_or("has not joined the CGKA group")?;
        for (who, id) in [("dave", dave_id), ("eve", eve_id)] {
            assert!(
                !members.contains(&id),
                "{who} came in through the revoked subgroup and is still in the CGKA group"
            );
        }

        Ok(())
    }

    #[tokio::test]
    async fn own_cgka_keys_are_the_keys_an_operation_provides_that_member() -> TestResult {
        test_utils::init_logging();

        let alice = make_keyhive().await;
        let bob_kh = make_keyhive().await;
        let bob = introduce(&alice, &bob_kh).await;
        let me = alice.active.id();

        let doc = alice.generate_doc(vec![], nonempty![[0u8; 32]]).await?;
        alice.add_member(bob, doc, Power::Read).await?;
        let (update, _) = alice.force_pcs_update(doc).await?;

        let ops = alice.cgka_ops_for_doc(&doc).await.expect("alice holds it");
        let invitation = ops
            .iter()
            .find(|op| invites(op.payload(), bob))
            .expect("bob is invited");
        let CgkaChange::Add { pk, .. } = invitation.payload().change else {
            unreachable!("an invitation is an add")
        };
        assert_eq!(own_cgka_keys(invitation, bob), vec![pk]);
        assert_eq!(own_cgka_keys(invitation, me), Vec::new());

        let CgkaChange::Update { new_path, .. } = &update.payload().change else {
            unreachable!("a PCS update is an update")
        };
        assert_eq!(own_cgka_keys(&update, me), vec![new_path.leaf_pk]);
        assert_eq!(own_cgka_keys(&update, bob), Vec::new());

        Ok(())
    }

    #[tokio::test]
    async fn a_second_route_does_not_add_a_member_to_the_cgka_group_twice() -> TestResult {
        test_utils::init_logging();

        let alice = make_keyhive().await;
        let frank_kh = make_keyhive().await;
        let frank_id = introduce(&alice, &frank_kh).await;

        let group_id = alice.generate_group(vec![]).await?;
        alice.add_member(frank_id, group_id, Power::Read).await?;

        let doc = alice.generate_doc(vec![], nonempty![[0u8; 32]]).await?;
        alice.add_member(group_id, doc, Power::Read).await?;

        let with_one_route = alice
            .cgka_members_for(doc)
            .await?
            .expect("this replica has joined the document's CGKA group")
            .len();
        assert_eq!(
            with_one_route, 2,
            "alice and frank, so frank really is in the CGKA group by way of the group \
             rather than absent from it"
        );

        // Frank is already reachable through the group. Adding him directly is a second
        // route to the same identity, not a second identity.
        alice.add_member(frank_id, doc, Power::Read).await?;

        assert_eq!(
            alice
                .cgka_members_for(doc)
                .await?
                .expect("this replica has joined the document's CGKA group")
                .len(),
            with_one_route,
            "a second route to frank should not put him in the CGKA group a second time"
        );

        Ok(())
    }

    #[tokio::test]
    async fn a_reader_added_before_joining_the_cgka_group_is_added_at_the_next_write() -> TestResult
    {
        test_utils::init_logging();

        let alice = make_keyhive().await;
        let bob = make_keyhive().await;
        let bob_id = introduce(&alice, &bob).await;
        introduce(&bob, &alice).await;

        let account_id = alice.generate_doc(vec![], nonempty![[0u8; 32]]).await?;
        let project_id = alice.generate_doc(vec![], nonempty![[1u8; 32]]).await?;

        alice
            .add_member(account_id, project_id, Power::Admin)
            .await?;
        alice.add_member(bob_id, account_id, Power::Admin).await?;

        // Bob receives the delegations that describe both documents and none of the CGKA
        // operations that would let him rekey one.
        let mut for_bob = alice.events_for_agent(bob_id).await?;
        for_bob.retain(|_, event| !matches!(event, Event::CgkaOperation(_)));
        bob.ingest_event_table(for_bob).await?;

        let carol_card = make_keyhive().await.get_existing_contact_card().await;
        let carol = bob.receive_contact_card(&carol_card).await?;
        let update = bob.add_member(carol, project_id, Power::Read).await?;

        assert!(update.cgka_ops.is_empty());

        send(&alice, &bob, true).await?;
        bob.try_encrypt_content(project_id, &[2u8; 32], &[], b"after joining")
            .await?;
        let members = bob
            .cgka_members_for(project_id)
            .await?
            .ok_or("bob has not joined the project's CGKA group")?;
        assert!(members.contains(&carol));

        Ok(())
    }

    #[tokio::test]
    async fn a_trunk_can_write_after_content_its_fork_wrote() -> TestResult {
        let alice = make_keyhive().await;
        let doc = alice.generate_doc(vec![], nonempty![[1u8; 32]]).await?;
        let trunk = Arc::new(Mutex::new(alice));

        transact_async(
            &trunk,
            |fork: Keyhive<Sendable, _, _, _, _, Log<[u8; 32]>, _, _>| async move {
                fork.try_encrypt_content(doc, &[2u8; 32], &[], b"in the fork")
                    .await
                    .map_err(|e| e.to_string())?;
                Ok::<_, String>(fork)
            },
        )
        .await?;

        trunk
            .lock()
            .await
            .try_encrypt_content(doc, &[3u8; 32], &[[2u8; 32]], b"after the fork")
            .await?;
        Ok(())
    }

    #[tokio::test]
    async fn a_fork_and_its_trunk_keep_each_others_cgka_group_members() -> TestResult {
        let alice = make_keyhive().await;
        let (bob, carol) = (make_keyhive().await, make_keyhive().await);
        let bob_id = introduce(&alice, &bob).await;
        let carol_id = introduce(&alice, &carol).await;
        let doc = alice.generate_doc(vec![], nonempty![[1u8; 32]]).await?;
        alice.add_member(bob_id, doc, Power::Read).await?;
        let trunk = Arc::new(Mutex::new(alice));

        transact_async(
            &trunk,
            |fork: Keyhive<Sendable, _, _, _, _, Log<[u8; 32]>, _, _>| async move {
                let members = fork
                    .cgka_members_for(doc)
                    .await
                    .map_err(|e| e.to_string())?;
                if !members.is_some_and(|s| s.contains(&bob_id)) {
                    return Err("the fork's CGKA group lost bob".to_string());
                }
                fork.add_member(carol_id, doc, Power::Read)
                    .await
                    .map_err(|e| e.to_string())?;
                Ok::<_, String>(fork)
            },
        )
        .await?;

        // Writing issues the operations the trunk's certificates imply for the
        // document, which would remove carol if the trunk lacked the
        // certificates the fork inserted.
        let trunk = trunk.lock().await;
        trunk
            .try_encrypt_content(doc, &[2u8; 32], &[], b"after the fork")
            .await?;
        let members = trunk
            .cgka_members_for(doc)
            .await?
            .ok_or("has not joined the CGKA group")?;
        assert!(
            members.contains(&bob_id),
            "bob is not a member of the CGKA group"
        );
        assert!(
            members.contains(&carol_id),
            "carol is not a member of the CGKA group"
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_async_transaction() -> TestResult {
        test_utils::init_logging();

        let sk = MemorySigner::generate(&mut rand::rngs::OsRng);
        let hive = Keyhive::<Sendable, _, [u8; 32], Vec<u8>, _, NoListener, _, _>::generate(
            sk,
            Arc::new(Mutex::new(MemoryCiphertextStore::new())),
            NoListener,
            MemoryKeyline::new(),
            rand::rngs::OsRng,
        )
        .await?;

        let trunk = Arc::new(Mutex::new(hive));

        let alice_indie = IndividualState::generate::<Sendable, _, _>(
            &MemorySigner::generate(&mut rand::rngs::OsRng),
            &mut rand::rngs::OsRng,
        )
        .await?;

        let alice_id = alice_indie.id();
        let alice = alice_indie;

        {
            trunk.lock().await.register_individual(alice.clone()).await;
            trunk
                .lock()
                .await
                .generate_doc(vec![alice_id.into()], nonempty![[0u8; 32]])
                .await?;
            trunk
                .lock()
                .await
                .generate_group(vec![alice_id.into()])
                .await?;
            let locked_trunk = trunk.lock().await;

            assert_eq!(locked_trunk.active.key_pairs.lock().await.len(), 7);
            assert_eq!(locked_trunk.stats().await.delegations, 4, "the root edges");
            assert_eq!(locked_trunk.stats().await.groups, 1);
            assert_eq!(locked_trunk.documents.lock().await.len(), 1);
        }

        let tx = transact_async(
            &trunk,
            |fork: Keyhive<Sendable, _, _, _, _, Log<[u8; 32]>, _, _>| async move {
                // Depending on when the async runs
                let init_doc_count = fork.documents.lock().await.len();
                assert!(init_doc_count == 1 || init_doc_count == 2);

                // The fork shares the trunk's Keyline store: its group and its
                // one or two documents, depending on when the async runs.
                let init_subjects = Keyline::<Sendable>::subjects(fork.keyline())
                    .await
                    .expect("the memory store does not fail")
                    .value
                    .len();
                assert!(init_subjects == 2 || init_subjects == 3);

                assert_eq!(fork.active.key_pairs.lock().await.len(), 7);
                fork.expand_prekeys().await.unwrap(); // 1 event (prekey)
                assert_eq!(fork.active.key_pairs.lock().await.len(), 8);

                let bob_indie = IndividualState::generate::<Sendable, _, _>(
                    &MemorySigner::generate(&mut rand::rngs::OsRng),
                    &mut rand::rngs::OsRng,
                )
                .await
                .unwrap();

                let bob = bob_indie.id();
                fork.register_individual(bob_indie).await;

                fork.generate_group(vec![bob.into()]).await.unwrap(); // 2 events (dlgs)
                fork.generate_group(vec![bob.into()]).await.unwrap(); // 2 events (dlgs)
                fork.generate_group(vec![bob.into()]).await.unwrap(); // 2 events (dlgs)

                // 2 events (dlgs)
                fork.generate_doc(vec![bob.into()], nonempty![[1u8; 32]])
                    .await
                    .unwrap();
                assert_eq!(fork.documents.lock().await.len(), init_doc_count + 1);

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
                // An add for the creator, an add for bob, and the creator's update.
                assert_eq!(cgka_count, 3);
                assert_eq!(prekey_expanded_count, 1);
                Ok::<_, String>(fork)
            },
        )
        .await;

        {
            let locked_trunk = trunk.lock().await;
            locked_trunk
                .generate_doc(vec![alice_id.into()], nonempty![[2u8; 32]])
                .await
                .unwrap();

            assert!(!locked_trunk.documents.lock().await.is_empty());
            assert!(locked_trunk.documents.lock().await.len() <= 3);

            // FIXME add transact right on Keyhive that also dispatches new events
            let () = tx?;

            // tx is done, so should be all caught up. Counts are now certain.
            assert_eq!(locked_trunk.active.key_pairs.lock().await.len(), 8);
            assert_eq!(locked_trunk.documents.lock().await.len(), 3);
            // Groups are Keyline subjects: the trunk's own and the fork's three.
            let subjects = Keyline::<Sendable>::subjects(locked_trunk.keyline())
                .await?
                .value;
            assert_eq!(subjects.len(), 3 + 4, "three documents and four groups");

            locked_trunk
                .generate_doc(vec![alice_id.into()], nonempty![[3u8; 32]])
                .await
                .unwrap();

            assert_eq!(locked_trunk.documents.lock().await.len(), 4);
        }

        Ok(())
    }
}
