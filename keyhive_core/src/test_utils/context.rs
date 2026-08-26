//! A testing context that manages a set of keyhives that know about each other, and the
//! machinery for moving events between them.

use crate::crypto::signed_ext::SignedSubjectId;
use crate::{
    access::Access,
    archive::Archive,
    event::static_event::StaticEvent,
    keyhive::{
        CausalDecryptError, EncryptContentError, Keyhive, NotFound, ReceiveStaticEventError,
    },
    listener::no_listener::NoListener,
    principal::{
        agent::Agent,
        document::{
            id::DocumentId, AddMemberError, AddMemberUpdate, DecryptError, EncryptError,
            GenerateDocError,
        },
        group::{
            delegation::Delegation, error::AddError, id::GroupId, AddGroupMemberError,
            RevokeMemberError,
        },
        identifier::Identifier,
        individual::{id::IndividualId, op::KeyOp, Individual, ReceivePrekeyOpError},
        membered::{id::MemberedId, Member, Membered},
        public::Public,
    },
    store::ciphertext::{
        memory::MemoryCiphertextStore, CausalDecryptionError, CausalDecryptionState,
    },
};
use beekem::encrypted::EncryptedContent;
use dupe::Dupe;
use future_form::Sendable;
use futures::lock::Mutex;
use keyhive_crypto::{
    content::reference::ContentRef, share_key::ShareKey, signed::Signed, signed::SigningError,
    signer::memory::MemorySigner, symmetric_key::SymmetricKey,
};
use nonempty::nonempty;
use rand::{rngs::StdRng, seq::SliceRandom, SeedableRng};
use std::{
    collections::{hash_map::DefaultHasher, BTreeMap, BTreeSet},
    hash::{Hash, Hasher},
    ops::Deref,
    sync::Arc,
};
use thiserror::Error;

/// The keyhive these tests use.
pub type Hive = Keyhive<Sendable, MemorySigner>;

type Store = MemoryCiphertextStore<[u8; 32], Vec<u8>>;
type Ciphertext = EncryptedContent<Vec<u8>, [u8; 32]>;

pub type TestResult<T> = Result<T, TestError>;

/// Why an operation was refused.
///
/// The library spreads one conclusion across several enums. This flattens the ones a test
/// asserts on into a single vocabulary, and wraps everything else as `Other`.
#[derive(Debug, Error)]
pub enum TestError {
    /// The issuer holds some access over the resource, but less than they tried to delegate.
    #[error("escalation: wanted {wanted}, holds {held}")]
    Escalation { wanted: Access, held: Access },

    /// The issuer has no access to the resource.
    #[error("no authority over that resource")]
    NoAuthority,

    /// The instance has not received the events that would tell it this exists.
    ///
    /// Boxed because an [`Identifier`] holds a decompressed curve point and is 192 bytes,
    /// which would make every `TestResult` in the suite carry that much on the error path.
    #[error("{0} has not been received. Sync first, or check access.")]
    NotSynced(Box<Identifier>),

    /// Two things in one context cannot share a name.
    #[error("{name:?} is already the name of something in this TestContext")]
    NameTaken { name: String },

    /// A predecessor was named that belongs to a different document.
    #[error("that content is in {holds:?}, not in {doc:?}")]
    WrongDocument { holds: String, doc: String },

    /// Prekey secrets belong to one identity and cannot be given to another.
    #[error("{from:?} and {to:?} are different identities")]
    DifferentIdentity { from: String, to: String },

    /// The reader holds no secret key that derives this content's key.
    #[error("no secret key for that content")]
    NoKey,

    /// A key was derived but the ciphertext did not authenticate under it.
    #[error("the ciphertext did not authenticate")]
    CiphertextRejected,

    /// Anything else, wrapping the underlying error as a `String`.
    #[error("{0}")]
    Other(String),
}

impl From<NotFound> for TestError {
    fn from(e: NotFound) -> Self {
        TestError::NotSynced(e.0)
    }
}

impl From<std::convert::Infallible> for TestError {
    fn from(never: std::convert::Infallible) -> Self {
        match never {}
    }
}

impl From<AddMemberError> for TestError {
    fn from(e: AddMemberError) -> Self {
        match e {
            AddMemberError::NotFound(inner) => inner.into(),
            AddMemberError::AddMemberError(inner) => inner.into(),
            other => TestError::Other(other.to_string()),
        }
    }
}

impl From<AddGroupMemberError> for TestError {
    fn from(e: AddGroupMemberError) -> Self {
        match e {
            AddGroupMemberError::AddError(AddError::Escalation { wanted, held }) => {
                TestError::Escalation { wanted, held }
            }
            AddGroupMemberError::NoProof => TestError::NoAuthority,
            other => TestError::Other(other.to_string()),
        }
    }
}

impl From<RevokeMemberError> for TestError {
    fn from(e: RevokeMemberError) -> Self {
        match e {
            RevokeMemberError::NotFound(inner) => inner.into(),
            RevokeMemberError::NoProof => TestError::NoAuthority,
            RevokeMemberError::AddError(AddError::Escalation { wanted, held }) => {
                TestError::Escalation { wanted, held }
            }
            RevokeMemberError::RedelegationError(inner) => inner.into(),
            other => TestError::Other(other.to_string()),
        }
    }
}

impl From<DecryptError> for TestError {
    fn from(e: DecryptError) -> Self {
        match e {
            DecryptError::NotFound(inner) => inner.into(),
            DecryptError::KeyNotFound => TestError::NoKey,
            DecryptError::DecryptionFailed(_) | DecryptError::SivMismatch => {
                TestError::CiphertextRejected
            }
            other => TestError::Other(other.to_string()),
        }
    }
}

macro_rules! other_from {
    ($($t:ty),+ $(,)?) => {$(
        impl From<$t> for TestError {
            fn from(e: $t) -> Self {
                TestError::Other(e.to_string())
            }
        }
    )+};
}

other_from!(
    SigningError,
    GenerateDocError,
    EncryptError,
    ReceivePrekeyOpError,
);

impl From<EncryptContentError> for TestError {
    fn from(e: EncryptContentError) -> Self {
        match e {
            EncryptContentError::NotFound(inner) => inner.into(),
            other => TestError::Other(other.to_string()),
        }
    }
}

impl From<CausalDecryptError<Sendable, [u8; 32], Vec<u8>, Store>> for TestError {
    fn from(e: CausalDecryptError<Sendable, [u8; 32], Vec<u8>, Store>) -> Self {
        match e {
            CausalDecryptError::NotFound(inner) => inner.into(),
            other => TestError::Other(other.to_string()),
        }
    }
}

impl From<ReceiveStaticEventError<Sendable, MemorySigner, [u8; 32], NoListener>> for TestError {
    fn from(e: ReceiveStaticEventError<Sendable, MemorySigner, [u8; 32], NoListener>) -> Self {
        TestError::Other(e.to_string())
    }
}

impl From<CausalDecryptionError<Sendable, [u8; 32], Vec<u8>, Store>> for TestError {
    fn from(e: CausalDecryptionError<Sendable, [u8; 32], Vec<u8>, Store>) -> Self {
        TestError::Other(e.to_string())
    }
}

impl From<String> for TestError {
    fn from(m: String) -> Self {
        TestError::Other(m)
    }
}

impl From<&str> for TestError {
    fn from(m: &str) -> Self {
        TestError::Other(m.to_string())
    }
}

/// Identifies one instance. A single keyhive identity can be running more than one instance.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct InstanceId(u32);

/// One running [`Hive`], with the name the test gave it.
///
/// Derefs to the keyhive, so `alice.add_member(..)` and `alice.id()` are the `Hive`s own
/// methods.
#[derive(Clone)]
pub struct Instance {
    hive: Hive,
    instance: InstanceId,
    name: Arc<str>,
}

impl Instance {
    /// The name this instance was created with, for assertion messages.
    pub fn name(&self) -> &str {
        &self.name
    }
}

impl From<&Instance> for Identifier {
    fn from(instance: &Instance) -> Identifier {
        instance.id().into()
    }
}

impl Deref for Instance {
    type Target = Hive;

    fn deref(&self) -> &Hive {
        &self.hive
    }
}

impl std::fmt::Debug for Instance {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Instance({})", self.name)
    }
}

/// The kind of [`StaticEvent`], for counting and filtering by kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EventKind {
    PrekeysExpanded,
    PrekeyRotated,
    CgkaOperation,
    Delegated,
    Revoked,
}

impl<T: ContentRef> From<&StaticEvent<T>> for EventKind {
    fn from(event: &StaticEvent<T>) -> Self {
        match event {
            StaticEvent::PrekeysExpanded(_) => EventKind::PrekeysExpanded,
            StaticEvent::PrekeyRotated(_) => EventKind::PrekeyRotated,
            StaticEvent::CgkaOperation(_) => EventKind::CgkaOperation,
            StaticEvent::Delegated(_) => EventKind::Delegated,
            StaticEvent::Revoked(_) => EventKind::Revoked,
        }
    }
}

/// The prekey operation, as a value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrekeyOp {
    Added { new: ShareKey },
    Rotated { old: ShareKey, new: ShareKey },
}

impl PrekeyOp {
    /// The key this operation introduced.
    pub fn new_key(&self) -> ShareKey {
        match self {
            PrekeyOp::Added { new } | PrekeyOp::Rotated { new, .. } => *new,
        }
    }
}

/// The same content with one bit of the ciphertext flipped.
pub fn with_a_flipped_bit(ct: &Ciphertext) -> Ciphertext {
    let mut copy = ct.clone();
    assert!(!copy.ciphertext.is_empty(), "nothing to flip");
    let last = copy.ciphertext.len() - 1;
    copy.ciphertext[last] ^= 1;
    copy
}

/// The content ref this harness gives a piece of content.
pub fn content_ref(content: &[u8]) -> [u8; 32] {
    blake3::hash(content).into()
}

/// One delegation, as plain values, for a test that wants to compare or assert on it.
///
/// A `Signed<Delegation<..>>` carries handles and four type parameters, which is more than an
/// assertion needs and prints badly on failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DelegationSummary {
    /// Who signed it.
    pub issuer: Identifier,
    /// Who received the access.
    pub audience: Identifier,
    /// The group or document the access is over.
    pub subject: Identifier,
    /// How much access it conveys before attenuation.
    pub can: Access,
}

impl From<&Signed<Delegation<Sendable, MemorySigner>>> for DelegationSummary {
    fn from(signed: &Signed<Delegation<Sendable, MemorySigner>>) -> Self {
        DelegationSummary {
            issuer: Identifier::from(signed.issuer()),
            audience: signed.payload().delegate().id(),
            subject: signed.subject_id(),
            can: signed.payload().can(),
        }
    }
}

/// `summary()` on what [`Hive::add_member`] returns, so a test can assert on plain values.
pub trait AddMemberUpdateExt {
    fn summary(&self) -> DelegationSummary;
}

impl AddMemberUpdateExt for AddMemberUpdate<Sendable, MemorySigner> {
    fn summary(&self) -> DelegationSummary {
        DelegationSummary::from(self.delegation.as_ref())
    }
}

/// A set of instances, groups and documents, with one [`Hive`] per instance.
pub struct TestContext {
    hives: BTreeMap<InstanceId, Instance>,
    /// The store each instance the context built was given, so it can deliver content the
    /// way an application would. An adopted instance has none, because its store belongs to
    /// whoever built it.
    stores: BTreeMap<InstanceId, Store>,
    /// One signing key per identity, so a second instance can be given the same one.
    signers: BTreeMap<IndividualId, MemorySigner>,
    names: BTreeMap<Identifier, Arc<str>>,
    /// The digests each instance has received, so `sync_all_unsent` sends a delta.
    delivered: BTreeMap<InstanceId, BTreeSet<[u8; 32]>>,
    last_delivery: usize,
    next_instance: u32,
    /// Which document each piece of content was written into. A ciphertext does not carry
    /// its document, so this is how `encrypt_after` can refuse a predecessor from elsewhere.
    written: BTreeMap<[u8; 32], DocumentId>,
}

impl std::fmt::Debug for TestContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let names: Vec<&str> = self.hives.values().map(|i| i.name()).collect();
        write!(f, "TestContext({})", names.join(", "))
    }
}

impl TestContext {
    pub async fn new() -> Self {
        let mut names = BTreeMap::new();
        names.insert(Public.id(), "public".into());
        TestContext {
            hives: BTreeMap::new(),
            stores: BTreeMap::new(),
            signers: BTreeMap::new(),
            names,
            delivered: BTreeMap::new(),
            last_delivery: 0,
            next_instance: 0,
            written: BTreeMap::new(),
        }
    }

    /// Create an identity, with one instance running.
    ///
    /// Every instance learns every other instance's contact card, so `NotSynced` is about
    /// events rather than introductions.
    pub async fn individual(&mut self, name: &str) -> TestResult<Instance> {
        let signer = MemorySigner::generate(&mut rand::rngs::OsRng);
        let handle = self.add_instance(signer.clone(), name).await?;
        self.signers.insert(handle.id(), signer);
        self.names.insert(handle.id().into(), handle.name.clone());
        Ok(handle)
    }

    /// Take a keyhive the test built itself and treat it as one of the cast.
    ///
    /// The signing key stays with whoever made it, so this context cannot later run a second
    /// instance of an adopted identity.
    pub async fn adopt(&mut self, hive: Hive, name: &str) -> TestResult<Instance> {
        let handle = self.register_instance(hive, name).await?;
        // An identity already in the cast keeps the name it arrived with.
        self.names
            .entry(handle.id().into())
            .or_insert_with(|| handle.name.clone());
        Ok(handle)
    }

    /// A new instance of an existing identity, sharing its signing key.
    pub async fn new_keyhive_instance_for(
        &mut self,
        of: &Instance,
        name: &str,
    ) -> TestResult<Instance> {
        let signer = self
            .signers
            .get(&of.id())
            .ok_or_else(|| format!("{:?} was not created by this TestContext", of.name))?
            .clone();
        let handle = self.add_instance(signer, name).await?;
        assert_eq!(handle.id(), of.id());
        Ok(handle)
    }

    /// Give one instance's prekey secrets to another instance of the same identity.
    ///
    /// An invitation is addressed to one specific prekey, so an instance cannot open one
    /// aimed at a sibling's prekey until it has that sibling's secrets. Returns how many
    /// events `to` was holding that it could then apply.
    pub async fn share_prekey_secrets(
        &mut self,
        from: &Instance,
        to: &Instance,
    ) -> TestResult<usize> {
        if from.id() != to.id() {
            return Err(TestError::DifferentIdentity {
                from: from.name.to_string(),
                to: to.name.to_string(),
            });
        }
        let blob = from
            .export_prekey_secrets()
            .await
            .map_err(|e| TestError::Other(e.to_string()))?;
        let before = self.pending_event_count(to).await;
        to.import_prekey_secrets(&blob)
            .await
            .map_err(|e| TestError::Other(e.to_string()))?;
        Ok(before.saturating_sub(self.pending_event_count(to).await))
    }

    /// [`Hive::expand_prekeys`], reduced to the key it added.
    pub async fn expand_prekeys(&self, who: &Instance) -> TestResult<ShareKey> {
        Ok(who.expand_prekeys().await?.payload().share_key)
    }

    /// [`Hive::rotate_prekey`], reduced to the key that replaced `old`.
    pub async fn rotate_prekey(&self, who: &Instance, old: ShareKey) -> TestResult<ShareKey> {
        Ok(who.rotate_prekey(old).await?.payload().new)
    }

    /// The [`Individual`] `observer` holds for `who`.
    async fn individual_seen_by(
        observer: &Instance,
        who: IndividualId,
    ) -> TestResult<Arc<Mutex<Individual>>> {
        observer
            .get_individual(who)
            .await
            .ok_or_else(|| TestError::NotSynced(Box::new(who.into())))
    }

    /// The prekeys `observer` holds for `who`.
    ///
    /// Reaching into another identity's key material, which is why it is here rather than on
    /// [`Hive`]. A test uses it to check that a rotation reached `observer`.
    pub async fn prekeys_of(
        &self,
        observer: &Instance,
        who: IndividualId,
    ) -> TestResult<BTreeSet<ShareKey>> {
        let indie = Self::individual_seen_by(observer, who).await?;
        let locked = indie.lock().await;
        Ok(locked.prekeys().iter().copied().collect())
    }

    /// The prekey operations behind [`TestContext::prekeys_of`].
    pub async fn prekey_ops_of(
        &self,
        observer: &Instance,
        who: IndividualId,
    ) -> TestResult<Vec<PrekeyOp>> {
        let indie = Self::individual_seen_by(observer, who).await?;
        let locked = indie.lock().await;
        Ok(locked
            .prekey_ops()
            .values()
            .map(|op| match op.as_ref() {
                KeyOp::Add(add) => PrekeyOp::Added {
                    new: add.payload().share_key,
                },
                KeyOp::Rotate(rot) => PrekeyOp::Rotated {
                    old: rot.payload().old,
                    new: rot.payload().new,
                },
            })
            .collect())
    }

    /// [`Hive::force_pcs_update`], reduced to the share key the rotation introduced.
    pub async fn force_pcs_update(&self, who: &Instance, doc: DocumentId) -> TestResult<ShareKey> {
        let handle = who
            .get_document(doc)
            .await
            .ok_or_else(|| TestError::NotSynced(Box::new(doc.into())))?;
        let (_op, new_key, _secret) = who.force_pcs_update(handle).await?;
        Ok(new_key)
    }

    pub async fn group(&mut self, owner: &Instance, name: &str) -> TestResult<GroupId> {
        self.claim_name(name)?;
        let g = owner.generate_group(vec![]).await?;
        let id = { g.lock().await.group_id() };
        self.names.insert(id.into(), name.into());
        Ok(id)
    }

    pub async fn doc(&mut self, owner: &Instance, name: &str) -> TestResult<DocumentId> {
        self.claim_name(name)?;
        let d = owner.generate_doc(vec![], nonempty![[0u8; 32]]).await?;
        let id = { d.lock().await.doc_id() };
        self.names.insert(id.into(), name.into());
        Ok(id)
    }

    /// Rename the keys of a query result, so assertions can say "bob" rather than an id.
    ///
    /// The library's queries are keyed by [`Identifier`]. Only the context knows the names.
    pub fn named<K: Into<Identifier>, V>(
        &self,
        raw: impl IntoIterator<Item = (K, V)>,
    ) -> BTreeMap<String, V> {
        raw.into_iter()
            .map(|(id, value)| (self.name_of(id.into()).to_string(), value))
            .collect()
    }

    /// [`TestContext::named`] over a member map, keeping only what each member may do.
    ///
    /// [`Hive::reachable_members`] says what kind of principal each member is as well as its
    /// access. A test that only asks about access says so with this.
    pub fn named_access<K: Into<Identifier>>(
        &self,
        raw: impl IntoIterator<Item = (K, Member)>,
    ) -> BTreeMap<String, Access> {
        self.named(raw.into_iter().map(|(id, member)| (id, member.can)))
    }

    /// The name this context knows `id` by, or the id itself if it knows none.
    pub fn name_of(&self, id: Identifier) -> Arc<str> {
        self.names
            .get(&id)
            .cloned()
            .unwrap_or_else(|| id.to_string().into())
    }

    /// Encrypt `content` into `doc`, choosing a content ref for it.
    pub async fn encrypt(
        &mut self,
        who: &Instance,
        doc: DocumentId,
        content: &[u8],
    ) -> TestResult<Ciphertext> {
        Ok(self.encrypt_keyed(who, doc, content).await?.0)
    }

    /// Encrypt, also returning the application secret the content went under.
    pub async fn encrypt_keyed(
        &mut self,
        who: &Instance,
        doc: DocumentId,
        content: &[u8],
    ) -> TestResult<(Ciphertext, SymmetricKey)> {
        let (out, key) = who
            .try_encrypt_content_keyed(doc, &content_ref(content), &vec![], content)
            .await?;
        let ct = out.encrypted_content().clone();
        self.written.insert(ct.content_ref, doc);
        Ok((ct, key))
    }

    /// Encrypt content that follows `after` in the document's content DAG.
    pub async fn encrypt_after(
        &mut self,
        who: &Instance,
        doc: DocumentId,
        after: &[&Ciphertext],
        content: &[u8],
    ) -> TestResult<Ciphertext> {
        let mut pred_refs = Vec::with_capacity(after.len());
        for pred in after {
            self.check_same_document(pred, doc)?;
            pred_refs.push(pred.content_ref);
        }
        let out = who
            .try_encrypt_content(doc, &content_ref(content), &pred_refs, content)
            .await?;
        let ct = out.encrypted_content().clone();
        self.written.insert(ct.content_ref, doc);
        Ok(ct)
    }

    /// Write `content` in an envelope listing the ancestors and carrying the keys to open
    /// them. Simulates what an application would do.
    ///
    /// The author is also given a copy in their own store, as an application would keep what
    /// it wrote. Other readers still need to be given one.
    pub async fn encrypt_in_envelope(
        &mut self,
        who: &Instance,
        doc: DocumentId,
        after: &[&Ciphertext],
        content: &[u8],
    ) -> TestResult<Ciphertext> {
        let mut pred_refs = Vec::with_capacity(after.len());
        for pred in after {
            self.check_same_document(pred, doc)?;
            pred_refs.push(pred.content_ref);
        }
        let out = who
            .try_encrypt_content_in_envelope(doc, &content_ref(content), &pred_refs, content)
            .await
            .map_err(|e| TestError::Other(e.to_string()))?;
        let ct = out.encrypted_content().clone();
        self.written.insert(ct.content_ref, doc);
        self.give_content(who, &ct).await?;
        Ok(ct)
    }

    /// Refuse a predecessor written into a different document.
    fn check_same_document(&self, pred: &Ciphertext, doc: DocumentId) -> TestResult<()> {
        match self.written.get(&pred.content_ref) {
            Some(held) if *held != doc => Err(TestError::WrongDocument {
                holds: self.name_of((*held).into()).to_string(),
                doc: self.name_of(doc.into()).to_string(),
            }),
            _ => Ok(()),
        }
    }

    /// The application secret `who` derives for `encrypted`, `None` if it cannot derive one,
    /// and an error if `who` has never received `doc`.
    pub async fn derived_key(
        &self,
        who: &Instance,
        doc: DocumentId,
        encrypted: &Ciphertext,
    ) -> TestResult<Option<SymmetricKey>> {
        match who.try_decrypt_content_keyed(doc, encrypted).await {
            Ok((_, key)) => Ok(Some(key)),
            Err(e) => match TestError::from(e) {
                TestError::NoKey | TestError::CiphertextRejected => Ok(None),
                other => Err(other),
            },
        }
    }

    /// Rebuild an archive as a new instance of the same identity, with a fresh ciphertext
    /// store.
    pub async fn rebuild_from_archive(
        &mut self,
        archive: &Archive<[u8; 32]>,
        name: &str,
    ) -> TestResult<Instance> {
        let identity = archive.id();
        let signer = self
            .signers
            .get(&identity)
            .ok_or("that archive's identity was not created by this TestContext")?
            .clone();
        let store = Store::new();
        let hive = Keyhive::<Sendable, _, _, _, _, _, _>::try_from_archive(
            archive,
            signer,
            store.clone(),
            NoListener,
            Arc::new(Mutex::new(rand::rngs::OsRng)),
        )
        .await
        .map_err(|e| TestError::Other(e.to_string()))?;

        self.register_instance(hive, name).await
    }

    /// Sends `from`'s events to `to`. Returns how many events `to` could not yet apply.
    ///
    /// Everything `to` is entitled to, including events it already holds. `sync_all_unsent`
    /// is the one that sends only a delta.
    pub async fn sync(&mut self, from: &Instance, to: &Instance) -> TestResult<usize> {
        let events = self.static_events_for_instance(from, to).await?;
        self.deliver(to, events).await
    }

    /// Sends `to` everything the public agent may see, like a sync server.
    pub async fn sync_as_public(&mut self, from: &Instance, to: &Instance) -> TestResult<usize> {
        let individual = Public.individual();
        let public = Agent::Individual(individual.id(), Arc::new(Mutex::new(individual)));
        let events = self.events_for(from, &public).await?;
        self.deliver(to, events).await
    }

    /// Sends everything except one kind of event, to make a dependency visible.
    pub async fn sync_without(
        &mut self,
        from: &Instance,
        to: &Instance,
        kind: EventKind,
    ) -> TestResult<usize> {
        let events: Vec<_> = self
            .static_events_for_instance(from, to)
            .await?
            .into_iter()
            .filter(|(_, event)| EventKind::from(event) != kind)
            .collect();
        self.deliver(to, events).await
    }

    /// Sends everything `batch` events at a time, ingesting each batch before the next.
    pub async fn sync_in_batches(
        &mut self,
        from: &Instance,
        to: &Instance,
        batch: usize,
    ) -> TestResult<usize> {
        assert!(batch > 0, "batch must be at least 1");
        let events = self.static_events_for_instance(from, to).await?;
        let mut pending = 0;
        for chunk in events.chunks(batch) {
            pending = self.deliver(to, chunk.to_vec()).await?;
        }
        Ok(pending)
    }

    /// Sends everything in an order decided by `seed`.
    ///
    /// The same seed permutes the same set of events the same way. It does not reproduce an
    /// order across runs: instances are generated from `OsRng`, so the identities, and
    /// therefore the digests sorted on here, differ every run.
    pub async fn sync_shuffled(
        &mut self,
        from: &Instance,
        to: &Instance,
        seed: u64,
    ) -> TestResult<usize> {
        let mut events = self.static_events_for_instance(from, to).await?;
        // `static_events_for_agent` comes out of a `HashMap`, whose order varies per process.
        // Without this the seed would permute a different starting order every run.
        events.sort_unstable_by_key(|(digest, _)| *digest);
        events.shuffle(&mut StdRng::seed_from_u64(seed));
        self.deliver(to, events).await
    }

    /// How many events the last delivery carried.
    ///
    /// `sync_in_batches` and `sync_all_unsent` deliver more than once, so after those this
    /// is the final batch or the final pair's delta rather than the call's total.
    pub fn events_last_delivered(&self) -> usize {
        self.last_delivery
    }

    /// How many events `who` holds that it cannot yet apply.
    ///
    /// A sum over [`Hive::stats`], which is what a client would read.
    pub async fn pending_event_count(&self, who: &Instance) -> usize {
        let s = who.stats().await;
        (s.pending_prekeys_expanded
            + s.pending_prekey_rotated
            + s.pending_cgka_operation
            + s.pending_delegated
            + s.pending_revoked) as usize
    }

    /// How many events of one kind `who` holds that it cannot yet apply.
    pub async fn pending_events_of_kind(&self, who: &Instance, kind: EventKind) -> usize {
        let s = who.stats().await;
        (match kind {
            EventKind::PrekeysExpanded => s.pending_prekeys_expanded,
            EventKind::PrekeyRotated => s.pending_prekey_rotated,
            EventKind::CgkaOperation => s.pending_cgka_operation,
            EventKind::Delegated => s.pending_delegated,
            EventKind::Revoked => s.pending_revoked,
        }) as usize
    }

    /// What `from` would send `to`, by kind, without sending it.
    ///
    /// This is what `to`'s memberships entitle it to hear about. A sync client wants the
    /// events themselves, from [`Hive::static_events_for_agent`]; a test wants to count them
    /// and say what they were.
    pub async fn event_kinds_for(
        &self,
        from: &Instance,
        to: &Instance,
    ) -> TestResult<Vec<EventKind>> {
        Ok(self
            .static_events_for_instance(from, to)
            .await?
            .iter()
            .map(|(_, event)| EventKind::from(event))
            .collect())
    }

    /// Sends every instance what every other has not yet sent it, repeating until a round
    /// changes nothing.
    ///
    /// Returns an error if the state has not settled after eight rounds.
    pub async fn sync_all_unsent(&mut self) -> TestResult<()> {
        const MAX_ROUNDS: usize = 8;
        let everyone: Vec<Instance> = self.hives.values().cloned().collect();
        let mut before = self.state_signature().await;
        for _ in 0..MAX_ROUNDS {
            for from in &everyone {
                for to in &everyone {
                    if from.instance != to.instance {
                        self.sync_unsent(from, to).await?;
                    }
                }
            }
            let after = self.state_signature().await;
            if after == before {
                return Ok(());
            }
            before = after;
        }
        Err(format!("sync_all_unsent did not settle in {MAX_ROUNDS} rounds").into())
    }

    /// What every instance holds and what it is still waiting on. Two rounds of syncing that
    /// leave this unchanged have moved nothing, and no further round can.
    async fn state_signature(&self) -> u64 {
        let mut hasher = DefaultHasher::new();
        for hive in self.hives.values() {
            hive.stats().await.hash(&mut hasher);
        }
        hasher.finish()
    }

    /// Sends `from`'s events to `to`, skipping any this context has already delivered.
    async fn sync_unsent(&mut self, from: &Instance, to: &Instance) -> TestResult<usize> {
        let known = self.delivered.get(&to.instance);
        let events: Vec<_> = self
            .static_events_for_instance(from, to)
            .await?
            .into_iter()
            .filter(|(digest, _)| known.is_none_or(|seen| !seen.contains(digest)))
            .collect();
        self.deliver(to, events).await
    }

    async fn static_events_for_instance(
        &self,
        from: &Instance,
        to: &Instance,
    ) -> TestResult<Vec<([u8; 32], StaticEvent<[u8; 32]>)>> {
        let to_agent = from
            .get_agent(to.id().into())
            .await
            .ok_or_else(|| TestError::NotSynced(Box::new(to.id().into())))?;
        self.events_for(from, &to_agent).await
    }

    async fn events_for(
        &self,
        from: &Instance,
        agent: &Agent<Sendable, MemorySigner>,
    ) -> TestResult<Vec<([u8; 32], StaticEvent<[u8; 32]>)>> {
        Ok(from
            .static_events_for_agent(agent)
            .await
            .into_iter()
            .map(|(digest, event)| (*digest.raw.as_bytes(), event))
            .collect())
    }

    /// Deliver events and return how many are still waiting on a dependency.
    ///
    /// Records what `to` received so `sync_all_unsent` does not send it again.
    async fn deliver(
        &mut self,
        to: &Instance,
        events: Vec<([u8; 32], StaticEvent<[u8; 32]>)>,
    ) -> TestResult<usize> {
        let (digests, events): (Vec<_>, Vec<_>) = events.into_iter().unzip();
        self.last_delivery = events.len();
        let pending = to.ingest_unsorted_static_events(events).await.len();
        self.delivered
            .entry(to.instance)
            .or_default()
            .extend(digests);
        Ok(pending)
    }

    /// Refuse a name that is already in use.
    ///
    /// Instances are checked separately from `names`, which is keyed by identifier and so
    /// holds only the first instance of each identity.
    fn claim_name(&self, name: &str) -> TestResult<()> {
        let taken = self.names.values().any(|n| &**n == name)
            || self.hives.values().any(|i| i.name() == name);
        if taken {
            return Err(TestError::NameTaken {
                name: name.to_string(),
            });
        }
        Ok(())
    }

    async fn add_instance(&mut self, signer: MemorySigner, name: &str) -> TestResult<Instance> {
        let store = MemoryCiphertextStore::new();
        let hive = Keyhive::generate(signer, store.clone(), NoListener, rand::rngs::OsRng).await?;
        let handle = self.register_instance(hive, name).await?;
        self.stores.insert(handle.instance, store);
        Ok(handle)
    }

    /// The group or document `subject` names, as `observer` holds it.
    async fn membered_handle(
        &self,
        observer: &Instance,
        subject: MemberedId,
    ) -> TestResult<Membered<Sendable, MemorySigner>> {
        match subject {
            MemberedId::DocumentId(id) => observer
                .get_document(id)
                .await
                .map(|d| Membered::Document(id, d))
                .ok_or_else(|| TestError::NotSynced(Box::new(id.into()))),
            MemberedId::GroupId(id) => observer
                .get_group(id)
                .await
                .map(|g| Membered::Group(id, g))
                .ok_or_else(|| TestError::NotSynced(Box::new(id.into()))),
        }
    }

    /// Everyone whose membership in `subject` was revoked and not replaced, with the access
    /// their revoked delegation had conveyed.
    pub async fn revoked_members_of(
        &self,
        observer: &Instance,
        subject: impl Into<MemberedId>,
    ) -> TestResult<BTreeMap<Identifier, Access>> {
        let raw = match self.membered_handle(observer, subject.into()).await? {
            Membered::Group(_, group) => group.lock().await.revoked_members(),
            Membered::Document(_, doc) => doc.lock().await.revoked_members(),
        };
        Ok(raw
            .into_iter()
            .map(|(id, (_, access))| (id, access))
            .collect())
    }

    /// Every delegation `observer` holds for `subject`.
    pub async fn delegations_for(
        &self,
        observer: &Instance,
        subject: impl Into<MemberedId>,
    ) -> TestResult<Vec<DelegationSummary>> {
        let handle = self.membered_handle(observer, subject.into()).await?;
        Ok(handle
            .members()
            .await
            .into_values()
            .flatten()
            .map(|signed| DelegationSummary::from(signed.as_ref()))
            .collect())
    }

    /// Give `to` a copy of the content, which is what an application would do with what it
    /// receives. Content does not travel with the events.
    pub async fn give_content(&self, to: &Instance, ct: &Ciphertext) -> TestResult<()> {
        self.stores
            .get(&to.instance)
            .ok_or_else(|| {
                TestError::Other(format!("{:?} was not built by this TestContext", to.name))
            })?
            .insert(Arc::new(ct.clone()))
            .await;
        Ok(())
    }

    /// Register a new instance and swap contact cards with every other instance.
    ///
    /// Every instance passes through here, so this is where a name is claimed.
    async fn register_instance(&mut self, hive: Hive, name: &str) -> TestResult<Instance> {
        self.claim_name(name)?;
        let card = hive.generate_contact_card().await?;
        for other in self.hives.values() {
            other.receive_contact_card(&card).await?;
            hive.receive_contact_card(&other.generate_contact_card().await?)
                .await?;
        }

        let instance = InstanceId(self.next_instance);
        self.next_instance += 1;
        let handle = Instance {
            hive,
            instance,
            name: name.into(),
        };
        self.hives.insert(instance, handle.clone());
        Ok(handle)
    }
}

impl Dupe for Instance {
    fn dupe(&self) -> Self {
        self.clone()
    }
}

/// Decrypt with a key the test obtained some other way, rather than with one derived through
/// the graph.
pub fn decrypt_with_key(ct: &Ciphertext, key: SymmetricKey) -> TestResult<Vec<u8>> {
    ct.try_decrypt(key)
        .map_err(|e| TestError::Other(format!("decryption with the given key failed: {e}")))
}

/// Reading a [`CausalDecryptionState`] the way a test wants to.
///
/// The state is three collections keyed by content ref. These are the four questions the
/// tests ask of it.
pub trait CausalDecryptionExt {
    /// The content the walk recovered, in no order.
    fn recovered(&self) -> BTreeSet<Vec<u8>>;
    /// How many pieces the walk decrypted, counting repeats.
    fn recovered_count(&self) -> usize;
    /// How many ancestors were listed but not held.
    fn missing(&self) -> usize;
    /// The key the walk reported for an ancestor it could not find.
    fn key_for_missing(&self, ct: &Ciphertext) -> Option<SymmetricKey>;
    /// The key the walk used to read a piece of content.
    fn key_for_recovered(&self, ct: &Ciphertext) -> Option<SymmetricKey>;
}

impl CausalDecryptionExt for CausalDecryptionState<[u8; 32], Vec<u8>> {
    fn recovered(&self) -> BTreeSet<Vec<u8>> {
        self.complete.iter().map(|(_, p)| p.clone()).collect()
    }

    fn recovered_count(&self) -> usize {
        self.complete.len()
    }

    fn missing(&self) -> usize {
        self.next.len()
    }

    fn key_for_missing(&self, ct: &Ciphertext) -> Option<SymmetricKey> {
        self.next.get(&ct.content_ref).copied()
    }

    fn key_for_recovered(&self, ct: &Ciphertext) -> Option<SymmetricKey> {
        self.keys.get(&ct.content_ref).copied()
    }
}
