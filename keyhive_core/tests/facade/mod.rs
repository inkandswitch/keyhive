//! A testing facade for `Keyhive`.

// Each integration test binary compiles the whole facade and uses a subset of it, so
// without this every binary warns about the methods it does not happen to call.
#![allow(dead_code)]

use futures::lock::Mutex;
use keyhive_core::{
    access::Access,
    archive::Archive,
    crypto::envelope::Envelope,
    event::static_event::StaticEvent,
    keyhive::{EncryptContentError, Keyhive},
    listener::no_listener::NoListener,
    principal::{
        agent::Agent,
        document::{id::DocumentId, AddMemberError, DecryptError, Document, GenerateDocError},
        group::{error::AddError, id::GroupId, AddGroupMemberError, RevokeMemberError},
        identifier::Identifier,
        individual::{id::IndividualId, op::KeyOp, Individual, ReceivePrekeyOpError},
        membered::Membered,
        public::Public,
    },
    store::ciphertext::{memory::MemoryCiphertextStore, CiphertextStoreExt},
};
use keyhive_crypto::{
    share_key::ShareKey, signed::SigningError, signer::memory::MemorySigner,
    symmetric_key::SymmetricKey,
};
use nonempty::nonempty;
use rand::{rngs::StdRng, seq::SliceRandom, Rng, SeedableRng};
use std::{
    collections::{hash_map::DefaultHasher, BTreeMap, BTreeSet, HashMap},
    hash::{Hash, Hasher},
    sync::Arc,
};
use thiserror::Error;

type Hive = Keyhive<
    future_form::Sendable,
    MemorySigner,
    [u8; 32],
    Vec<u8>,
    MemoryCiphertextStore<[u8; 32], Vec<u8>>,
    NoListener,
    StdRng,
>;

type AgentHandle = Agent<future_form::Sendable, MemorySigner, [u8; 32], NoListener>;
type MemberedHandle = Membered<future_form::Sendable, MemorySigner, [u8; 32], NoListener>;
type DocHandle = Arc<Mutex<Document<future_form::Sendable, MemorySigner, [u8; 32], NoListener>>>;
type ContentStore = MemoryCiphertextStore<[u8; 32], Vec<u8>>;

pub type Result<T> = std::result::Result<T, TestError>;

/// Why an operation was refused.
#[derive(Debug, Error)]
pub enum TestError {
    /// The issuer holds some access over the resource, but less than they tried to delegate.
    #[error("escalation: wanted {wanted}, holds {held}")]
    Escalation { wanted: Access, held: Access },

    /// The issuer has no access to the resource.
    #[error("no authority over that resource")]
    NoAuthority,

    /// The individual has not yet received the required events. Also returned when they
    /// have no access to the subject and so were never sent it.
    #[error("{individual:?} has not received {subject:?}. Sync first, or check they have access.")]
    NotSynced { individual: String, subject: String },

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

impl From<keyhive_core::keyhive::NotFound> for TestError {
    fn from(e: keyhive_core::keyhive::NotFound) -> Self {
        TestError::Other(e.to_string())
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
            AddMemberError::AddMemberError(inner) => inner.into(),
            other => TestError::Other(other.to_string()),
        }
    }
}

impl From<AddGroupMemberError> for TestError {
    fn from(e: AddGroupMemberError) -> Self {
        match e {
            AddGroupMemberError::AccessEscalation { wanted, have } => {
                TestError::Escalation { wanted, held: have }
            }
            AddGroupMemberError::AddError(AddError::Escelation { claimed, proof }) => {
                TestError::Escalation {
                    wanted: claimed,
                    held: proof,
                }
            }
            AddGroupMemberError::NoProof => TestError::NoAuthority,
            other => TestError::Other(other.to_string()),
        }
    }
}

impl From<RevokeMemberError> for TestError {
    fn from(e: RevokeMemberError) -> Self {
        match e {
            RevokeMemberError::NoProof => TestError::NoAuthority,
            RevokeMemberError::AddError(AddError::Escelation { claimed, proof }) => {
                TestError::Escalation {
                    wanted: claimed,
                    held: proof,
                }
            }
            RevokeMemberError::RedelegationError(inner) => inner.into(),
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
    EncryptContentError,
    ReceivePrekeyOpError,
);

impl From<DecryptError> for TestError {
    fn from(e: DecryptError) -> Self {
        match e {
            DecryptError::KeyNotFound => TestError::NoKey,
            DecryptError::DecryptionFailed(_) | DecryptError::SivMismatch => {
                TestError::CiphertextRejected
            }
            other => TestError::Other(other.to_string()),
        }
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

/// Identifies one `Keyhive` instance. A single keyhive identity can be
/// running more than one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TestInstanceId(u32);

/// A keyhive identity.
#[derive(Clone, Debug)]
pub struct TestIndividual {
    identity: IndividualId,
    instance: TestInstanceId,
    name: Arc<str>,
}

#[derive(Clone, Debug)]
pub struct TestGroup {
    id: GroupId,
    name: Arc<str>,
    owner: TestInstanceId,
}

#[derive(Clone, Debug)]
pub struct TestDocument {
    id: DocumentId,
    name: Arc<str>,
    owner: TestInstanceId,
}

/// Encrypted content with the id for the document it belongs to.
#[derive(Clone)]
pub struct TestEncryptedContent {
    doc: DocumentId,
    inner: beekem::encrypted::EncryptedContent<Vec<u8>, [u8; 32]>,
}

impl std::fmt::Debug for TestEncryptedContent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let r = self.inner.content_ref;
        write!(
            f,
            "TestEncryptedContent({:02x}{:02x}.. in {})",
            r[0], r[1], self.doc
        )
    }
}

#[derive(Clone, Copy, Debug)]
pub struct TestPublic;

const PUBLIC_NAME: &str = "public";

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TestSymmetricKey(SymmetricKey);

impl std::fmt::Debug for TestSymmetricKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let b = self.0.as_slice();
        write!(f, "TestSymmetricKey({:02x}{:02x}..)", b[0], b[1])
    }
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TestDelegation {
    digest: [u8; 32],
    issuer: Arc<str>,
    audience: Arc<str>,
    subject: Arc<str>,
    can: Access,
}

impl TestDelegation {
    /// Who signed it.
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// Who received the access.
    pub fn audience(&self) -> &str {
        &self.audience
    }

    /// The group or document the access is over.
    pub fn subject(&self) -> &str {
        &self.subject
    }

    /// How much access it conveys before attenuation.
    pub fn can(&self) -> Access {
        self.can
    }
}

impl std::fmt::Debug for TestDelegation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}-{:?}->{} over {} ({:02x}{:02x}{:02x}{:02x})",
            self.issuer,
            self.can,
            self.audience,
            self.subject,
            self.digest[0],
            self.digest[1],
            self.digest[2],
            self.digest[3],
        )
    }
}

impl TestEncryptedContent {
    /// The same content with one bit of the ciphertext flipped.
    pub fn with_a_flipped_bit(&self) -> Self {
        let mut copy = self.clone();
        assert!(!copy.inner.ciphertext.is_empty(), "nothing to flip");
        let last = copy.inner.ciphertext.len() - 1;
        copy.inner.ciphertext[last] ^= 1;
        copy
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TestShareKey(ShareKey);

impl std::fmt::Debug for TestShareKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let b = self.0.to_bytes();
        write!(f, "TestShareKey({:02x}{:02x}..)", b[0], b[1])
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TestPrekeyOp {
    Added {
        new: TestShareKey,
    },
    Rotated {
        old: TestShareKey,
        new: TestShareKey,
    },
}

impl TestPrekeyOp {
    /// The key this op introduced.
    pub fn new_key(&self) -> TestShareKey {
        match self {
            TestPrekeyOp::Added { new } | TestPrekeyOp::Rotated { new, .. } => *new,
        }
    }
}

/// What was recovered by walking back through an envelope's ancestors.
#[derive(Clone, Debug)]
pub struct TestCausalDecryption {
    recovered: Vec<Vec<u8>>,
    recovered_keys: BTreeMap<[u8; 32], SymmetricKey>,
    missing: BTreeMap<[u8; 32], SymmetricKey>,
}

impl TestCausalDecryption {
    /// The content recovered by the walk, in no order.
    pub fn recovered(&self) -> BTreeSet<Vec<u8>> {
        self.recovered.iter().cloned().collect()
    }

    /// How many pieces of content the walk decrypted, counting repeats.
    pub fn recovered_count(&self) -> usize {
        self.recovered.len()
    }

    /// How many ancestors were listed but not held. Their keys are known, so they can be
    /// decrypted as soon as they arrive.
    pub fn missing(&self) -> usize {
        self.missing.len()
    }

    /// The key the walk reported for an ancestor it could not find, if it reported one.
    pub fn key_for_missing(&self, ct: &TestEncryptedContent) -> Option<TestSymmetricKey> {
        self.missing
            .get(&ct.inner.content_ref)
            .copied()
            .map(TestSymmetricKey)
    }

    /// The key the walk used to read a piece of content, if it read it.
    pub fn key_for_recovered(&self, ct: &TestEncryptedContent) -> Option<TestSymmetricKey> {
        self.recovered_keys
            .get(&ct.inner.content_ref)
            .copied()
            .map(TestSymmetricKey)
    }
}

/// A serialized `Keyhive`.
#[derive(Clone)]
pub struct TestArchive {
    identity: IndividualId,
    inner: Archive<[u8; 32]>,
}

#[derive(Clone, Debug)]
pub struct TestStaticEvent {
    kind: TestEventKind,
}

impl TestStaticEvent {
    pub fn kind(&self) -> TestEventKind {
        self.kind
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TestEventKind {
    PrekeysExpanded,
    PrekeyRotated,
    CgkaOperation,
    Delegated,
    Revoked,
}

fn kind_of(event: &StaticEvent<[u8; 32]>) -> TestEventKind {
    match event {
        StaticEvent::PrekeysExpanded(_) => TestEventKind::PrekeysExpanded,
        StaticEvent::PrekeyRotated(_) => TestEventKind::PrekeyRotated,
        StaticEvent::CgkaOperation(_) => TestEventKind::CgkaOperation,
        StaticEvent::Delegated(_) => TestEventKind::Delegated,
        StaticEvent::Revoked(_) => TestEventKind::Revoked,
    }
}

impl TestIndividual {
    pub fn name(&self) -> &str {
        &self.name
    }
}
impl TestGroup {
    pub fn name(&self) -> &str {
        &self.name
    }
}
impl TestDocument {
    pub fn name(&self) -> &str {
        &self.name
    }
}

/// Anything a delegation can be addressed to: an individual, a group, a document, or public.
pub trait TestAgent {
    fn agent_id(&self) -> Identifier;
    fn name(&self) -> &str;
}

/// Anything that can have members: a group or a document.
pub trait TestMembered: TestAgent {
    #[doc(hidden)]
    fn as_membered(&self) -> TestMemberedRef<'_>;

    /// The instance that created it, which is the one whose view is authoritative.
    #[doc(hidden)]
    fn owner(&self) -> TestInstanceId;
}

#[doc(hidden)]
pub enum TestMemberedRef<'a> {
    Group(&'a TestGroup),
    Doc(&'a TestDocument),
}

impl TestAgent for TestIndividual {
    fn agent_id(&self) -> Identifier {
        self.identity.into()
    }
    fn name(&self) -> &str {
        &self.name
    }
}
impl TestAgent for TestGroup {
    fn agent_id(&self) -> Identifier {
        self.id.into()
    }
    fn name(&self) -> &str {
        &self.name
    }
}
impl TestAgent for TestDocument {
    fn agent_id(&self) -> Identifier {
        self.id.into()
    }
    fn name(&self) -> &str {
        &self.name
    }
}

impl TestAgent for TestPublic {
    fn agent_id(&self) -> Identifier {
        Public.id()
    }
    fn name(&self) -> &str {
        PUBLIC_NAME
    }
}

impl TestMembered for TestGroup {
    fn as_membered(&self) -> TestMemberedRef<'_> {
        TestMemberedRef::Group(self)
    }
    fn owner(&self) -> TestInstanceId {
        self.owner
    }
}
impl TestMembered for TestDocument {
    fn as_membered(&self) -> TestMemberedRef<'_> {
        TestMemberedRef::Doc(self)
    }
    fn owner(&self) -> TestInstanceId {
        self.owner
    }
}

/// A set of individuals, groups and documents, with one `Keyhive` instance per individual.
pub struct TestContext {
    hives: BTreeMap<TestInstanceId, Hive>,
    /// One signing key per identity. A second instance can be given the same one.
    signers: BTreeMap<IndividualId, MemorySigner>,
    handles: BTreeMap<TestInstanceId, TestIndividual>,
    next_instance: u32,
    names: BTreeMap<Identifier, Arc<str>>,
    csprng: StdRng,
    docs: Vec<TestDocument>,
    /// The digests each instance has already received, so `sync_all_unsent` sends a delta.
    delivered: BTreeMap<TestInstanceId, BTreeSet<[u8; 32]>>,
    /// How many events were last delivered.
    last_delivery: usize,
    /// Each instance's ciphertext store. Storing what you wrote or received is the
    /// application's role, and causal decryption reads back out of it.
    stores: BTreeMap<TestInstanceId, ContentStore>,
}

impl TestContext {
    pub async fn new() -> Self {
        let mut names = BTreeMap::new();
        names.insert(Public.id(), PUBLIC_NAME.into());
        TestContext {
            hives: BTreeMap::new(),
            signers: BTreeMap::new(),
            handles: BTreeMap::new(),
            next_instance: 0,
            names,
            docs: Vec::new(),
            delivered: BTreeMap::new(),
            last_delivery: 0,
            stores: BTreeMap::new(),
            csprng: StdRng::from_rng(rand::rngs::OsRng).expect("OsRng cannot fail"),
        }
    }

    pub fn public(&self) -> TestPublic {
        TestPublic
    }

    /// Create a keyhive identity.
    ///
    /// Every individual learns every other individual's contact card.
    pub async fn individual(&mut self, name: &str) -> Result<TestIndividual> {
        let mut hive_rng = StdRng::seed_from_u64(self.csprng.gen());
        let signer = MemorySigner::generate(&mut hive_rng);
        let handle = self.add_instance(signer.clone(), hive_rng, name).await?;
        self.signers.insert(handle.identity, signer);
        self.names
            .insert(handle.identity.into(), handle.name.clone());
        Ok(handle)
    }

    /// A second `Keyhive` for an existing identity, sharing its signing key.
    pub async fn second_instance(
        &mut self,
        of: &TestIndividual,
        name: &str,
    ) -> Result<TestIndividual> {
        let signer = self
            .signers
            .get(&of.identity)
            .ok_or_else(|| format!("{:?} was not created by this TestContext", of.name))?
            .clone();
        let hive_rng = StdRng::seed_from_u64(self.csprng.gen());
        let handle = self.add_instance(signer, hive_rng, name).await?;
        assert_eq!(handle.identity, of.identity);
        Ok(handle)
    }

    /// Give one instance's prekey secrets to another instance of the same identity.
    ///
    /// An invitation is addressed to one specific prekey, so an instance can't open one
    /// aimed at a sibling's prekey until it has that sibling's secrets. Returns how many
    /// events `to` was holding that it could then apply.
    pub async fn share_prekey_secrets(
        &mut self,
        from: &TestIndividual,
        to: &TestIndividual,
    ) -> Result<usize> {
        if from.identity != to.identity {
            return Err(TestError::DifferentIdentity {
                from: from.name.to_string(),
                to: to.name.to_string(),
            });
        }
        let blob = self
            .hive(from)?
            .export_prekey_secrets()
            .await
            .map_err(|e| TestError::Other(e.to_string()))?;
        let before = self.pending_events(to).await?;
        self.hive(to)?
            .import_prekey_secrets(&blob)
            .await
            .map_err(|e| TestError::Other(e.to_string()))?;
        Ok(before.saturating_sub(self.pending_events(to).await?))
    }

    pub async fn group(&mut self, owner: &TestIndividual, name: &str) -> Result<TestGroup> {
        self.claim_name(name)?;
        let g = self.hive(owner)?.generate_group(vec![]).await?;
        let id = { g.lock().await.group_id() };
        let name: Arc<str> = name.into();
        self.names.insert(id.into(), name.clone());
        Ok(TestGroup {
            id,
            name,
            owner: owner.instance,
        })
    }

    pub async fn doc(&mut self, owner: &TestIndividual, name: &str) -> Result<TestDocument> {
        self.claim_name(name)?;
        let d = self
            .hive(owner)?
            .generate_doc(vec![], nonempty![[0u8; 32]])
            .await?;
        let id = { d.lock().await.doc_id() };
        let name: Arc<str> = name.into();
        self.names.insert(id.into(), name.clone());
        let handle = TestDocument {
            id,
            name,
            owner: owner.instance,
        };
        self.docs.push(handle.clone());
        Ok(handle)
    }

    /// `issuer` delegates `can` over `membered` to `audience`.
    ///
    /// Signed by the issuer. Returns an error if the issuer may not do this.
    pub async fn delegate(
        &self,
        issuer: &TestIndividual,
        audience: &impl TestAgent,
        membered: &impl TestMembered,
        can: Access,
    ) -> Result<TestDelegation> {
        let hive = self.hive(issuer)?;
        let aud = self
            .get_agent(issuer, audience.agent_id(), audience.name())
            .await?;
        let res = self.get_membered(issuer, membered).await?;
        let relevant = self.other_relevant_docs(issuer, membered).await;
        let update = hive
            .add_member(aud.id(), res.membered_id(), can, &relevant)
            .await?;
        Ok(TestDelegation {
            digest: *update.delegation.digest().raw.as_bytes(),
            // The identity's name, not this instance's.
            issuer: self.name_of(issuer.identity.into()),
            audience: self.name_of(audience.agent_id()),
            subject: self.name_of(membered.agent_id()),
            can,
        })
    }

    /// `issuer` removes `audience`'s membership in `membered`, keeping everyone else.
    ///
    /// Members `audience` had admitted keep their access, because their delegations are
    /// re-issued under the issuer.
    pub async fn revoke(
        &self,
        issuer: &TestIndividual,
        audience: &impl TestAgent,
        membered: &impl TestMembered,
    ) -> Result<()> {
        self.revoke_inner(issuer, audience, membered, true).await
    }

    /// `issuer` removes `audience`, and everyone whose only way in was through them.
    pub async fn revoke_cascading(
        &self,
        issuer: &TestIndividual,
        audience: &impl TestAgent,
        membered: &impl TestMembered,
    ) -> Result<()> {
        self.revoke_inner(issuer, audience, membered, false).await
    }

    async fn revoke_inner(
        &self,
        issuer: &TestIndividual,
        audience: &impl TestAgent,
        membered: &impl TestMembered,
        retain_all_other_members: bool,
    ) -> Result<()> {
        let hive = self.hive(issuer)?;
        let res = self.get_membered(issuer, membered).await?;
        hive.revoke_member(
            audience.agent_id(),
            retain_all_other_members,
            res.membered_id(),
        )
        .await?;
        Ok(())
    }

    /// The access level keyhive claims `who` has over `doc`, according to the
    /// document owner's instance. `None` means no access.
    pub async fn effective_access(
        &self,
        who: &impl TestAgent,
        doc: &TestDocument,
    ) -> Result<Option<Access>> {
        let observer = self.individual_by_instance(doc.owner)?;
        self.effective_access_seen_by(&observer, who, doc).await
    }

    /// The access level keyhive claims `who` has over `doc`, according to
    /// `observer`'s instance. Use this to check that two individuals agree.
    pub async fn effective_access_seen_by(
        &self,
        observer: &TestIndividual,
        who: &impl TestAgent,
        doc: &TestDocument,
    ) -> Result<Option<Access>> {
        let hive = self.hive(observer)?;
        let agent = self.get_agent(observer, who.agent_id(), who.name()).await?;
        Ok(hive
            .docs_reachable_by_agent(agent.id())
            .await?
            .get(&doc.id)
            .copied())
    }

    /// The groups and documents `audience` reaches, as `observer` sees it, and at what level.
    pub async fn memberships_reachable_by(
        &self,
        observer: &TestIndividual,
        audience: &impl TestAgent,
    ) -> Result<BTreeMap<String, Access>> {
        let aud = self
            .get_agent(observer, audience.agent_id(), audience.name())
            .await?;
        Ok(self
            .hive(observer)?
            .membered_reachable_by_agent(aud.id())
            .await?
            .into_iter()
            .map(|(id, access)| (self.name_of(id.into()).to_string(), access))
            .collect())
    }

    /// The documents `who` reaches, as `observer` sees it, and at what level.
    ///
    /// A document delegated to Public is not included unless it's passed as `who`.
    pub async fn documents_reachable_by(
        &self,
        observer: &TestIndividual,
        who: &impl TestAgent,
    ) -> Result<BTreeMap<String, Access>> {
        let hive = self.hive(observer)?;
        let aud = self.get_agent(observer, who.agent_id(), who.name()).await?;
        Ok(hive
            .docs_reachable_by_agent(aud.id())
            .await?
            .into_iter()
            .map(|(id, access)| (self.name_of(id.into()).to_string(), access))
            .collect())
    }

    /// Everyone who can reach `membered`, including through nested groups.
    pub async fn transitive_members_of(
        &self,
        membered: &impl TestMembered,
    ) -> Result<BTreeMap<String, Access>> {
        let observer = self.individual_by_instance(membered.owner())?;
        // Resolved first so an unsynced subject is reported by name rather than as a bare
        // identifier, which is all the library's own lookup failure carries.
        let handle = self.get_membered(&observer, membered).await?;
        let raw = self
            .hive(&observer)?
            .reachable_members(handle.membered_id())
            .await?;

        Ok(raw
            .into_iter()
            .map(|(id, member)| (self.name_of(id).to_string(), member.can))
            .collect())
    }

    /// Everyone whose membership in `membered` was revoked and not replaced, with the
    /// access their revoked delegation had conveyed.
    ///
    /// Someone who was revoked and then delegated again is excluded from this result.
    pub async fn revoked_members_of(
        &self,
        membered: &impl TestMembered,
    ) -> Result<BTreeMap<String, Access>> {
        let observer = self.individual_by_instance(membered.owner())?;
        let raw = match self.get_membered(&observer, membered).await? {
            Membered::Group(_, group) => group.lock().await.revoked_members(),
            Membered::Document(_, doc) => doc.lock().await.revoked_members(),
        };
        Ok(raw
            .into_iter()
            .map(|(id, (_, access))| (self.name_of(id).to_string(), access))
            .collect())
    }

    /// Every delegation `observer` holds for `membered`.
    pub async fn delegations_for(
        &self,
        observer: &TestIndividual,
        membered: &impl TestMembered,
    ) -> Result<Vec<TestDelegation>> {
        let handle = self.get_membered(observer, membered).await?;
        let subject = self.name_of(membered.agent_id());
        let mut out = vec![];
        for signed in handle.members().await.values().flat_map(|d| d.iter()) {
            let issuer = Identifier::from(signed.issuer());
            let audience = signed.payload().delegate().id();
            out.push(TestDelegation {
                digest: *signed.digest().raw.as_bytes(),
                issuer: self.name_of(issuer),
                audience: self.name_of(audience),
                subject: subject.clone(),
                can: signed.payload().can(),
            });
        }
        Ok(out)
    }

    /// The content `who` reads back, or an error if they cannot read it.
    ///
    /// For content written with `encrypt_in_envelope` this is the envelope rather than the
    /// payload since unwrapping it is `causal_decrypt`'s role.
    pub async fn read(&self, who: &TestIndividual, ct: &TestEncryptedContent) -> Result<Vec<u8>> {
        // Resolved first so a document this instance has never received is reported as
        // such, rather than as a decryption failure.
        self.get_document_by_id(who, ct.doc, "that document")
            .await?;
        Ok(self
            .hive(who)?
            .try_decrypt_content(ct.doc, &ct.inner)
            .await?)
    }

    /// Whether `who` can actually decrypt the encrypted content.
    pub async fn can_decrypt(
        &self,
        who: &TestIndividual,
        ct: &TestEncryptedContent,
    ) -> Result<bool> {
        Ok(self.read(who, ct).await.is_ok())
    }

    /// The higher of `who`'s own access and public's access.
    pub async fn best_access(
        &self,
        who: &impl TestAgent,
        doc: &TestDocument,
    ) -> Result<Option<Access>> {
        let observer = self.individual_by_instance(doc.owner)?;
        // Resolved first, for the same reason as `transitive_members_of`.
        let handle = self.get_membered(&observer, doc).await?;
        let members = self
            .hive(&observer)?
            .reachable_members(handle.membered_id())
            .await?;
        let direct = members.get(&who.agent_id()).map(|m| m.can);
        let public = members.get(&Public.id()).map(|m| m.can);
        // None sorts below every Some, so this is "the better of the two, if either".
        Ok(direct.max(public))
    }

    /// Whether `who` has received the events needed to learn about `what`.
    ///
    /// `effective_access` returns `None` both for no access and for never having heard of
    /// the subject. This method can distinguish those cases.
    pub async fn has_received(&self, who: &TestIndividual, what: &impl TestAgent) -> Result<bool> {
        Ok(self.hive(who)?.get_agent(what.agent_id()).await.is_some())
    }

    /// The application secret `who` derives for this content, or `None` if they cannot.
    pub async fn derived_key(
        &self,
        who: &TestIndividual,
        ct: &TestEncryptedContent,
    ) -> Result<Option<TestSymmetricKey>> {
        let Ok(_) = self.get_document_by_id(who, ct.doc, "that document").await else {
            return Ok(None);
        };
        Ok(self
            .hive(who)?
            .try_decrypt_content_keyed(ct.doc, &ct.inner)
            .await
            .ok()
            .map(|(_, key)| TestSymmetricKey(key)))
    }

    /// Decrypt with a key the test obtained some other way, rather than with one derived
    /// through the graph.
    pub fn decrypt_with_key(
        &self,
        ct: &TestEncryptedContent,
        key: &TestSymmetricKey,
    ) -> Result<Vec<u8>> {
        ct.inner
            .try_decrypt(key.0)
            .map_err(|e| TestError::Other(format!("decryption with the given key failed: {e}")))
    }

    pub async fn encrypt(
        &self,
        who: &TestIndividual,
        doc: &TestDocument,
        content: &[u8],
    ) -> Result<TestEncryptedContent> {
        Ok(self.encrypt_keyed(who, doc, content).await?.0)
    }

    /// Encrypt content that follows `after` in the document's content DAG.
    pub async fn encrypt_after(
        &self,
        who: &TestIndividual,
        doc: &TestDocument,
        after: &[&TestEncryptedContent],
        content: &[u8],
    ) -> Result<TestEncryptedContent> {
        let mut pred_refs = Vec::with_capacity(after.len());
        for pred in after {
            if pred.doc != doc.id {
                return Err(TestError::WrongDocument {
                    holds: self.name_of(pred.doc.into()).to_string(),
                    doc: doc.name.to_string(),
                });
            }
            pred_refs.push(pred.inner.content_ref);
        }
        self.get_document(who, doc).await?;
        let content_ref: [u8; 32] = blake3::hash(content).into();
        let out = self
            .hive(who)?
            .try_encrypt_content(doc.id, &content_ref, &pred_refs, content)
            .await?;
        Ok(TestEncryptedContent {
            doc: doc.id,
            inner: out.encrypted_content().clone(),
        })
    }

    /// Write `content` in an envelope listing the ancestors and carrying the keys to open
    /// them. Simulates what an application would do.
    pub async fn encrypt_in_envelope(
        &self,
        who: &TestIndividual,
        doc: &TestDocument,
        after: &[&TestEncryptedContent],
        content: &[u8],
    ) -> Result<TestEncryptedContent> {
        let mut ancestors = HashMap::with_capacity(after.len());
        for pred in after {
            let key = self.derived_key(who, pred).await?.ok_or(TestError::NoKey)?;
            ancestors.insert(pred.inner.content_ref, key.0);
        }
        let envelope = Envelope {
            plaintext: content.to_vec(),
            ancestors,
        };
        let bytes = bincode::serialize(&envelope)
            .map_err(|e| TestError::Other(format!("could not serialize an envelope: {e}")))?;

        let out = self.encrypt_after(who, doc, after, &bytes).await?;
        self.deliver_content(who, &out).await?;
        Ok(out)
    }

    /// Give `to` a copy of the content, simulating how an application would behave.
    pub async fn deliver_content(
        &self,
        to: &TestIndividual,
        ct: &TestEncryptedContent,
    ) -> Result<()> {
        self.stores
            .get(&to.instance)
            .ok_or_else(|| format!("{:?} is not in this TestContext", to.name))?
            .insert(Arc::new(ct.inner.clone()))
            .await;
        Ok(())
    }

    /// Walk back from `ct` through the ancestors it lists, decrypting what `who` holds.
    ///
    /// Reports what it recovered and what it could not find.
    pub async fn causal_decrypt(
        &self,
        who: &TestIndividual,
        ct: &TestEncryptedContent,
    ) -> Result<TestCausalDecryption> {
        // Resolved first so a document this instance has never received is reported as
        // such rather than as a decryption failure.
        self.get_document_by_id(who, ct.doc, "that document")
            .await?;
        let state = self
            .hive(who)?
            .try_causal_decrypt_content(ct.doc, &ct.inner)
            .await
            .map_err(|e| TestError::Other(e.to_string()))?;
        Ok(TestCausalDecryption {
            recovered: state.complete.into_iter().map(|(_, p)| p).collect(),
            recovered_keys: state.keys.into_iter().collect(),
            missing: state.next.into_iter().collect(),
        })
    }

    /// Walk back from more than one entrypoint at once.
    ///
    /// `Keyhive::try_causal_decrypt_content` takes a single entrypoint. A reader holding
    /// several heads walks from all of them together, and a shared ancestor should be read
    /// once rather than once per head.
    ///
    /// The recovered set includes the entrypoints themselves, unlike `causal_decrypt`.
    pub async fn causal_decrypt_from(
        &self,
        who: &TestIndividual,
        entrypoints: &[&TestEncryptedContent],
    ) -> Result<TestCausalDecryption> {
        let mut to_walk = Vec::new();
        for ct in entrypoints {
            let key = self.derived_key(who, ct).await?.ok_or(TestError::NoKey)?;
            to_walk.push((Arc::new(ct.inner.clone()), key.0));
        }
        let store = self
            .stores
            .get(&who.instance)
            .ok_or_else(|| format!("{:?} is not in this TestContext", who.name))?;
        let state = CiphertextStoreExt::<future_form::Sendable, _, _>::try_causal_decrypt(
            store,
            &mut to_walk,
        )
        .await
        .map_err(|e| TestError::Other(e.to_string()))?;
        Ok(TestCausalDecryption {
            recovered: state.complete.into_iter().map(|(_, p)| p).collect(),
            recovered_keys: state.keys.into_iter().collect(),
            missing: state.next.into_iter().collect(),
        })
    }

    /// Encrypt content. Returns the content and the application secret it went under.
    pub async fn encrypt_keyed(
        &self,
        who: &TestIndividual,
        doc: &TestDocument,
        content: &[u8],
    ) -> Result<(TestEncryptedContent, TestSymmetricKey)> {
        self.get_document(who, doc).await?;
        let content_ref: [u8; 32] = blake3::hash(content).into();
        let (out, key) = self
            .hive(who)?
            .try_encrypt_content_keyed(doc.id, &content_ref, &vec![], content)
            .await?;
        Ok((
            TestEncryptedContent {
                doc: doc.id,
                inner: out.encrypted_content().clone(),
            },
            TestSymmetricKey(key),
        ))
    }

    /// Force PCS update on `doc`. Returns the share key the rotation introduced.
    pub async fn force_pcs_update(
        &self,
        who: &TestIndividual,
        doc: &TestDocument,
    ) -> Result<TestShareKey> {
        let handle = self.get_document(who, doc).await?;
        let (_op, new_key, _secret) = self
            .hive(who)?
            .force_pcs_update(handle)
            .await
            .map_err(|e| TestError::Other(e.to_string()))?;
        Ok(TestShareKey(new_key))
    }

    /// Add a prekey. Returns the key that was added.
    pub async fn expand_prekeys(&self, who: &TestIndividual) -> Result<TestShareKey> {
        let op = self.hive(who)?.expand_prekeys().await?;
        Ok(TestShareKey(op.payload().share_key))
    }

    /// Replace `old` with a fresh key. Returns the key that replaced it.
    pub async fn rotate_prekey(
        &self,
        who: &TestIndividual,
        old: &TestShareKey,
    ) -> Result<TestShareKey> {
        let op = self.hive(who)?.rotate_prekey(old.0).await?;
        Ok(TestShareKey(op.payload().new))
    }

    /// The prekeys `observer` holds for `of`.
    pub async fn prekeys(
        &self,
        observer: &TestIndividual,
        of: &TestIndividual,
    ) -> Result<BTreeSet<TestShareKey>> {
        let indie = self.get_individual(observer, of).await?;
        let locked = indie.lock().await;
        Ok(locked.prekeys().iter().copied().map(TestShareKey).collect())
    }

    /// The prekey ops `observer` holds for `of`.
    pub async fn prekey_ops(
        &self,
        observer: &TestIndividual,
        of: &TestIndividual,
    ) -> Result<Vec<TestPrekeyOp>> {
        let indie = self.get_individual(observer, of).await?;
        let locked = indie.lock().await;
        Ok(locked
            .prekey_ops()
            .values()
            .map(|op| match op.as_ref() {
                KeyOp::Add(add) => TestPrekeyOp::Added {
                    new: TestShareKey(add.payload().share_key),
                },
                KeyOp::Rotate(rot) => TestPrekeyOp::Rotated {
                    old: TestShareKey(rot.payload().old),
                    new: TestShareKey(rot.payload().new),
                },
            })
            .collect())
    }

    /// Serialize `who`'s instance.
    pub async fn archive(&self, who: &TestIndividual) -> Result<TestArchive> {
        Ok(TestArchive {
            identity: who.identity,
            inner: self.hive(who)?.into_archive().await,
        })
    }

    /// Rebuild an instance from an archive, as a new instance of the same identity.
    ///
    /// The restored instance gets a fresh ciphertext store.
    pub async fn rebuild_from_archive(
        &mut self,
        archive: &TestArchive,
        name: &str,
    ) -> Result<TestIndividual> {
        let signer = self
            .signers
            .get(&archive.identity)
            .ok_or("that archive's identity was not created by this TestContext")?
            .clone();
        let store = ContentStore::new();
        let hive = Keyhive::<future_form::Sendable, _, _, _, _, _, _>::try_from_archive(
            &archive.inner,
            signer,
            store.clone(),
            NoListener,
            Arc::new(Mutex::new(StdRng::seed_from_u64(self.csprng.gen()))),
        )
        .await
        .map_err(|e| TestError::Other(e.to_string()))?;

        self.register_instance(hive, store, name).await
    }

    /// Merge an archive into a live instance. Returns how many events remain pending.
    pub async fn ingest_archive(
        &mut self,
        into: &TestIndividual,
        archive: TestArchive,
    ) -> Result<usize> {
        Ok(self
            .hive(into)?
            .ingest_archive(archive.inner)
            .await
            .map_err(|e| TestError::Other(e.to_string()))?
            .len())
    }

    /// Sends `from`'s events to `to`. Returns how many events `to` could not yet apply.
    ///
    /// Everything `to` is entitled to, including events it already holds.
    pub async fn sync(&mut self, from: &TestIndividual, to: &TestIndividual) -> Result<usize> {
        let events = self.static_events_for_agent(from, to).await?;
        self.deliver(to, events).await
    }

    /// Sends `from`'s events to `to`, skipping any this context has already delivered.
    async fn sync_unsent(&mut self, from: &TestIndividual, to: &TestIndividual) -> Result<usize> {
        let known = self.delivered.get(&to.instance);
        let events: Vec<_> = self
            .static_events_for_agent(from, to)
            .await?
            .into_iter()
            .filter(|(digest, _)| known.is_none_or(|seen| !seen.contains(digest)))
            .collect();
        self.deliver(to, events).await
    }

    /// Sends `to` everything the public agent may see, like a sync server.
    pub async fn sync_as_public(
        &mut self,
        from: &TestIndividual,
        to: &TestIndividual,
    ) -> Result<usize> {
        let individual = Public.individual();
        let public = Agent::Individual(individual.id(), Arc::new(Mutex::new(individual)));
        let events = self.events_for(from, &public).await?;
        self.deliver(to, events).await
    }

    /// Sends everything except one kind of event, to make a dependency visible.
    pub async fn sync_without(
        &mut self,
        from: &TestIndividual,
        to: &TestIndividual,
        kind: TestEventKind,
    ) -> Result<usize> {
        let events: Vec<_> = self
            .static_events_for_agent(from, to)
            .await?
            .into_iter()
            .filter(|(_, event)| kind_of(event) != kind)
            .collect();
        self.deliver(to, events).await
    }

    /// Sends everything `batch` events at a time, ingesting each batch before the next.
    pub async fn sync_in_batches(
        &mut self,
        from: &TestIndividual,
        to: &TestIndividual,
        batch: usize,
    ) -> Result<usize> {
        assert!(batch > 0, "batch must be at least 1");
        let events = self.static_events_for_agent(from, to).await?;
        let mut pending = 0;
        for chunk in events.chunks(batch) {
            pending = self.deliver(to, chunk.to_vec()).await?;
        }
        Ok(pending)
    }

    /// Sends everything in an order decided by `seed`.
    ///
    /// The same seed permutes the same set of events the same way. It does not reproduce an
    /// order across runs: `TestContext::new` seeds itself from `OsRng`, so the identities,
    /// and therefore the digests sorted on here, differ every run.
    pub async fn sync_shuffled(
        &mut self,
        from: &TestIndividual,
        to: &TestIndividual,
        seed: u64,
    ) -> Result<usize> {
        let mut events = self.static_events_for_agent(from, to).await?;
        // `static_events_for_agent` comes out of a `HashMap`, whose order varies per process.
        // Without this the seed would permute a different starting order every run.
        events.sort_unstable_by_key(|(digest, _)| *digest);
        events.shuffle(&mut StdRng::seed_from_u64(seed));
        self.deliver(to, events).await
    }

    /// What `from` would send `to`, without sending it. This is what `to`'s memberships
    /// entitle it to hear about.
    pub async fn static_events_for(
        &self,
        from: &TestIndividual,
        to: &TestIndividual,
    ) -> Result<Vec<TestStaticEvent>> {
        Ok(self
            .static_events_for_agent(from, to)
            .await?
            .iter()
            .map(|(_, event)| TestStaticEvent {
                kind: kind_of(event),
            })
            .collect())
    }

    /// How many events the last delivery carried.
    ///
    /// `sync_in_batches` and `sync_all_unsent` deliver more than once, so after those this
    /// is the final batch or the final pair's delta rather than the call's total.
    pub fn events_last_delivered(&self) -> usize {
        self.last_delivery
    }

    /// How many events of one kind `who` has that it cannot yet apply.
    pub async fn pending_events_of_kind(
        &self,
        who: &TestIndividual,
        kind: TestEventKind,
    ) -> Result<usize> {
        let s = self.hive(who)?.stats().await;
        Ok(match kind {
            TestEventKind::PrekeysExpanded => s.pending_prekeys_expanded,
            TestEventKind::PrekeyRotated => s.pending_prekey_rotated,
            TestEventKind::CgkaOperation => s.pending_cgka_operation,
            TestEventKind::Delegated => s.pending_delegated,
            TestEventKind::Revoked => s.pending_revoked,
        } as usize)
    }

    /// How many events `who` has that it cannot yet apply.
    pub async fn pending_events(&self, who: &TestIndividual) -> Result<usize> {
        let s = self.hive(who)?.stats().await;
        Ok((s.pending_prekeys_expanded
            + s.pending_prekey_rotated
            + s.pending_cgka_operation
            + s.pending_delegated
            + s.pending_revoked) as usize)
    }

    /// Sends every individual what every other has not yet sent them, repeating until a
    /// round changes nothing.
    ///
    /// Returns an error if the state has not settled after eight rounds.
    pub async fn sync_all_unsent(&mut self) -> Result<()> {
        const MAX_ROUNDS: usize = 8;
        let everyone: Vec<TestIndividual> = self.handles.values().cloned().collect();
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

    /////////////////////
    // Internal details
    /////////////////////

    /// What every instance holds and what it is still waiting on. Two rounds of syncing
    /// that leave this unchanged have moved nothing, and no further round can.
    async fn state_signature(&self) -> u64 {
        let mut hasher = DefaultHasher::new();
        for hive in self.hives.values() {
            hive.stats().await.hash(&mut hasher);
        }
        hasher.finish()
    }

    /// Everything `to`'s memberships entitle it to hear about, each with its digest.
    async fn static_events_for_agent(
        &self,
        from: &TestIndividual,
        to: &TestIndividual,
    ) -> Result<Vec<([u8; 32], StaticEvent<[u8; 32]>)>> {
        let to_agent = self.get_agent(from, to.identity.into(), &to.name).await?;
        self.events_for(from, &to_agent).await
    }

    /// Everything `agent`'s memberships entitle it to hear about, each with its digest.
    ///
    /// Unlike `static_events_for_agent`, this can be an agent unknown to the `TestContext`.
    async fn events_for(
        &self,
        from: &TestIndividual,
        agent: &AgentHandle,
    ) -> Result<Vec<([u8; 32], StaticEvent<[u8; 32]>)>> {
        Ok(self
            .hive(from)?
            .static_events_for_agent(agent)
            .await
            .into_iter()
            .map(|(digest, event)| (*digest.raw.as_bytes(), event))
            .collect())
    }

    /// Deliver events and return a count of how many are still waiting on a dependency.
    ///
    /// Records what `to` received so `sync` does not send it again.
    async fn deliver(
        &mut self,
        to: &TestIndividual,
        events: Vec<([u8; 32], StaticEvent<[u8; 32]>)>,
    ) -> Result<usize> {
        let (digests, events): (Vec<_>, Vec<_>) = events.into_iter().unzip();
        self.last_delivery = events.len();
        let pending = self
            .hive(to)?
            .ingest_unsorted_static_events(events)
            .await
            .len();
        self.delivered
            .entry(to.instance)
            .or_default()
            .extend(digests);
        Ok(pending)
    }

    /// Refuse a name that is already in use.
    fn claim_name(&self, name: &str) -> Result<()> {
        let taken = self.names.values().any(|n| &**n == name)
            || self.handles.values().any(|h| &*h.name == name);
        if taken {
            return Err(TestError::NameTaken {
                name: name.to_string(),
            });
        }
        Ok(())
    }

    /// The name this context knows `id` by, or the id itself if it knows none.
    fn name_of(&self, id: Identifier) -> Arc<str> {
        self.names
            .get(&id)
            .cloned()
            .unwrap_or_else(|| id.to_string().into())
    }

    fn hive(&self, who: &TestIndividual) -> Result<&Hive> {
        self.hives
            .get(&who.instance)
            .ok_or_else(|| format!("{:?} is not in this TestContext", who.name).into())
    }

    fn individual_by_instance(&self, instance: TestInstanceId) -> Result<TestIndividual> {
        self.handles
            .get(&instance)
            .cloned()
            .ok_or_else(|| "unknown instance".into())
    }

    /// `observer`'s copy of what it knows about the person `of`.
    async fn get_individual(
        &self,
        observer: &TestIndividual,
        of: &TestIndividual,
    ) -> Result<Arc<Mutex<Individual>>> {
        self.hive(observer)?
            .get_individual(of.identity)
            .await
            .ok_or_else(|| TestError::NotSynced {
                individual: observer.name.to_string(),
                subject: of.name.to_string(),
            })
    }

    async fn add_instance(
        &mut self,
        signer: MemorySigner,
        rng: StdRng,
        name: &str,
    ) -> Result<TestIndividual> {
        let store = ContentStore::new();
        let hive = Keyhive::<future_form::Sendable, _, _, _, _, _, _>::generate(
            signer,
            store.clone(),
            NoListener,
            rng,
        )
        .await?;

        self.register_instance(hive, store, name).await
    }

    /// Register a new instance and swap contact cards with every other instance.
    async fn register_instance(
        &mut self,
        hive: Hive,
        store: ContentStore,
        name: &str,
    ) -> Result<TestIndividual> {
        self.claim_name(name)?;
        let card = hive.generate_contact_card().await?;
        for other in self.hives.values() {
            other.receive_contact_card(&card).await?;
            hive.receive_contact_card(&other.generate_contact_card().await?)
                .await?;
        }

        let identity = hive.id();
        let instance = TestInstanceId(self.next_instance);
        self.next_instance += 1;
        self.hives.insert(instance, hive);
        self.stores.insert(instance, store);
        let handle = TestIndividual {
            identity,
            instance,
            name: name.into(),
        };
        self.handles.insert(instance, handle.clone());
        Ok(handle)
    }

    async fn get_agent(
        &self,
        observer: &TestIndividual,
        id: Identifier,
        name: &str,
    ) -> Result<AgentHandle> {
        self.hive(observer)?
            .get_agent(id)
            .await
            .ok_or_else(|| TestError::NotSynced {
                individual: observer.name.to_string(),
                subject: name.to_string(),
            })
    }

    async fn get_membered(
        &self,
        observer: &TestIndividual,
        membered: &impl TestMembered,
    ) -> Result<MemberedHandle> {
        match membered.as_membered() {
            TestMemberedRef::Doc(d) => {
                let h = self.get_document(observer, d).await?;
                Ok(Membered::Document(d.id, h))
            }
            TestMemberedRef::Group(g) => {
                let h = self.hive(observer)?.get_group(g.id).await.ok_or_else(|| {
                    TestError::NotSynced {
                        individual: observer.name.to_string(),
                        subject: g.name.to_string(),
                    }
                })?;
                Ok(Membered::Group(g.id, h))
            }
        }
    }

    async fn get_document(
        &self,
        observer: &TestIndividual,
        doc: &TestDocument,
    ) -> Result<DocHandle> {
        self.get_document_by_id(observer, doc.id, doc.name()).await
    }

    async fn get_document_by_id(
        &self,
        observer: &TestIndividual,
        id: DocumentId,
        name: &str,
    ) -> Result<DocHandle> {
        self.hive(observer)?
            .get_document(id)
            .await
            .ok_or_else(|| TestError::NotSynced {
                individual: observer.name.to_string(),
                subject: name.to_string(),
            })
    }

    /// `add_member`'s `other_relevant_docs` argument: every document the observer can open,
    /// excluding the resource itself.
    async fn other_relevant_docs(
        &self,
        observer: &TestIndividual,
        membered: &impl TestMembered,
    ) -> Vec<DocHandle> {
        let exclude = match membered.as_membered() {
            TestMemberedRef::Doc(d) => Some(d.id),
            TestMemberedRef::Group(_) => None,
        };
        let mut out = vec![];
        for d in &self.docs {
            if Some(d.id) == exclude {
                continue;
            }
            if let Ok(h) = self.get_document(observer, d).await {
                out.push(h);
            }
        }
        out
    }
}
