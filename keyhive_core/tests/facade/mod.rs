//! A testing facade for `Keyhive`.

#![allow(dead_code)]

use dupe::Dupe;
use futures::lock::Mutex;
use keyhive_core::{
    access::Access,
    archive::Archive,
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
    store::ciphertext::memory::MemoryCiphertextStore,
};
use keyhive_crypto::{
    share_key::ShareKey, signed::SigningError, signer::memory::MemorySigner,
    symmetric_key::SymmetricKey,
};
use nonempty::nonempty;
use rand::{rngs::StdRng, seq::SliceRandom, Rng, SeedableRng};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

type Hive = Keyhive<
    future_form::Sendable,
    MemorySigner,
    [u8; 32],
    Vec<u8>,
    MemoryCiphertextStore<[u8; 32], Vec<u8>>,
    NoListener,
    StdRng,
>;

pub type Result<T> = std::result::Result<T, TestError>;

/// Why an operation was refused.
#[derive(Debug)]
pub enum TestError {
    /// The issuer holds some access over the resource, but less than they tried to delegate.
    Escalation { wanted: Access, held: Access },
    /// The issuer has no access to the resource.
    NoAuthority,
    /// The individual has not yet received the required events.
    NotSynced { individual: String, subject: String },
    /// Anything else, wrapping the underlying error as a `String`.
    Other(String),
}

impl std::fmt::Display for TestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TestError::Escalation { wanted, held } => {
                write!(f, "escalation: wanted {wanted}, holds {held}")
            }
            TestError::NoAuthority => write!(f, "no authority over that resource"),
            TestError::NotSynced {
                individual,
                subject,
            } => {
                write!(
                    f,
                    "{individual:?} does not know about {subject:?}. Sync first."
                )
            }
            TestError::Other(m) => write!(f, "{m}"),
        }
    }
}

impl std::error::Error for TestError {}

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

impl From<SigningError> for TestError {
    fn from(e: SigningError) -> Self {
        TestError::Other(e.to_string())
    }
}

impl From<GenerateDocError> for TestError {
    fn from(e: GenerateDocError) -> Self {
        TestError::Other(e.to_string())
    }
}

impl From<EncryptContentError> for TestError {
    fn from(e: EncryptContentError) -> Self {
        TestError::Other(e.to_string())
    }
}

impl From<DecryptError> for TestError {
    fn from(e: DecryptError) -> Self {
        TestError::Other(e.to_string())
    }
}

impl From<ReceivePrekeyOpError> for TestError {
    fn from(e: ReceivePrekeyOpError) -> Self {
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

pub trait TestAgent {
    fn agent_id(&self) -> Identifier;
    fn name(&self) -> &str;
}

pub trait TestMembered: TestAgent {
    #[doc(hidden)]
    fn as_membered(&self) -> TestMemberedRef<'_>;
}

#[doc(hidden)]
pub enum TestMemberedRef<'a> {
    Group(&'a TestGroup),
    Doc(&'a TestDocument),
}

impl TestAgent for TestIndividual {
    /// A keyhive identity's id.
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
}
impl TestMembered for TestDocument {
    fn as_membered(&self) -> TestMemberedRef<'_> {
        TestMemberedRef::Doc(self)
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
    seed: u64,
    docs: Vec<TestDocument>,
}

impl TestContext {
    /// A context, recording a seed for replayability.
    pub async fn new() -> Self {
        Self::with_seed(rand::rngs::OsRng.gen()).await
    }

    /// A context whose key material follows from `seed` so a failure can be
    /// replayed.
    pub async fn with_seed(seed: u64) -> Self {
        let mut names = BTreeMap::new();
        names.insert(Public.id(), PUBLIC_NAME.into());
        TestContext {
            hives: BTreeMap::new(),
            signers: BTreeMap::new(),
            handles: BTreeMap::new(),
            next_instance: 0,
            names,
            docs: Vec::new(),
            csprng: StdRng::seed_from_u64(seed),
            seed,
        }
    }

    /// The seed this context was built from. Report it when a test fails.
    pub fn seed(&self) -> u64 {
        self.seed
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
            return Err(format!(
                "{:?} and {:?} are different people; prekey secrets are not transferable",
                from.name, to.name
            )
            .into());
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

    /// `issuer` delegates `can` over `resource` to `audience`.
    ///
    /// Signed by the issuer. Returns an error if the issuer may not do this.
    pub async fn delegate(
        &mut self,
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
        let update = hive.add_member(aud, &res, can, &relevant).await?;
        Ok(TestDelegation {
            digest: *update.delegation.digest().raw.as_bytes(),
            issuer: issuer.name.clone(),
            audience: self.name_of(audience.agent_id(), audience.name()),
            subject: self.name_of(membered.agent_id(), membered.name()),
            can,
        })
    }

    /// `issuer` removes `audience`'s membership in `resource`.
    pub async fn revoke(
        &mut self,
        issuer: &TestIndividual,
        audience: &impl TestAgent,
        membered: &impl TestMembered,
    ) -> Result<()> {
        let hive = self.hive(issuer)?;
        let res = self.get_membered(issuer, membered).await?;
        hive.revoke_member(audience.agent_id(), true, &res).await?;
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
            .docs_reachable_by_agent(&agent)
            .await
            .get(&doc.id)
            .map(|a| a.can()))
    }

    /// Everyone who can reach `membered`, including through nested groups.
    pub async fn transitive_members_of(
        &self,
        membered: &impl TestMembered,
    ) -> Result<BTreeMap<String, Access>> {
        let owner = match membered.as_membered() {
            TestMemberedRef::Group(g) => g.owner,
            TestMemberedRef::Doc(d) => d.owner,
        };
        let observer = self.individual_by_instance(owner)?;
        let handle = self.get_membered(&observer, membered).await?;
        let raw = self.hive(&observer)?.reachable_members(handle).await;

        Ok(raw
            .into_iter()
            .map(|(id, (_, access))| {
                let name = self
                    .names
                    .get(&id)
                    .map(|n| n.to_string())
                    .unwrap_or_else(|| format!("<{id}>"));
                (name, access)
            })
            .collect())
    }

    /// Every delegation `observer` holds for `membered`.
    pub async fn delegations_for(
        &self,
        observer: &TestIndividual,
        membered: &impl TestMembered,
    ) -> Result<Vec<TestDelegation>> {
        let handle = self.get_membered(observer, membered).await?;
        let subject = self.name_of(membered.agent_id(), membered.name());
        let mut out = vec![];
        for signed in handle.members().await.values().flat_map(|d| d.iter()) {
            let issuer = Identifier::from(signed.issuer());
            let audience = signed.payload().delegate().id();
            out.push(TestDelegation {
                digest: *signed.digest().raw.as_bytes(),
                issuer: self.name_of(issuer, &issuer.to_string()),
                audience: self.name_of(audience, &audience.to_string()),
                subject: subject.clone(),
                can: signed.payload().can(),
            });
        }
        Ok(out)
    }

    /// Whether `who` can actually decrypt the encrypted content.
    pub async fn can_decrypt(
        &self,
        who: &TestIndividual,
        ct: &TestEncryptedContent,
    ) -> Result<bool> {
        let Ok(handle) = self.get_document_by_id(who, ct.doc).await else {
            return Ok(false);
        };
        Ok(self
            .hive(who)?
            .try_decrypt_content(handle, &ct.inner)
            .await
            .is_ok())
    }

    /// The higher of `who`'s own access and public's access.
    pub async fn best_access(
        &self,
        who: &impl TestAgent,
        doc: &TestDocument,
    ) -> Result<Option<Access>> {
        let observer = self.individual_by_instance(doc.owner)?;
        let handle = self.get_membered(&observer, doc).await?;
        let members = self.hive(&observer)?.reachable_members(handle).await;
        let direct = members.get(&who.agent_id()).map(|(_, a)| *a);
        let public = members.get(&Public.id()).map(|(_, a)| *a);
        Ok(match (direct, public) {
            (Some(d), Some(p)) => Some(d.max(p)),
            (Some(d), None) => Some(d),
            (None, Some(p)) => Some(p),
            (None, None) => None,
        })
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
        let Ok(handle) = self.get_document_by_id(who, ct.doc).await else {
            return Ok(None);
        };
        Ok(self
            .hive(who)?
            .try_decrypt_content_keyed(handle, &ct.inner)
            .await
            .ok()
            .map(|(_, key)| TestSymmetricKey(key)))
    }

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
        &mut self,
        who: &TestIndividual,
        doc: &TestDocument,
        content: &[u8],
    ) -> Result<TestEncryptedContent> {
        let handle = self.get_document(who, doc).await?;
        let content_ref: [u8; 32] = blake3::hash(content).into();
        let out = self
            .hive(who)?
            .try_encrypt_content(handle, &content_ref, &vec![], content)
            .await?;
        Ok(TestEncryptedContent {
            doc: doc.id,
            inner: out.encrypted_content().clone(),
        })
    }

    /// Encrypt. Returns the application secret the content went under.
    pub async fn encrypt_keyed(
        &mut self,
        who: &TestIndividual,
        doc: &TestDocument,
        content: &[u8],
    ) -> Result<(TestEncryptedContent, TestSymmetricKey)> {
        let handle = self.get_document(who, doc).await?;
        let content_ref: [u8; 32] = blake3::hash(content).into();
        let (out, key) = self
            .hive(who)?
            .try_encrypt_content_keyed(handle, &content_ref, &vec![], content)
            .await?;
        Ok((
            TestEncryptedContent {
                doc: doc.id,
                inner: out.encrypted_content().clone(),
            },
            TestSymmetricKey(key),
        ))
    }

    /// Add a prekey. Returns the key that was added.
    pub async fn expand_prekeys(&mut self, who: &TestIndividual) -> Result<TestShareKey> {
        let op = self.hive(who)?.expand_prekeys().await?;
        Ok(TestShareKey(op.payload().share_key))
    }

    /// Replace `old` with a fresh key. Returns the key that replaced it.
    pub async fn rotate_prekey(
        &mut self,
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
        let hive = Keyhive::<future_form::Sendable, _, _, _, _, _, _>::try_from_archive(
            &archive.inner,
            signer,
            MemoryCiphertextStore::new(),
            NoListener,
            Arc::new(Mutex::new(StdRng::seed_from_u64(self.csprng.gen()))),
        )
        .await
        .map_err(|e| TestError::Other(e.to_string()))?;

        let identity = hive.id();
        let instance = TestInstanceId(self.next_instance);
        self.next_instance += 1;
        let card = hive.contact_card().await?;
        for other in self.hives.values() {
            other.receive_contact_card(&card).await?;
            hive.receive_contact_card(&other.contact_card().await?)
                .await?;
        }
        self.hives.insert(instance, hive);
        let handle = TestIndividual {
            identity,
            instance,
            name: name.into(),
        };
        self.handles.insert(instance, handle.clone());
        Ok(handle)
    }

    /// Merge an archive into a live instance. Returns how many events remain pending.
    pub async fn ingest_archive(
        &mut self,
        into: &TestIndividual,
        archive: &TestArchive,
    ) -> Result<usize> {
        Ok(self
            .hive(into)?
            .ingest_archive(archive.inner.clone())
            .await
            .map_err(|e| TestError::Other(e.to_string()))?
            .len())
    }

    /// Sends `from`'s events to `to`. Returns how many events `to` could not yet apply.
    pub async fn sync(&mut self, from: &TestIndividual, to: &TestIndividual) -> Result<usize> {
        let events = self.static_events_for_agent(from, to).await?;
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
            .filter(|e| kind_of(e) != kind)
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
        assert!(batch > 0, "a batch of zero events would never terminate");
        let events = self.static_events_for_agent(from, to).await?;
        let mut pending = 0;
        for chunk in events.chunks(batch) {
            pending = self.deliver(to, chunk.to_vec()).await?;
        }
        Ok(pending)
    }

    /// Sends everything in an order decided by `seed`, so a failing order can be replayed.
    pub async fn sync_shuffled(
        &mut self,
        from: &TestIndividual,
        to: &TestIndividual,
        seed: u64,
    ) -> Result<usize> {
        let mut events = self.static_events_for_agent(from, to).await?;
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
            .map(|e| TestStaticEvent { kind: kind_of(e) })
            .collect())
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

    /// Sends events between every pair of individuals.
    pub async fn sync_all(&mut self) -> Result<()> {
        let ids: Vec<TestInstanceId> = self.hives.keys().copied().collect();
        for _ in 0..3 {
            for from in &ids {
                for to in &ids {
                    if from != to {
                        let a = self.individual_by_instance(*from)?;
                        let b = self.individual_by_instance(*to)?;
                        self.sync(&a, &b).await?;
                    }
                }
            }
        }
        Ok(())
    }

    /////////////////////
    // Internal details
    /////////////////////
    async fn static_events_for_agent(
        &self,
        from: &TestIndividual,
        to: &TestIndividual,
    ) -> Result<Vec<StaticEvent<[u8; 32]>>> {
        let to_agent = self.get_agent(from, to.identity.into(), &to.name).await?;
        Ok(self
            .hive(from)?
            .static_events_for_agent(&to_agent)
            .await
            .into_values()
            .collect())
    }

    /// Deliver events and return a count of how many are still waiting on a dependency.
    async fn deliver(
        &self,
        to: &TestIndividual,
        events: Vec<StaticEvent<[u8; 32]>>,
    ) -> Result<usize> {
        Ok(self
            .hive(to)?
            .ingest_unsorted_static_events(events)
            .await
            .len())
    }

    fn name_of(&self, id: Identifier, fallback: &str) -> Arc<str> {
        self.names
            .get(&id)
            .cloned()
            .unwrap_or_else(|| fallback.into())
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
        let hive = Keyhive::<future_form::Sendable, _, _, _, _, _, _>::generate(
            signer,
            MemoryCiphertextStore::new(),
            NoListener,
            rng,
        )
        .await?;

        let card = hive.contact_card().await?;
        for other in self.hives.values() {
            other.receive_contact_card(&card).await?;
            hive.receive_contact_card(&other.contact_card().await?)
                .await?;
        }

        let identity = hive.id();
        let instance = TestInstanceId(self.next_instance);
        self.next_instance += 1;
        self.hives.insert(instance, hive);
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
    ) -> Result<Agent<future_form::Sendable, MemorySigner, [u8; 32], NoListener>> {
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
    ) -> Result<Membered<future_form::Sendable, MemorySigner, [u8; 32], NoListener>> {
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

    #[allow(clippy::type_complexity)]
    async fn get_document(
        &self,
        observer: &TestIndividual,
        doc: &TestDocument,
    ) -> Result<Arc<Mutex<Document<future_form::Sendable, MemorySigner, [u8; 32], NoListener>>>>
    {
        self.hive(observer)?
            .get_document(doc.id)
            .await
            .ok_or_else(|| TestError::NotSynced {
                individual: observer.name.to_string(),
                subject: doc.name.to_string(),
            })
    }

    #[allow(clippy::type_complexity)]
    async fn get_document_by_id(
        &self,
        observer: &TestIndividual,
        id: DocumentId,
    ) -> Result<Arc<Mutex<Document<future_form::Sendable, MemorySigner, [u8; 32], NoListener>>>>
    {
        self.hive(observer)?
            .get_document(id)
            .await
            .ok_or_else(|| TestError::NotSynced {
                individual: observer.name.to_string(),
                subject: format!("{id}"),
            })
    }

    /// `add_member`'s `other_relevant_docs` argument: every document the observer can open,
    /// excluding the resource itself.
    #[allow(clippy::type_complexity)]
    async fn other_relevant_docs(
        &self,
        observer: &TestIndividual,
        membered: &impl TestMembered,
    ) -> Vec<Arc<Mutex<Document<future_form::Sendable, MemorySigner, [u8; 32], NoListener>>>> {
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
                out.push(h.dupe());
            }
        }
        out
    }
}
