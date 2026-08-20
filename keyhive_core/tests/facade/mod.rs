//! A testing facade for `Keyhive`.

#![allow(dead_code)]

use dupe::Dupe;
use futures::lock::Mutex;
use keyhive_core::{
    access::Access,
    keyhive::{EncryptContentError, Keyhive},
    listener::no_listener::NoListener,
    principal::{
        agent::Agent,
        document::{id::DocumentId, AddMemberError, DecryptError, Document, GenerateDocError},
        group::{error::AddError, id::GroupId, AddGroupMemberError, RevokeMemberError},
        identifier::Identifier,
        individual::{id::IndividualId, ReceivePrekeyOpError},
        membered::Membered,
    },
    store::ciphertext::memory::MemoryCiphertextStore,
};
use keyhive_crypto::{signed::SigningError, signer::memory::MemorySigner};
use nonempty::nonempty;
use std::{collections::BTreeMap, sync::Arc};

type Hive = Keyhive<
    future_form::Sendable,
    MemorySigner,
    [u8; 32],
    Vec<u8>,
    MemoryCiphertextStore<[u8; 32], Vec<u8>>,
    NoListener,
    rand::rngs::OsRng,
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

/// Everything else the facade calls reports as `Other`. None of it is a refusal that a
/// test should be distinguishing.
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

/// A keyhive identity with their own `Keyhive` instance and signing key.
#[derive(Clone, Debug)]
pub struct TestIndividual {
    id: IndividualId,
    name: Arc<str>,
}

#[derive(Clone, Debug)]
pub struct TestGroup {
    id: GroupId,
    name: Arc<str>,
    owner: IndividualId,
}

#[derive(Clone, Debug)]
pub struct TestDocument {
    id: DocumentId,
    name: Arc<str>,
    owner: IndividualId,
}

/// Encrypted content, with the id for the document it belongs to.
pub struct TestEncryptedContent {
    doc: DocumentId,
    inner: beekem::encrypted::EncryptedContent<Vec<u8>, [u8; 32]>,
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
    fn agent_id(&self) -> Identifier {
        self.id.into()
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
    hives: BTreeMap<IndividualId, Hive>,
    names: BTreeMap<Identifier, Arc<str>>,
    docs: Vec<TestDocument>,
}

impl TestContext {
    pub async fn new() -> Self {
        TestContext {
            hives: BTreeMap::new(),
            names: BTreeMap::new(),
            docs: Vec::new(),
        }
    }

    /// Create a keyhive identity.
    ///
    /// Every individual learns every other individual's contact card.
    pub async fn individual(&mut self, name: &str) -> Result<TestIndividual> {
        let signer = MemorySigner::generate(&mut rand::rngs::OsRng);
        let hive = Keyhive::<future_form::Sendable, _, _, _, _, _, _>::generate(
            signer,
            MemoryCiphertextStore::new(),
            NoListener,
            rand::rngs::OsRng,
        )
        .await?;

        let card = hive.contact_card().await?;
        for other in self.hives.values() {
            other.receive_contact_card(&card).await?;
            hive.receive_contact_card(&other.contact_card().await?)
                .await?;
        }

        let id = hive.id();
        let name: Arc<str> = name.into();
        self.names.insert(id.into(), name.clone());
        self.hives.insert(id, hive);
        Ok(TestIndividual { id, name })
    }

    pub async fn group(&mut self, owner: &TestIndividual, name: &str) -> Result<TestGroup> {
        let g = self.hive(owner)?.generate_group(vec![]).await?;
        let id = { g.lock().await.group_id() };
        let name: Arc<str> = name.into();
        self.names.insert(id.into(), name.clone());
        Ok(TestGroup {
            id,
            name,
            owner: owner.id,
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
            owner: owner.id,
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
    ) -> Result<()> {
        let hive = self.hive(issuer)?;
        let aud = self
            .get_agent(issuer, audience.agent_id(), audience.name())
            .await?;
        let res = self.get_membered(issuer, membered).await?;
        let relevant = self.other_relevant_docs(issuer, membered).await;
        hive.add_member(aud, &res, can, &relevant).await?;
        Ok(())
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
        let observer = self.individual_by_id(doc.owner)?;
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
        let observer = self.individual_by_id(owner)?;
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

    /// Sends `from`'s events to `to`. Returns how many events `to` could not yet apply.
    pub async fn sync(&mut self, from: &TestIndividual, to: &TestIndividual) -> Result<usize> {
        let to_agent = self.get_agent(from, to.id.into(), &to.name).await?;
        let events = self.hive(from)?.static_events_for_agent(&to_agent).await;
        let pending = self
            .hive(to)?
            .ingest_unsorted_static_events(events.into_values().collect())
            .await;
        Ok(pending.len())
    }

    /// Sends events between every pair of individuals.
    pub async fn sync_all(&mut self) -> Result<()> {
        let ids: Vec<IndividualId> = self.hives.keys().copied().collect();
        for _ in 0..3 {
            for from in &ids {
                for to in &ids {
                    if from != to {
                        let a = self.individual_by_id(*from)?;
                        let b = self.individual_by_id(*to)?;
                        self.sync(&a, &b).await?;
                    }
                }
            }
        }
        Ok(())
    }

    /////////////////////
    /// Internal details
    /////////////////////
    fn hive(&self, who: &TestIndividual) -> Result<&Hive> {
        self.hives
            .get(&who.id)
            .ok_or_else(|| format!("{:?} is not in this TestContext", who.name).into())
    }

    fn individual_by_id(&self, id: IndividualId) -> Result<TestIndividual> {
        let name = self
            .names
            .get(&id.into())
            .ok_or("unknown actor id")?
            .clone();
        Ok(TestIndividual { id, name })
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

    /// `add_member`'s `other_relevant_docs` argument: documents whose key state is
    /// affected, **excluding the resource itself**.
    ///
    /// The exclusion is essential and not visible from the signature. `add_member` locks
    /// the resource and then locks each document in this list; `futures::lock::Mutex` is
    /// not reentrant, so passing the resource here makes the task hang, with no panic and
    /// no timeout.
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
