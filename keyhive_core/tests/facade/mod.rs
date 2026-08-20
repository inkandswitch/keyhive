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
        public::Public,
    },
    store::ciphertext::memory::MemoryCiphertextStore,
};
use keyhive_crypto::{
    signed::SigningError, signer::memory::MemorySigner, symmetric_key::SymmetricKey,
};
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
    hives: BTreeMap<IndividualId, Hive>,
    names: BTreeMap<Identifier, Arc<str>>,
    docs: Vec<TestDocument>,
}

impl TestContext {
    pub async fn new() -> Self {
        let mut names = BTreeMap::new();
        names.insert(Public.id(), PUBLIC_NAME.into());
        TestContext {
            hives: BTreeMap::new(),
            names,
            docs: Vec::new(),
        }
    }

    pub fn public(&self) -> TestPublic {
        TestPublic
    }

    // Create a keyhive identity.
    //
    // Every individual learns every other individual's contact card.
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

    /// The higher of `who`'s own access and public's access.
    pub async fn best_access(
        &self,
        who: &impl TestAgent,
        doc: &TestDocument,
    ) -> Result<Option<Access>> {
        let observer = self.individual_by_id(doc.owner)?;
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
    /// the subject. This can distinguish those cases.
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
    fn name_of(&self, id: Identifier, fallback: &str) -> Arc<str> {
        self.names
            .get(&id)
            .cloned()
            .unwrap_or_else(|| fallback.into())
    }

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
    /// affected, excluding the resource itself.
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
