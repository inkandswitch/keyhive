pub mod archive;
pub mod id;

use self::archive::DocumentArchive;
use super::individual::id::IndividualId;
use crate::{
    certificate::{CertificateError, KeylineStorageError},
    cgka::{citations::KeylineImplicitRemovesProtocol, Cgka},
    content::heads::ContentHeads,
    error::not_found::NotFound,
    keyhive::Keyhive,
    listener::membership::MembershipListener,
    principal::{group::RevokeMemberError, membered::id::MemberedId},
    update::{AddMemberUpdate, RevokeMemberUpdate},
};
use beekem::{
    error::CgkaError,
    keys::{LeafKeyPair, ShareKeyMap},
    operation::{CgkaBatch, CgkaOperation, CitationId},
};
use future_form::FutureForm;
use id::DocumentId;
use keyhive_codec::{
    error::DecodeError,
    traits::{Decode, Encode},
};
use keyhive_content::{
    ancestor_key::AncestorKey,
    application_secret::TryEncryptError,
    encrypted::{ContentDecryptError, EncryptedContent},
    envelope::{Envelope, OpenEnvelopeError},
    reference::ContentRef,
    store::{CausalDecryptionError, CausalDecryptionState, CiphertextStore, CiphertextStoreExt},
};
use keyhive_crypto::{
    identifier::Identifier,
    share_key::{ShareKey, ShareSecretKey},
    signer::async_signer::AsyncSigner,
    symmetric_key::SymmetricKey,
    verified::{
        Verified, {self},
    },
};
use keyline::{contract::Keyline, delegation::Delegation, power::Power};
use nonempty::NonEmpty;
use rand::{CryptoRng, RngCore};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    sync::Arc,
};
use thiserror::Error;
use tracing::instrument;

/// A document this replica is a member of: its CGKA group and the
/// content heads it knows. Its membership is the Keyline certificate set.
#[derive(Debug, Clone)]
pub struct DocumentState<T: ContentRef> {
    id: DocumentId,
    pub(crate) content_heads: HashSet<T>,
    pub(crate) content_state: HashSet<T>,

    /// Keys for content this document has written or read through its CGKA
    /// group or a traversal. Each one encrypted or decrypted a block whose
    /// header claims that content ref. A write takes its predecessors' keys
    /// from here. Archived, and not evicted.
    known_decryption_keys: HashMap<T, AncestorKey<T>>,

    /// This replica's CGKA group. A replica has a document only as a
    /// member whose creation or invitation has merged. A relay has none of
    /// its operations and has no `DocumentState`.
    cgka: Cgka<KeylineImplicitRemovesProtocol>,
}

impl<T: ContentRef> DocumentState<T> {
    /// A member's document: its CGKA group, built from its operations, and the
    /// content heads it knows.
    pub(crate) fn with_cgka(
        id: DocumentId,
        cgka: Cgka<KeylineImplicitRemovesProtocol>,
        content_heads: HashSet<T>,
        content_state: HashSet<T>,
    ) -> Self {
        DocumentState {
            id,
            content_heads,
            content_state,
            known_decryption_keys: HashMap::new(),
            cgka,
        }
    }

    pub fn id(&self) -> Identifier {
        self.id.into()
    }

    pub fn doc_id(&self) -> DocumentId {
        self.id
    }

    pub(crate) fn cgka(&self) -> &Cgka<KeylineImplicitRemovesProtocol> {
        &self.cgka
    }

    pub(crate) fn cgka_mut(&mut self) -> &mut Cgka<KeylineImplicitRemovesProtocol> {
        &mut self.cgka
    }

    /// The members of this document's CGKA group.
    ///
    /// Resolves any outstanding concurrent membership change first, which
    /// rebuilds the CGKA group.
    ///
    /// Returns whatever error the rebuild fails with.
    pub fn cgka_members(&mut self) -> Result<impl Iterator<Item = IndividualId> + '_, CgkaError> {
        self.cgka.member_ids()
    }

    #[instrument(skip_all)]
    #[allow(clippy::too_many_arguments, clippy::type_complexity)]
    /// A new document's CGKA graph: `founders` added in order, each with the
    /// prekey operation that proves its key, then a rotation by the first,
    /// its owner, whose prekey secret is `owner_sk`. `implicit_removes_protocol`
    /// removes members the cited certificates do not entitle. Returns the document and its
    /// genesis operations.
    pub(crate) async fn generate<
        F: FutureForm,
        S: AsyncSigner<F>,
        R: CryptoRng + RngCore,
        E: core::error::Error + 'static,
    >(
        id: DocumentId,
        founders: NonEmpty<(
            IndividualId,
            ShareKey,
            Option<Vec<u8>>,
            BTreeSet<CitationId>,
        )>,
        owner_sk: ShareSecretKey,
        implicit_removes_protocol: KeylineImplicitRemovesProtocol,
        initial_content_heads: NonEmpty<T>,
        signer: &S,
        csprng: &mut R,
    ) -> Result<(Self, Vec<Verified<CgkaOperation>>), GenerateDocError<E>> {
        let (owner, owner_pk, _, _) = founders.head;
        let mut owner_sks = ShareKeyMap::new();
        owner_sks.insert(owner_pk, owner_sk);
        let mut cgka = Cgka::new(id, owner, owner_sks, implicit_removes_protocol);
        let mut ops = cgka.add_multiple(founders, signer).await?;
        let (_pcs_key, update_op, _new_key_pair) =
            cgka.update(owner_pk, owner_sk, signer, csprng).await?;
        ops.push(update_op);

        let doc = DocumentState::with_cgka(
            id,
            cgka,
            initial_content_heads.into_iter().collect(),
            HashSet::new(),
        );
        Ok((doc, ops))
    }

    /// Add `id` to this document's [`Cgka`] with key `pk`, which `key_proof`
    /// shows `id` published. Returns `None` if `id` is already a CGKA group member.
    #[instrument(skip_all)]
    pub(crate) async fn add_cgka_member<F: FutureForm, S: AsyncSigner<F>>(
        &mut self,
        id: IndividualId,
        pk: ShareKey,
        key_proof: Option<Vec<u8>>,
        citations: BTreeSet<CitationId>,
        signer: &S,
    ) -> Result<Option<Verified<CgkaOperation>>, CgkaError> {
        self.cgka.add(id, pk, key_proof, citations, signer).await
    }

    /// Create a [`CgkaChange::Remove`] without explicitly listing
    /// targets. Specific members to be removed are determined by
    /// `citations`.
    #[instrument(skip_all)]
    pub(crate) async fn remove_cgka_members_by_citations<F: FutureForm, S: AsyncSigner<F>>(
        &mut self,
        citations: BTreeSet<CitationId>,
        signer: &S,
    ) -> Result<Verified<CgkaOperation>, CgkaError> {
        self.cgka.remove_by_citations(citations, signer).await
    }

    pub fn cgka_ops(&self) -> Result<NonEmpty<CgkaBatch>, CgkaError> {
        self.cgka.ops()
    }

    /// Rotate our CGKA key, returning the update and the new key pair.
    #[instrument(skip_all)]
    pub async fn pcs_update<F: FutureForm, S: AsyncSigner<F>, R: RngCore + CryptoRng>(
        &mut self,
        signer: &S,
        csprng: &mut R,
    ) -> Result<(Verified<CgkaOperation>, LeafKeyPair), EncryptError> {
        let new_share_secret_key = ShareSecretKey::generate(csprng);
        let new_share_key = new_share_secret_key.share_key();
        let (_, op, new_key_pair) = self
            .cgka
            .update(new_share_key, new_share_secret_key, signer, csprng)
            .await
            .map_err(EncryptError::UnableToPcsUpdate)?;
        Ok((op, new_key_pair))
    }

    /// The keys of `pred_refs`, from content this document has written or read.
    /// Fails with the first predecessor it has no key for.
    pub(crate) fn predecessor_keys(&self, pred_refs: &[T]) -> Result<Vec<AncestorKey<T>>, T> {
        pred_refs
            .iter()
            .map(|pred| {
                self.known_decryption_keys
                    .get(pred)
                    .cloned()
                    .ok_or_else(|| pred.clone())
            })
            .collect()
    }

    /// Remember `key` for its content ref, unless this document already has one for it.
    pub(crate) fn remember_key(&mut self, key: AncestorKey<T>) {
        self.known_decryption_keys
            .entry(key.content_ref().clone())
            .or_insert(key);
    }

    /// Every key this document has.
    pub(crate) fn keys(&self) -> impl Iterator<Item = &AncestorKey<T>> {
        self.known_decryption_keys.values()
    }

    /// Remember the key that decrypted each block a traversal read, unless
    /// this document already has one for it.
    pub(crate) fn remember_traversed_keys<F: FutureForm, P, S: CiphertextStore<F, T, P>>(
        &mut self,
        walked: &Result<CausalDecryptionState<T, P>, CausalDecryptionError<F, T, P, S>>,
    ) {
        let read = match walked {
            Ok(read) => read,
            Err(err) => &err.progress,
        };
        for key in read.keys.values() {
            self.remember_key(key.clone());
        }
    }

    /// Encrypt `content` with the keys of its `ancestors`, returning it with the key it is
    /// encrypted under. The third element is the update this write had to make and the key
    /// pair it sampled for our key in the CGKA group, if we had no current key.
    #[instrument(skip_all)]
    pub async fn try_encrypt_content_keyed<
        F: FutureForm,
        S: AsyncSigner<F>,
        R: CryptoRng + RngCore,
    >(
        &mut self,
        content_ref: &T,
        content: &[u8],
        ancestors: &[AncestorKey<T>],
        signer: &S,
        csprng: &mut R,
    ) -> Result<
        (
            EncryptedContent<Vec<u8>, T>,
            SymmetricKey,
            Option<(Verified<CgkaOperation>, LeafKeyPair)>,
        ),
        EncryptError,
    > {
        let pred_refs: Vec<T> = ancestors.iter().map(|a| a.content_ref().clone()).collect();
        let (app_secret, rotation) = self
            .cgka
            .new_app_secret_for(content_ref, &pred_refs, signer, csprng)
            .await
            .map_err(EncryptError::FailedToMakeAppSecret)?;

        let (encrypted_content, own_key) = app_secret
            .try_encrypt(self.doc_id().into(), ancestors, content)
            .map_err(EncryptError::EncryptionFailed)?;
        let application_secret_key = own_key.key();
        self.known_decryption_keys
            .insert(content_ref.clone(), own_key);

        Ok((encrypted_content, application_secret_key, rotation))
    }

    /// Decrypt content with its key from this document's CGKA group.
    #[instrument(skip_all)]
    pub fn try_decrypt_content<P>(
        &mut self,
        encrypted_content: &EncryptedContent<P, T>,
    ) -> Result<Envelope<T, Vec<u8>>, DecryptError> {
        self.try_decrypt_content_keyed(encrypted_content)
            .map(|(envelope, _key)| envelope)
    }

    /// [`Self::try_decrypt_content`], also returning the application secret
    /// that was used.
    #[instrument(skip_all)]
    pub fn try_decrypt_content_keyed<P>(
        &mut self,
        encrypted_content: &EncryptedContent<P, T>,
    ) -> Result<(Envelope<T, Vec<u8>>, SymmetricKey), DecryptError> {
        let decrypt_key = self
            .cgka
            .decryption_key_for(encrypted_content)
            .map_err(|_| DecryptError::KeyNotFound)?;
        self.try_decrypt_content_with(encrypted_content, decrypt_key)
            .map(|envelope| (envelope, decrypt_key))
    }

    /// Decrypt content with `decrypt_key`, its key from this document's CGKA
    /// group, and return its envelope. Records the key, unless this document
    /// already has one for that content ref.
    pub(crate) fn try_decrypt_content_with<P>(
        &mut self,
        encrypted_content: &EncryptedContent<P, T>,
        decrypt_key: SymmetricKey,
    ) -> Result<Envelope<T, Vec<u8>>, DecryptError> {
        let (envelope, opened_by) =
            Envelope::open(encrypted_content, decrypt_key, self.doc_id().into())?;

        self.remember_key(opened_by);

        Ok(envelope)
    }

    #[instrument(skip_all)]
    pub async fn try_causal_decrypt_content<
        F: FutureForm,
        C: CiphertextStore<F, T, P> + CiphertextStoreExt<F, T, P>,
        P: Decode + Encode + Clone,
    >(
        &mut self,
        encrypted_content: &EncryptedContent<P, T>,
        store: C,
    ) -> Result<CausalDecryptionState<T, P>, DocCausalDecryptionError<F, T, P, C>>
where {
        let entrypoint_envelope = self.try_decrypt_content(encrypted_content)?;

        let mut to_decrypt: Vec<(Arc<EncryptedContent<P, T>>, SymmetricKey)> = vec![];
        let mut not_served = HashMap::new();
        for (digest, symm_key) in entrypoint_envelope.ancestors.iter() {
            if let Some(encrypted) = store
                .get_ciphertext(digest)
                .await
                .map_err(DocCausalDecryptionError::GetCiphertextError)?
            {
                to_decrypt.push((encrypted, *symm_key));
            } else {
                not_served.insert(digest.clone(), *symm_key);
            }
        }

        // The walk reports the ancestors it could not fetch below the ones it
        // was given. The entrypoint's own go in the same report, with their
        // keys, so the reader knows what to fetch and can open it.
        let mut walked = store
            .try_causal_decrypt(self.doc_id().into(), &mut to_decrypt)
            .await;
        match &mut walked {
            Ok(state) => state.next.extend(not_served),
            Err(err) => err.progress.next.extend(not_served),
        }
        self.remember_traversed_keys(&walked);
        Ok(walked?)
    }

    #[instrument(skip_all)]
    pub fn into_archive(&self) -> DocumentArchive<T> {
        DocumentArchive {
            content_heads: self.content_heads.clone(),
            content_state: self.content_state.clone(),
            content_keys: self
                .known_decryption_keys
                .iter()
                .map(|(content_ref, key)| (content_ref.clone(), key.key()))
                .collect(),
        }
    }
}

/// A document, as a transient handle over the keyhive: one this replica holds
/// as a member.
#[derive(Debug, Clone)]
pub struct Document<KH> {
    keyhive: KH,
    id: DocumentId,
}

impl<KH> Document<KH> {
    pub(crate) fn new(keyhive: KH, id: DocumentId) -> Self {
        Document { keyhive, id }
    }

    /// The keyhive this handle reads through.
    pub fn keyhive(&self) -> &KH {
        &self.keyhive
    }

    pub fn id(&self) -> Identifier {
        self.id.into()
    }

    pub fn doc_id(&self) -> DocumentId {
        self.id
    }
}

impl<F, S, T, P, C, L, R, K> Document<Keyhive<F, S, T, P, C, L, R, K>>
where
    F: FutureForm,
    S: AsyncSigner<F> + Clone,
    T: ContentRef,
    P: Decode,
    C: CiphertextStore<F, T, P> + CiphertextStoreExt<F, T, P> + Clone,
    L: MembershipListener<F, T>,
    R: CryptoRng + RngCore,
    K: Keyline<F, RetentionWatermark = ContentHeads<T>>,
    K::Error: Send + Sync + 'static,
{
    /// The live delegations about this document: its direct members.
    #[allow(clippy::type_complexity)]
    pub async fn members(
        &self,
    ) -> Result<Vec<Arc<verified::Signed<Delegation>>>, KeylineStorageError<K::Error>> {
        self.keyhive.delegations_about(self.id).await
    }

    /// Everyone with a live route to this document, with their power.
    pub async fn transitive_members(
        &self,
    ) -> Result<BTreeMap<Identifier, Power>, KeylineStorageError<K::Error>> {
        self.keyhive.members_of(self.id.into()).await
    }

    /// Grant `to_add` power over this document.
    pub async fn add_member(
        &self,
        to_add: Identifier,
        can: Power,
    ) -> Result<AddMemberUpdate, AddMemberError<K::Error>> {
        self.keyhive
            .add_member(to_add, MemberedId::DocumentId(self.id), can)
            .await
    }

    /// Revoke `to_revoke` from this document; with `retain_all_other_members`,
    /// the revoker adopts the members it had admitted.
    pub async fn revoke_member(
        &self,
        to_revoke: Identifier,
        retain_all_other_members: bool,
    ) -> Result<RevokeMemberUpdate<T>, RevokeMemberError<K::Error>> {
        self.keyhive
            .revoke_member(to_revoke, retain_all_other_members, self.id)
            .await
    }

    /// The individuals in this replica's CGKA group for the document. Returns `None` if it
    /// has no CGKA group for it or cannot read that group, e.g., when Keyline cannot
    /// answer a membership question a replay requires.
    pub async fn cgka_members(&self) -> Option<BTreeSet<IndividualId>> {
        let state = self.keyhive.document_state(self.id).await?;
        self.keyhive
            .cgka_group_members(self.id.into(), &state)
            .await
            .ok()
    }

    /// How many operations this replica's CGKA graph for the document has.
    /// Returns `None` if it has not joined the document's CGKA group.
    pub async fn cgka_ops_count(&self) -> Option<usize> {
        let state = self.keyhive.document_state(self.id).await?;
        let count = state.lock().await.cgka().ops_count();
        Some(count)
    }

    /// The content heads this replica knows for the document; `None` if it
    /// has not joined the document's CGKA group.
    pub async fn content_heads(&self) -> Option<HashSet<T>> {
        let state = self.keyhive.document_state(self.id).await?;
        let heads = state.lock().await.content_heads.clone();
        Some(heads)
    }
}

#[derive(Debug, Error)]
pub enum AddMemberError<E: core::error::Error + 'static> {
    /// The identifier was not found.
    #[error(transparent)]
    NotFound(#[from] NotFound),

    #[error(transparent)]
    CgkaError(#[from] CgkaError),

    #[error(transparent)]
    Certificate(#[from] CertificateError),

    #[error(transparent)]
    KeylineStorage(#[from] KeylineStorageError<E>),

    /// The writer has no standing over the resource in Keyline.
    #[error("no standing over the resource")]
    NoAuthority,

    /// The writer's standing over the resource is below what it tried to grant.
    #[error("cannot grant {wanted}: holds only {held}")]
    Escalation { wanted: Power, held: Power },
}

#[derive(Debug, Error)]
pub enum EncryptError {
    /// The identifier was not found.
    #[error(transparent)]
    NotFound(#[from] NotFound),

    #[error("Encryption failed: {0}")]
    EncryptionFailed(TryEncryptError),

    #[error("Unable to PCS update: {0}")]
    UnableToPcsUpdate(CgkaError),

    #[error("Failed to make app secret: {0}")]
    FailedToMakeAppSecret(CgkaError),

    /// The CGKA group could not be prepared for writing, because operations waiting
    /// to be applied could not be applied or the operations this replica's
    /// certificates imply for it could not be issued.
    #[error("could not prepare the CGKA group for writing: {0}")]
    PrepareToWrite(Box<dyn core::error::Error + Send + Sync>),

    /// A member of the CGKA group lacks `Read` in this replica's
    /// certificates and this replica may not sign the remove that would
    /// remove it because it lacks `Read` itself.
    #[error("a member of the CGKA group lacks Read and this replica may not sign its remove")]
    CgkaMemberLacksRead,
}

#[derive(Debug, Error)]
pub enum GenerateDocError<E: core::error::Error + 'static> {
    #[error(transparent)]
    NotFound(#[from] NotFound),

    #[error(transparent)]
    CgkaError(#[from] CgkaError),

    #[error(transparent)]
    Certificate(#[from] CertificateError),

    #[error(transparent)]
    KeylineStorage(#[from] KeylineStorageError<E>),

    #[error("the document's owner is not one of its readers")]
    OwnerCannotRead,

    #[error("no secret key for the prekey the document's owner is added with")]
    OwnerHoldsNoPrekeySecret,

    #[error("no prekey operation of the document's owner publishes the prekey it is added with")]
    OwnerPrekeyUnproven,
}

#[derive(Debug, Error)]
pub enum DocCausalDecryptionError<F: FutureForm, T: ContentRef, P, C: CiphertextStore<F, T, P>> {
    /// Boxed because it is far larger than the other variants
    #[error(transparent)]
    CausalDecryptionError(Box<CausalDecryptionError<F, T, P, C>>),

    #[error("{0}")]
    GetCiphertextError(C::GetCiphertextError),

    #[error("Cannot decrypt entrypoint: {0}")]
    EntrypointDecryptError(#[from] DecryptError),
}

impl<F: FutureForm, T: ContentRef, P, C: CiphertextStore<F, T, P>>
    From<CausalDecryptionError<F, T, P, C>> for DocCausalDecryptionError<F, T, P, C>
{
    fn from(error: CausalDecryptionError<F, T, P, C>) -> Self {
        DocCausalDecryptionError::CausalDecryptionError(Box::new(error))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedContentWithUpdate<T: ContentRef> {
    pub(crate) encrypted_content: EncryptedContent<Vec<u8>, T>,
    pub(crate) update_op: Option<Verified<CgkaOperation>>,
}

impl<T: ContentRef> EncryptedContentWithUpdate<T> {
    pub fn encrypted_content(&self) -> &EncryptedContent<Vec<u8>, T> {
        &self.encrypted_content
    }

    pub fn update_op(&self) -> Option<&Verified<CgkaOperation>> {
        self.update_op.as_ref()
    }
}

#[derive(Debug, Error)]
pub enum DecryptError {
    /// The identifier was not found.
    #[error(transparent)]
    NotFound(#[from] NotFound),

    #[error("Key not found")]
    KeyNotFound,

    #[error("Keyline storage: {0}")]
    KeylineStorage(String),

    #[error("Decryption error: {0}")]
    DecryptionFailed(chacha20poly1305::Error),

    #[error("SIV mismatch versus expected")]
    SivMismatch,

    #[error("Unable to build SIV due to IO error: {0}")]
    IoErrorOnSivBuild(#[from] std::io::Error),

    /// The content decrypted, but is not an envelope. Only a writer with
    /// its key can produce this.
    #[error("the content is not an envelope: {0}")]
    MalformedEnvelope(DecodeError),
}

impl From<OpenEnvelopeError> for DecryptError {
    fn from(err: OpenEnvelopeError) -> Self {
        match err {
            OpenEnvelopeError::Decrypt(e) => e.into(),
            OpenEnvelopeError::Decode(e) => DecryptError::MalformedEnvelope(e),
        }
    }
}

impl From<ContentDecryptError> for DecryptError {
    fn from(err: ContentDecryptError) -> Self {
        match err {
            ContentDecryptError::Decryption => {
                DecryptError::DecryptionFailed(chacha20poly1305::Error)
            }
            ContentDecryptError::NonceMismatch => DecryptError::SivMismatch,
        }
    }
}
