pub mod archive;
pub mod id;

use self::archive::DocumentArchive;
use super::{group::AddGroupMemberError, individual::id::IndividualId};
use crate::{
    access::Access,
    cgka::{
        beekem::DecryptTreeSecretError,
        error::CgkaError,
        operation::{CgkaEpoch, CgkaOperation},
        Cgka, NewAppSecretError, RemoveError, TryCgkaFromArchiveError, UpdateLeafError,
    },
    content::reference::ContentRef,
    crypto::{
        digest::Digest,
        encrypted::EncryptedContent,
        envelope::Envelope,
        share_key::{AsyncSecretKey, ShareKey},
        signed::{Signed, SigningError},
        signer::{async_signer::AsyncSigner, ephemeral::EphemeralSigner},
        symmetric_key::SymmetricKey,
        verifiable::Verifiable,
    },
    error::missing_dependency::MissingDependency,
    listener::{membership::MembershipListener, no_listener::NoListener},
    principal::{
        active::Active,
        agent::{id::AgentId, Agent},
        group::{
            delegation::{Delegation, DelegationError},
            error::AddError,
            revocation::Revocation,
            Group, RevokeMemberError,
        },
        identifier::Identifier,
    },
    store::{
        ciphertext::{CausalDecryptionError, CausalDecryptionState, CiphertextStore, ErrorReason},
        delegation::DelegationStore,
        revocation::RevocationStore,
        secret_key::traits::ShareSecretStore,
    },
    util::content_addressed_map::CaMap,
};
use derivative::Derivative;
use dupe::Dupe;
use ed25519_dalek::VerifyingKey;
use id::DocumentId;
use nonempty::NonEmpty;
use serde::{Deserialize, Serialize};
use std::{
    cell::RefCell,
    collections::{BTreeMap, HashMap, HashSet},
    fmt::Debug,
    hash::{Hash, Hasher},
    rc::Rc,
};
use thiserror::Error;
use tracing::instrument;

#[derive(Clone, Derivative)]
pub struct Document<
    S: AsyncSigner,
    K: ShareSecretStore,
    T: ContentRef = [u8; 32],
    L: MembershipListener<S, K, T> = NoListener,
> {
    pub(crate) group: Group<S, K, T, L>,
    pub(crate) content_heads: HashSet<T>,
    pub(crate) content_state: HashSet<T>,

    known_decryption_keys: HashMap<T, SymmetricKey>,
    pub(crate) cgka: Cgka<K>,
}

impl<S: AsyncSigner, K: ShareSecretStore, T: ContentRef, L: MembershipListener<S, K, T>>
    Document<S, K, T, L>
{
    // NOTE doesn't register into the top-level Keyhive context
    #[instrument(skip_all, fields(group_id = %group.id(), viewer_id = %viewer.id()))]
    pub async fn from_group(
        group: Group<S, K, T, L>,
        viewer: &Active<S, K, T, L>,
        mut share_secret_store: K,
        content_heads: NonEmpty<T>,
    ) -> Result<Self, DocFromGroupError<K>> {
        let doc_id = DocumentId(group.id());
        let initial_secret_key = share_secret_store
            .generate_share_secret_key()
            .await
            .map_err(DocFromGroupError::GenerateInitialKeyError)?;
        let initial_pk = initial_secret_key.to_share_key();
        let mut doc = Document {
            cgka: Cgka::new(
                doc_id,
                viewer.id(),
                initial_pk,
                share_secret_store,
                &viewer.signer,
            )
            .await?,
            group,
            content_heads: content_heads.iter().cloned().collect(),
            content_state: Default::default(),
            known_decryption_keys: HashMap::new(),
        };
        doc.rebuild();
        Ok(doc)
    }

    pub fn id(&self) -> Identifier {
        self.group.id()
    }

    pub fn doc_id(&self) -> DocumentId {
        DocumentId(self.group.id())
    }

    pub fn agent_id(&self) -> AgentId {
        self.doc_id().into()
    }

    #[allow(clippy::type_complexity)]
    pub fn members(&self) -> &HashMap<Identifier, NonEmpty<Rc<Signed<Delegation<S, K, T, L>>>>> {
        self.group.members()
    }

    pub fn transitive_members(&self) -> HashMap<Identifier, (Agent<S, K, T, L>, Access)> {
        self.group.transitive_members()
    }

    pub fn delegation_heads(&self) -> &CaMap<Signed<Delegation<S, K, T, L>>> {
        self.group.delegation_heads()
    }

    pub fn revocation_heads(&self) -> &CaMap<Signed<Revocation<S, K, T, L>>> {
        self.group.revocation_heads()
    }

    #[allow(clippy::type_complexity)]
    pub fn get_capability(
        &self,
        member_id: &Identifier,
    ) -> Option<&Rc<Signed<Delegation<S, K, T, L>>>> {
        self.group.get_capability(member_id)
    }

    #[instrument(
        skip_all,
        fields(parent_ids = ?parents.iter().map(|p| p.id()).collect::<Vec<_>>())
    )]
    pub async fn generate<R: rand::CryptoRng + rand::RngCore>(
        parents: NonEmpty<Agent<S, K, T, L>>,
        initial_content_heads: NonEmpty<T>,
        delegations: DelegationStore<S, K, T, L>,
        revocations: RevocationStore<S, K, T, L>,
        listener: L,
        mut owner_sks: K,
        signer: &S,
        csprng: &mut R,
    ) -> Result<Self, GenerateDocError<K>> {
        let (group_result, group_vk) = EphemeralSigner::with_signer(csprng, |verifier, signer| {
            Group::generate_after_content(
                signer,
                verifier,
                parents,
                delegations,
                revocations,
                BTreeMap::from_iter([(
                    DocumentId(verifier.into()),
                    initial_content_heads.clone().into_iter().collect(),
                )]),
                listener,
            )
        });

        let group = group_result.await?;
        let owner_id = IndividualId(group_vk.into());
        let doc_id = DocumentId(group.id());
        let owner_share_secret_key = owner_sks
            .generate_share_secret_key()
            .await
            .map_err(GenerateDocError::GenerateSecretError)?;
        let owner_share_key = owner_share_secret_key.to_share_key();
        let group_members = group.pick_individual_prekeys(doc_id);
        let other_members: Vec<(IndividualId, ShareKey)> = group_members
            .iter()
            .filter(|(id, _sk)| **id != owner_id)
            .map(|(id, pk)| (*id, *pk))
            .collect();
        let mut cgka = Cgka::new(doc_id, owner_id, owner_share_key, owner_sks.clone(), signer)
            .await?
            .with_new_owner(owner_id)?;
        let mut ops: Vec<Signed<CgkaOperation>> = vec![];
        ops.push(cgka.init_add_op());
        if let Some(others) = NonEmpty::from_vec(other_members) {
            ops.extend(cgka.add_multiple(others, signer).await?.iter().cloned());
        }
        let (_pcs_key, update_op) = cgka.update(&owner_share_secret_key, signer, csprng).await?;

        ops.push(update_op);
        for op in ops {
            group.listener.on_cgka_op(&Rc::new(op)).await;
        }

        Ok(Document {
            group,
            content_state: HashSet::new(),
            content_heads: initial_content_heads.iter().cloned().collect(),
            known_decryption_keys: HashMap::new(),
            cgka,
        })
    }

    #[allow(clippy::type_complexity)]
    #[instrument(
        skip(self, member_to_add, can, signer),
        fields(doc_id = ?self.doc_id(), member_id = %member_to_add.id())
    )]
    pub async fn add_member(
        &mut self,
        member_to_add: Agent<S, K, T, L>,
        can: Access,
        signer: &S,
        other_relevant_docs: &[Rc<RefCell<Document<S, K, T, L>>>],
    ) -> Result<AddMemberUpdate<S, K, T, L>, AddMemberError<K>> {
        let mut after_content: BTreeMap<DocumentId, Vec<T>> = other_relevant_docs
            .iter()
            .map(|d| {
                (
                    d.borrow().doc_id(),
                    d.borrow().content_heads.iter().cloned().collect(),
                )
            })
            .collect();

        after_content.insert(self.doc_id(), self.content_state.iter().cloned().collect());

        let mut update = self
            .group
            .add_member_with_manual_content(member_to_add.dupe(), can, signer, after_content)
            .await?;

        if can.is_reader() {
            // Group::add_member_with_manual_content adds the member to the CGKA for
            // transitive document members of the group, but not to the group itself
            // (because the group might not be a document), so we add the member to
            // the group here and add any extra resulting cgka ops to the update.
            let cgka_ops_for_this_doc = self.add_cgka_member(&update.delegation, signer).await?;
            update.cgka_ops.extend(cgka_ops_for_this_doc.into_iter());
        }
        Ok(update)
    }

    #[instrument(
        skip_all,
        fields(doc_id = %self.doc_id(), member_id = %delegation.payload.delegate.id())
    )]
    pub(crate) async fn add_cgka_member(
        &mut self,
        delegation: &Signed<Delegation<S, K, T, L>>,
        signer: &S,
    ) -> Result<Vec<Signed<CgkaOperation>>, DecryptTreeSecretError<K>> {
        let prekeys = delegation
            .payload
            .delegate
            .pick_individual_prekeys(self.doc_id());

        let mut acc = vec![];
        for (id, prekey) in prekeys.iter() {
            if let Some(op) = self.cgka.add(*id, *prekey, signer).await? {
                acc.push(op);
            }
        }
        Ok(acc)
    }

    #[instrument(skip(self, signer), fields(doc_id = ?self.doc_id()))]
    pub async fn revoke_member(
        &mut self,
        member_id: Identifier,
        retain_all_other_members: bool,
        signer: &S,
        after_other_doc_content: &mut BTreeMap<DocumentId, Vec<T>>,
    ) -> Result<RevokeMemberUpdate<S, K, T, L>, RevokeMemberError<K>> {
        let RevokeMemberUpdate {
            revocations,
            redelegations,
            cgka_ops,
        } = self
            .group
            .revoke_member(
                member_id,
                retain_all_other_members,
                signer,
                after_other_doc_content,
            )
            .await?;

        // FIXME: Convert revocations into CgkaOperations by calling remove on Cgka.
        // FIXME: We need to check if this has revoked the last member in our group?
        let mut ids_to_remove = Vec::new();
        let mut ops = cgka_ops;
        if let Some(delegations) = self.group.members.get(&member_id) {
            for id in delegations
                .iter()
                .flat_map(|d| d.payload().delegate.individual_ids())
            {
                ids_to_remove.push(id);
            }
        }

        for id in ids_to_remove {
            if let Some(op) = self.cgka.remove(id, signer).await? {
                ops.push(op);
            }
        }
        Ok(RevokeMemberUpdate {
            revocations,
            redelegations,
            cgka_ops: ops,
        })
    }

    #[instrument(skip(self, signer), fields(doc_id = ?self.doc_id()))]
    pub async fn remove_cgka_member(
        &mut self,
        id: IndividualId,
        signer: &S,
    ) -> Result<Option<Signed<CgkaOperation>>, RemoveError<K>> {
        self.cgka.remove(id, signer).await
    }

    pub fn get_agent_revocations(
        &self,
        agent: &Agent<S, K, T, L>,
    ) -> Vec<Rc<Signed<Revocation<S, K, T, L>>>> {
        self.group.get_agent_revocations(agent)
    }

    pub fn rebuild(&mut self) {
        self.group.rebuild();
        // FIXME also rebuild CGKA?
    }

    #[allow(clippy::type_complexity)]
    pub fn receive_delegation(
        &mut self,
        delegation: Rc<Signed<Delegation<S, K, T, L>>>,
    ) -> Result<Digest<Signed<Delegation<S, K, T, L>>>, AddError> {
        self.group.receive_delegation(delegation)
    }

    pub async fn receive_revocation(
        &mut self,
        revocation: Rc<Signed<Revocation<S, K, T, L>>>,
    ) -> Result<Digest<Signed<Revocation<S, K, T, L>>>, AddError> {
        self.group.receive_revocation(revocation).await
    }

    pub async fn merge_cgka_op(
        &mut self,
        op: Rc<Signed<CgkaOperation>>,
    ) -> Result<(), DecryptTreeSecretError<K>> {
        self.cgka.merge_concurrent_operation(op).await
    }

    #[instrument(skip(self), fields(doc_id = ?self.doc_id()))]
    pub async fn merge_cgka_invite_op(
        &mut self,
        op: Rc<Signed<CgkaOperation>>,
    ) -> Result<(), DecryptTreeSecretError<K>> {
        let CgkaOperation::Add {
            added_id,
            ref predecessors,
            ..
        } = op.payload
        else {
            return Err(CgkaError::UnexpectedInviteOperation)?;
        };
        if !self
            .cgka
            .contains_predecessors(&HashSet::from_iter(predecessors.iter().cloned()))
        {
            return Err(CgkaError::OutOfOrderOperation)?;
        }
        self.cgka = self.cgka.with_new_owner(added_id)?;
        self.merge_cgka_op(op).await
    }

    pub fn cgka_ops(&self) -> Result<NonEmpty<CgkaEpoch>, CgkaError> {
        self.cgka.ops()
    }

    #[instrument(skip_all, fields(doc_id = ?self.doc_id()))]
    pub async fn pcs_update<R: rand::RngCore + rand::CryptoRng>(
        &mut self,
        signer: &S,
        csprng: &mut R,
    ) -> Result<Signed<CgkaOperation>, PcsUpdateErrorError<K>> {
        let new_share_secret_key = self
            .cgka
            .store
            .generate_share_secret_key()
            .await
            .map_err(PcsUpdateErrorError::GenerateSecretError)?;
        let (_, op) = self
            .cgka
            .update(&new_share_secret_key, signer, csprng)
            .await?;
        Ok(op)
    }

    #[instrument(skip_all, fields(doc_id = ?self.doc_id(), content_ref))]
    pub async fn try_encrypt_content<R: rand::CryptoRng + rand::RngCore>(
        &mut self,
        content_ref: &T,
        content: &[u8],
        pred_refs: &Vec<T>,
        signer: &S,
        csprng: &mut R,
    ) -> Result<EncryptedContentWithUpdate<T>, TryEncryptError<K>> {
        let (app_secret, maybe_update_op) = self
            .cgka
            .new_app_secret_for(content_ref, content, pred_refs, signer, csprng)
            .await?;

        self.known_decryption_keys
            .insert(content_ref.clone(), app_secret.key());

        Ok(EncryptedContentWithUpdate {
            encrypted_content: app_secret
                .try_encrypt(content)
                .map_err(TryEncryptError::EncryptionFailed)?,
            update_op: maybe_update_op,
        })
    }

    #[instrument(skip_all, fields(doc_id = ?self.doc_id(), nonce = ?encrypted_content.nonce))]
    pub async fn try_decrypt_content<P: for<'de> Deserialize<'de>>(
        &mut self,
        encrypted_content: &EncryptedContent<P, T>,
    ) -> Result<Vec<u8>, DecryptError> {
        let decrypt_key = self
            .cgka
            .decryption_key_for(encrypted_content)
            .await
            .map_err(|_| DecryptError::KeyNotFound)?;

        let mut plaintext = encrypted_content.ciphertext.clone();
        decrypt_key
            .try_decrypt(encrypted_content.nonce, &mut plaintext)
            .map_err(DecryptError::DecryptionFailed)?;

        // FIXME for some reason this decrypts successfully,
        // but the bytes of the symmetric key are different,
        // so we get a different nocne.
        //
        // FIXME the above is beacuse the nonce is ignored due to CGKA changes. Fix this.
        //
        // let expected_siv = Siv::new(&decrypt_key, &plaintext, self.doc_id())?;
        // if expected_siv != encrypted_content.nonce {
        //     Err(DecryptError::SivMismatch)?;
        // }
        Ok(plaintext)
    }

    #[instrument(
        skip_all,
        fields(doc_id = %self.doc_id(), content_id = ?encrypted_content.content_ref)
    )]
    pub async fn try_causal_decrypt_content<
        C: CiphertextStore<T, P>,
        P: for<'de> Deserialize<'de> + Serialize + Clone,
    >(
        &mut self,
        encrypted_content: &EncryptedContent<P, T>,
        store: &mut C,
    ) -> Result<CausalDecryptionState<T, P>, DocCausalDecryptionError<T, P, C>>
    where
        T: for<'de> Deserialize<'de>,
    {
        let raw_entrypoint = self.try_decrypt_content(encrypted_content).await?;

        let mut acc = CausalDecryptionState::new();

        let entrypoint_envelope: Envelope<T, Vec<u8>> =
            bincode::deserialize(raw_entrypoint.as_slice()).map_err(|e| CausalDecryptionError {
                progress: acc.clone(),
                cannot: HashMap::from_iter([(
                    encrypted_content.content_ref.clone(),
                    ErrorReason::DeserializationFailed(e.into()),
                )]),
            })?;

        let mut to_decrypt: Vec<(Rc<EncryptedContent<P, T>>, SymmetricKey)> = vec![];
        for (digest, symm_key) in entrypoint_envelope.ancestors.iter() {
            if let Some(encrypted) = store
                .get_ciphertext(digest)
                .await
                .map_err(DocCausalDecryptionError::GetCiphertextError)?
            {
                to_decrypt.push((encrypted, *symm_key));
            } else {
                acc.next.insert(digest.clone(), *symm_key);
            }
        }

        Ok(store.try_causal_decrypt(&mut to_decrypt).await?)
    }

    #[instrument(skip(self), fields(doc_id = ?self.doc_id()))]
    pub fn into_archive(&self) -> DocumentArchive<T> {
        DocumentArchive {
            group: self.group.into_archive(),
            content_heads: self.content_heads.clone(),
            content_state: self.content_state.clone(),
            cgka: self.cgka.into_archive(),
        }
    }

    pub(crate) async fn dummy_from_archive(
        archive: DocumentArchive<T>,
        delegations: DelegationStore<S, K, T, L>,
        revocations: RevocationStore<S, K, T, L>,
        share_secret_store: K,
        listener: L,
    ) -> Result<Self, TryCgkaFromArchiveError<K>> {
        Ok(Document {
            group: Group::<S, K, T, L>::dummy_from_archive(
                archive.group,
                delegations,
                revocations,
                listener,
            ),
            content_heads: archive.content_heads,
            content_state: archive.content_state,
            known_decryption_keys: HashMap::new(),
            cgka: Cgka::try_from_archive(&archive.cgka, share_secret_store).await?,
        })
    }
}

impl<S: AsyncSigner, K: ShareSecretStore, T: ContentRef, L: MembershipListener<S, K, T>> Debug
    for Document<S, K, T, L>
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Ensures that we don't skip fields by accident
        let Document {
            group,
            content_heads,
            content_state,
            known_decryption_keys,
            cgka,
        } = self;
        f.debug_struct("Document")
            .field("group", group)
            .field("content_heads", content_heads)
            .field("content_state", content_state)
            .field("known_decryption_keys", known_decryption_keys)
            .field("cgka", cgka)
            .finish()
    }
}

impl<S: AsyncSigner, K: ShareSecretStore, T: ContentRef, L: MembershipListener<S, K, T>> Verifiable
    for Document<S, K, T, L>
{
    fn verifying_key(&self) -> VerifyingKey {
        self.group.verifying_key()
    }
}

impl<S: AsyncSigner, K: ShareSecretStore, T: ContentRef, L: MembershipListener<S, K, T>> Hash
    for Document<S, K, T, L>
{
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.group.hash(state);
        crate::util::hasher::hash_set(&self.content_heads, state);
        crate::util::hasher::hash_set(&self.content_state, state);
        self.cgka.hash(state);
    }
}

impl<S: AsyncSigner, K: ShareSecretStore, T: ContentRef, L: MembershipListener<S, K, T>> PartialEq
    for Document<S, K, T, L>
{
    fn eq(&self, other: &Self) -> bool {
        let Document {
            group,
            content_heads,
            content_state,
            cgka,
            known_decryption_keys,
        } = self;
        let round1 = *group == other.group
            && *content_heads == other.content_heads
            && *content_state == other.content_state
            && *cgka == other.cgka;

        if !round1 {
            return false;
        }

        if known_decryption_keys.len() != other.known_decryption_keys.len() {
            return false;
        }

        for (k, v) in known_decryption_keys {
            if let Some(other_v) = other.known_decryption_keys.get(k) {
                if v != other_v {
                    return false;
                }
            } else {
                return false;
            }
        }

        true
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddMemberUpdate<
    S: AsyncSigner,
    K: ShareSecretStore,
    T: ContentRef = [u8; 32],
    L: MembershipListener<S, K, T> = NoListener,
> {
    pub delegation: Rc<Signed<Delegation<S, K, T, L>>>,
    pub cgka_ops: Vec<Signed<CgkaOperation>>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RevokeMemberUpdate<
    S: AsyncSigner,
    K: ShareSecretStore,
    T: ContentRef = [u8; 32],
    L: MembershipListener<S, K, T> = NoListener,
> {
    pub(crate) revocations: Vec<Rc<Signed<Revocation<S, K, T, L>>>>,
    pub(crate) redelegations: Vec<Rc<Signed<Delegation<S, K, T, L>>>>,
    pub(crate) cgka_ops: Vec<Signed<CgkaOperation>>,
}

impl<S: AsyncSigner, K: ShareSecretStore, T: ContentRef, L: MembershipListener<S, K, T>>
    RevokeMemberUpdate<S, K, T, L>
{
    #[allow(clippy::type_complexity)]
    pub fn revocations(&self) -> &[Rc<Signed<Revocation<S, K, T, L>>>] {
        &self.revocations
    }

    #[allow(clippy::type_complexity)]
    pub fn redelegations(&self) -> &[Rc<Signed<Delegation<S, K, T, L>>>] {
        &self.redelegations
    }

    #[allow(clippy::type_complexity)]
    pub fn cgka_ops(&self) -> &[Signed<CgkaOperation>] {
        &self.cgka_ops
    }
}

impl<S: AsyncSigner, K: ShareSecretStore, T: ContentRef, L: MembershipListener<S, K, T>> Default
    for RevokeMemberUpdate<S, K, T, L>
{
    fn default() -> Self {
        Self {
            revocations: vec![],
            redelegations: vec![],
            cgka_ops: vec![],
        }
    }
}

#[derive(Debug, Error)]
pub enum AddMemberError<K: ShareSecretStore> {
    #[error(transparent)]
    AddMemberError(#[from] AddGroupMemberError<K>),

    #[error(transparent)]
    CgkaError(#[from] CgkaError),

    #[error(transparent)]
    DecryptTreeSecretError(#[from] DecryptTreeSecretError<K>),
}

#[derive(Debug, Error)]
pub enum PcsUpdateErrorError<K: ShareSecretStore> {
    #[error("Encryption failed: {0}")]
    EncryptionFailed(chacha20poly1305::Error),

    #[error(transparent)]
    UpdateLeafError(#[from] UpdateLeafError<K>),

    #[error("Generate share secret key error: {0}")]
    GenerateSecretError(K::GenerateSecretError),
}

#[derive(Debug, Error)]
pub enum TryEncryptError<K: ShareSecretStore> {
    #[error("Encryption failed: {0}")]
    EncryptionFailed(chacha20poly1305::Error),

    #[error(transparent)]
    NewAppSecretError(#[from] NewAppSecretError<K>),
}

#[derive(Error)]
pub enum DocFromGroupError<K: ShareSecretStore> {
    #[error(transparent)]
    CgkaError(#[from] CgkaError),

    #[error("Generate initial key error: {0}")]
    GenerateInitialKeyError(K::GenerateSecretError),
}

impl<K: ShareSecretStore> Debug for DocFromGroupError<K> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DocFromGroupError::CgkaError(e) => e.fmt(f),
            DocFromGroupError::GenerateInitialKeyError(e) => e.fmt(f),
        }
    }
}

#[derive(Debug, Error)]
pub enum GenerateDocError<K: ShareSecretStore> {
    #[error(transparent)]
    DelegationError(#[from] DelegationError),

    #[error(transparent)]
    SigningError(#[from] SigningError),

    #[error(transparent)]
    CgkaError(#[from] CgkaError),

    #[error(transparent)]
    UpdateLeafError(#[from] UpdateLeafError<K>),

    #[error("Generate share secret key error: {0}")]
    GenerateSecretError(K::GenerateSecretError),

    #[error(transparent)]
    DecryptTreeSecretError(#[from] DecryptTreeSecretError<K>),
}

#[derive(Debug, Error)]
pub enum DocCausalDecryptionError<T: ContentRef, P, C: CiphertextStore<T, P>> {
    #[error(transparent)]
    CausalDecryptionError(#[from] CausalDecryptionError<T, P, C>),

    #[error("{0}")]
    GetCiphertextError(C::GetCiphertextError),

    #[error("Cannot decrypt entrypoint: {0}")]
    EntrypointDecryptError(#[from] DecryptError),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedContentWithUpdate<T: ContentRef> {
    pub(crate) encrypted_content: EncryptedContent<Vec<u8>, T>,
    pub(crate) update_op: Option<Signed<CgkaOperation>>,
}

impl<T: ContentRef> EncryptedContentWithUpdate<T> {
    pub fn encrypted_content(&self) -> &EncryptedContent<Vec<u8>, T> {
        &self.encrypted_content
    }

    pub fn update_op(&self) -> Option<&Signed<CgkaOperation>> {
        self.update_op.as_ref()
    }
}

#[derive(Debug, Error)]
pub enum DecryptError {
    #[error("Key not found")]
    KeyNotFound,

    #[error("Decryption error: {0}")]
    DecryptionFailed(chacha20poly1305::Error),

    #[error("SIV mismatch versus expected")]
    SivMismatch,

    #[error("Unable to build SIV due to IO error: {0}")]
    IoErrorOnSivBuild(#[from] std::io::Error),
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum TryFromDocumentArchiveError<
    S: AsyncSigner,
    K: ShareSecretStore,
    T: ContentRef,
    L: MembershipListener<S, K, T>,
> {
    #[error("Cannot find individual: {0}")]
    MissingIndividual(IndividualId),

    #[error("Cannot find delegation: {0}")]
    MissingDelegation(Digest<Signed<Delegation<S, K, T, L>>>),

    #[error("Cannot find revocation: {0}")]
    MissingRevocation(Digest<Signed<Revocation<S, K, T, L>>>),
}

impl<S: AsyncSigner, K: ShareSecretStore, T: ContentRef, L: MembershipListener<S, K, T>>
    From<MissingDependency<Digest<Signed<Delegation<S, K, T, L>>>>>
    for TryFromDocumentArchiveError<S, K, T, L>
{
    fn from(e: MissingDependency<Digest<Signed<Delegation<S, K, T, L>>>>) -> Self {
        TryFromDocumentArchiveError::MissingDelegation(e.0)
    }
}
