pub mod archive;
pub mod id;

use self::archive::DocumentArchive;
use super::{group::AddGroupMemberError, individual::id::IndividualId};
use crate::{
    access::Access,
    cgka::{
        error::CgkaError,
        keys::ShareKeyMap,
        operation::{CgkaEpoch, CgkaOperation},
        Cgka,
    },
    content::reference::ContentRef,
    crypto::{
        digest::Digest,
        encrypted::EncryptedContent,
        envelope::Envelope,
        share_key::{ShareKey, ShareSecretKey},
        signed::{Signed, SigningError},
        signer::{async_signer::AsyncSigner, ephemeral::EphemeralSigner},
        symmetric_key::SymmetricKey,
        verifiable::Verifiable,
    },
    error::missing_dependency::MissingDependency,
    listener::{membership::MembershipListener, no_listener::NoListener},
    principal::{
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
    },
    util::content_addressed_map::CaMap,
};
use derivative::Derivative;
use derive_where::derive_where;
use dupe::Dupe;
use ed25519_dalek::VerifyingKey;
use futures::{future::join_all, lock::Mutex};
use id::DocumentId;
use nonempty::NonEmpty;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    hash::{Hash, Hasher},
    sync::Arc,
};
use thiserror::Error;
use tracing::instrument;

#[derive(Clone, Derivative)]
#[derive_where(Debug; T)]
pub struct Document<
    S: AsyncSigner,
    T: ContentRef = [u8; 32],
    L: MembershipListener<S, T> = NoListener,
> {
    pub(crate) group: Group<S, T, L>,
    pub(crate) content_heads: HashSet<T>,
    pub(crate) content_state: HashSet<T>,

    known_decryption_keys: HashMap<T, SymmetricKey>,
    cgka: Option<Cgka>,
}

impl<S: AsyncSigner, T: ContentRef, L: MembershipListener<S, T>> Document<S, T, L> {
    // FIXME: We need a signing key for initializing Cgka and we need to share
    // the init add op.
    // NOTE doesn't register into the top-level Keyhive context
    #[instrument(skip_all)]
    pub async fn from_group(
        group: Group<S, T, L>,
        content_heads: NonEmpty<T>,
    ) -> Result<Self, CgkaError> {
        let mut doc = Document {
            cgka: None,
            group,
            content_heads: content_heads.iter().cloned().collect(),
            content_state: Default::default(),
            known_decryption_keys: HashMap::new(),
        };
        doc.rebuild().await;
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

    pub fn cgka(&self) -> Result<&Cgka, CgkaError> {
        match &self.cgka {
            Some(cgka) => Ok(cgka),
            None => Err(CgkaError::NotInitialized),
        }
    }

    pub fn cgka_mut(&mut self) -> Result<&mut Cgka, CgkaError> {
        match &mut self.cgka {
            Some(cgka) => Ok(cgka),
            None => Err(CgkaError::NotInitialized),
        }
    }

    #[allow(clippy::type_complexity)]
    pub fn members(&self) -> &HashMap<Identifier, NonEmpty<Arc<Signed<Delegation<S, T, L>>>>> {
        self.group.members()
    }

    pub async fn transitive_members(&self) -> HashMap<Identifier, (Agent<S, T, L>, Access)> {
        self.group.transitive_members().await
    }

    pub fn delegation_heads(&self) -> &CaMap<Signed<Delegation<S, T, L>>> {
        self.group.delegation_heads()
    }

    pub fn revocation_heads(&self) -> &CaMap<Signed<Revocation<S, T, L>>> {
        self.group.revocation_heads()
    }

    #[allow(clippy::type_complexity)]
    pub fn get_capability(
        &self,
        member_id: &Identifier,
    ) -> Option<&Arc<Signed<Delegation<S, T, L>>>> {
        self.group.get_capability(member_id)
    }

    #[instrument(skip_all)]
    pub async fn generate<R: rand::CryptoRng + rand::RngCore>(
        parents: NonEmpty<Agent<S, T, L>>,
        initial_content_heads: NonEmpty<T>,
        delegations: DelegationStore<S, T, L>,
        revocations: RevocationStore<S, T, L>,
        listener: L,
        signer: &S,
        csprng: Arc<Mutex<R>>,
    ) -> Result<Self, GenerateDocError> {
        let mut locked_csprng = csprng.lock().await;
        let (group_result, group_vk) =
            EphemeralSigner::with_signer(&mut *locked_csprng, |verifier, signer| {
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
        let owner_share_secret_key = ShareSecretKey::generate(&mut *locked_csprng);
        let owner_share_key = owner_share_secret_key.share_key();
        let group_members = group.pick_individual_prekeys(doc_id).await;
        let other_members: Vec<(IndividualId, ShareKey)> = group_members
            .iter()
            .filter(|(id, _sk)| **id != owner_id)
            .map(|(id, pk)| (*id, *pk))
            .collect();
        let mut owner_sks = ShareKeyMap::new();
        owner_sks.insert(owner_share_key, owner_share_secret_key);
        let mut cgka = Cgka::new(doc_id, owner_id, owner_share_key, signer)
            .await?
            .with_new_owner(owner_id, owner_sks)?;
        let mut ops: Vec<Signed<CgkaOperation>> = Vec::new();
        ops.push(cgka.init_add_op());
        if let Some(others) = NonEmpty::from_vec(other_members) {
            ops.extend(cgka.add_multiple(others, signer).await?.iter().cloned());
        }
        let (_pcs_key, update_op) = cgka
            .update(
                owner_share_key,
                owner_share_secret_key,
                signer,
                &mut *locked_csprng,
            )
            .await?;

        ops.push(update_op);
        for op in ops {
            group.listener.on_cgka_op(&Arc::new(op)).await;
        }

        Ok(Document {
            group,
            content_state: HashSet::new(),
            content_heads: initial_content_heads.iter().cloned().collect(),
            known_decryption_keys: HashMap::new(),
            cgka: Some(cgka),
        })
    }

    #[allow(clippy::type_complexity)]
    #[instrument(skip_all)]
    pub async fn add_member(
        &mut self,
        member_to_add: Agent<S, T, L>,
        can: Access,
        signer: &S,
        other_relevant_docs: &[Arc<Mutex<Document<S, T, L>>>],
    ) -> Result<AddMemberUpdate<S, T, L>, AddMemberError> {
        let mut after_content: BTreeMap<_, _> =
            join_all(other_relevant_docs.iter().map(|doc| async {
                let locked = doc.lock().await;
                (
                    locked.doc_id(),
                    locked.content_heads.iter().cloned().collect::<Vec<T>>(),
                )
            }))
            .await
            .into_iter()
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

    #[instrument(skip_all)]
    pub(crate) async fn add_cgka_member(
        &mut self,
        delegation: &Signed<Delegation<S, T, L>>,
        signer: &S,
    ) -> Result<Vec<Signed<CgkaOperation>>, CgkaError> {
        let prekeys = delegation
            .payload
            .delegate
            .pick_individual_prekeys(self.doc_id())
            .await;

        let mut acc = Vec::new();
        for (id, prekey) in prekeys.iter() {
            if let Some(op) = self.cgka_mut()?.add(*id, *prekey, signer).await? {
                acc.push(op);
            }
        }
        Ok(acc)
    }

    #[instrument(skip_all)]
    pub async fn revoke_member(
        &mut self,
        member_id: Identifier,
        retain_all_other_members: bool,
        signer: &S,
        after_other_doc_content: &mut BTreeMap<DocumentId, Vec<T>>,
    ) -> Result<RevokeMemberUpdate<S, T, L>, RevokeMemberError> {
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
            for d in delegations {
                ids_to_remove.extend(d.payload().delegate.individual_ids().await.iter())
            }
        }

        for id in ids_to_remove {
            if let Some(op) = self.cgka_mut()?.remove(id, signer).await? {
                ops.push(op);
            }
        }
        Ok(RevokeMemberUpdate {
            revocations,
            redelegations,
            cgka_ops: ops,
        })
    }

    #[instrument(skip_all)]
    pub async fn remove_cgka_member(
        &mut self,
        id: IndividualId,
        signer: &S,
    ) -> Result<Option<Signed<CgkaOperation>>, CgkaError> {
        self.cgka_mut()?.remove(id, signer).await
    }

    pub async fn get_agent_revocations(
        &self,
        agent: &Agent<S, T, L>,
    ) -> Vec<Arc<Signed<Revocation<S, T, L>>>> {
        self.group.get_agent_revocations(agent).await
    }

    pub async fn rebuild(&mut self) {
        self.group.rebuild().await;
        // FIXME also rebuild CGKA?
    }

    #[allow(clippy::type_complexity)]
    pub async fn receive_delegation(
        &mut self,
        delegation: Arc<Signed<Delegation<S, T, L>>>,
    ) -> Result<Digest<Signed<Delegation<S, T, L>>>, AddError> {
        self.group.receive_delegation(delegation).await
    }

    pub async fn receive_revocation(
        &mut self,
        revocation: Arc<Signed<Revocation<S, T, L>>>,
    ) -> Result<Digest<Signed<Revocation<S, T, L>>>, AddError> {
        self.group.receive_revocation(revocation).await
    }

    pub fn merge_cgka_op(&mut self, op: Arc<Signed<CgkaOperation>>) -> Result<(), CgkaError> {
        match &mut self.cgka {
            Some(cgka) => return cgka.merge_concurrent_operation(op),
            None => match op.payload.clone() {
                CgkaOperation::Add {
                    added_id,
                    pk,
                    ref predecessors,
                    ..
                } => {
                    if !predecessors.is_empty() {
                        return Err(CgkaError::OutOfOrderOperation);
                    }
                    self.cgka = Some(Cgka::new_from_init_add(
                        self.doc_id(),
                        added_id,
                        pk,
                        (*op).clone(),
                    )?)
                }
                _ => return Err(CgkaError::UnexpectedInitialOperation),
            },
        }
        Ok(())
    }

    #[instrument(skip_all)]
    pub fn merge_cgka_invite_op(
        &mut self,
        op: Arc<Signed<CgkaOperation>>,
        sk: &ShareSecretKey,
    ) -> Result<(), CgkaError> {
        let CgkaOperation::Add {
            added_id,
            pk,
            ref predecessors,
            ..
        } = op.payload
        else {
            return Err(CgkaError::UnexpectedInviteOperation);
        };
        if !self
            .cgka()?
            .contains_predecessors(&HashSet::from_iter(predecessors.iter().cloned()))
        {
            return Err(CgkaError::OutOfOrderOperation);
        }
        let mut owner_sks = self.cgka()?.owner_sks.clone();
        owner_sks.insert(pk, *sk);
        self.cgka = Some(self.cgka()?.with_new_owner(added_id, owner_sks)?);
        self.merge_cgka_op(op)
    }

    pub fn cgka_ops(&self) -> Result<NonEmpty<CgkaEpoch>, CgkaError> {
        self.cgka()?.ops()
    }

    #[instrument(skip_all)]
    pub async fn pcs_update<R: rand::RngCore + rand::CryptoRng>(
        &mut self,
        signer: &S,
        csprng: &mut R,
    ) -> Result<Signed<CgkaOperation>, EncryptError> {
        let new_share_secret_key = ShareSecretKey::generate(csprng);
        let new_share_key = new_share_secret_key.share_key();
        let (_, op) = self
            .cgka_mut()
            .map_err(EncryptError::UnableToPcsUpdate)?
            .update(new_share_key, new_share_secret_key, signer, csprng)
            .await
            .map_err(EncryptError::UnableToPcsUpdate)?;
        Ok(op)
    }

    #[instrument(skip_all)]
    pub async fn try_encrypt_content<R: rand::CryptoRng + rand::RngCore>(
        &mut self,
        content_ref: &T,
        content: &[u8],
        pred_refs: &Vec<T>,
        signer: &S,
        csprng: &mut R,
    ) -> Result<EncryptedContentWithUpdate<T>, EncryptError> {
        let (app_secret, maybe_update_op) = self
            .cgka_mut()
            .map_err(EncryptError::FailedToMakeAppSecret)?
            .new_app_secret_for(content_ref, content, pred_refs, signer, csprng)
            .await
            .map_err(EncryptError::FailedToMakeAppSecret)?;

        self.known_decryption_keys
            .insert(content_ref.clone(), app_secret.key());

        Ok(EncryptedContentWithUpdate {
            encrypted_content: app_secret
                .try_encrypt(content)
                .map_err(EncryptError::EncryptionFailed)?,
            update_op: maybe_update_op,
        })
    }

    #[instrument(skip_all)]
    pub fn try_decrypt_content<P: for<'de> Deserialize<'de>>(
        &mut self,
        encrypted_content: &EncryptedContent<P, T>,
    ) -> Result<Vec<u8>, DecryptError> {
        let decrypt_key = self
            .cgka_mut()
            .map_err(|_| DecryptError::KeyNotFound)?
            .decryption_key_for(encrypted_content)
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

    #[instrument(skip_all)]
    pub async fn try_causal_decrypt_content<
        C: CiphertextStore<T, P>,
        P: for<'de> Deserialize<'de> + Serialize + Clone,
    >(
        &mut self,
        encrypted_content: &EncryptedContent<P, T>,
        store: C,
    ) -> Result<CausalDecryptionState<T, P>, DocCausalDecryptionError<T, P, C>>
    where
        T: for<'de> Deserialize<'de>,
    {
        let raw_entrypoint = self.try_decrypt_content(encrypted_content)?;

        let mut acc = CausalDecryptionState::new();

        let entrypoint_envelope: Envelope<T, Vec<u8>> =
            bincode::deserialize(raw_entrypoint.as_slice()).map_err(|e| CausalDecryptionError {
                progress: acc.clone(),
                cannot: HashMap::from_iter([(
                    encrypted_content.content_ref.clone(),
                    ErrorReason::DeserializationFailed(e.into()),
                )]),
            })?;

        let mut to_decrypt: Vec<(Arc<EncryptedContent<P, T>>, SymmetricKey)> = vec![];
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

    #[instrument(skip_all)]
    pub fn into_archive(&self) -> DocumentArchive<T> {
        DocumentArchive {
            group: self.group.into_archive(),
            content_heads: self.content_heads.clone(),
            content_state: self.content_state.clone(),
            cgka: self.cgka.clone(),
        }
    }

    pub(crate) fn dummy_from_archive(
        archive: DocumentArchive<T>,
        delegations: DelegationStore<S, T, L>,
        revocations: RevocationStore<S, T, L>,
        listener: L,
    ) -> Result<Self, MissingIndividualError> {
        Ok(Document {
            group: Group::<S, T, L>::dummy_from_archive(
                archive.group,
                delegations,
                revocations,
                listener,
            ),
            content_heads: archive.content_heads,
            content_state: archive.content_state,
            known_decryption_keys: HashMap::new(),
            cgka: archive.cgka,
        })
    }
}

impl<S: AsyncSigner, T: ContentRef, L: MembershipListener<S, T>> Verifiable for Document<S, T, L> {
    fn verifying_key(&self) -> VerifyingKey {
        self.group.verifying_key()
    }
}

impl<S: AsyncSigner, T: ContentRef, L: MembershipListener<S, T>> Hash for Document<S, T, L> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.group.hash(state);
        crate::util::hasher::hash_set(&self.content_heads, state);
        crate::util::hasher::hash_set(&self.content_state, state);
        self.cgka.hash(state);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddMemberUpdate<
    S: AsyncSigner,
    T: ContentRef = [u8; 32],
    L: MembershipListener<S, T> = NoListener,
> {
    pub delegation: Arc<Signed<Delegation<S, T, L>>>,
    pub cgka_ops: Vec<Signed<CgkaOperation>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("Missing individual: {0}")]
pub struct MissingIndividualError(pub Box<IndividualId>);

#[derive(Debug, Clone, PartialEq)]
pub struct RevokeMemberUpdate<
    S: AsyncSigner,
    T: ContentRef = [u8; 32],
    L: MembershipListener<S, T> = NoListener,
> {
    pub(crate) revocations: Vec<Arc<Signed<Revocation<S, T, L>>>>,
    pub(crate) redelegations: Vec<Arc<Signed<Delegation<S, T, L>>>>,
    pub(crate) cgka_ops: Vec<Signed<CgkaOperation>>,
}

impl<S: AsyncSigner, T: ContentRef, L: MembershipListener<S, T>> RevokeMemberUpdate<S, T, L> {
    #[allow(clippy::type_complexity)]
    pub fn revocations(&self) -> &[Arc<Signed<Revocation<S, T, L>>>] {
        &self.revocations
    }

    #[allow(clippy::type_complexity)]
    pub fn redelegations(&self) -> &[Arc<Signed<Delegation<S, T, L>>>] {
        &self.redelegations
    }

    #[allow(clippy::type_complexity)]
    pub fn cgka_ops(&self) -> &[Signed<CgkaOperation>] {
        &self.cgka_ops
    }
}

impl<S: AsyncSigner, T: ContentRef, L: MembershipListener<S, T>> Default
    for RevokeMemberUpdate<S, T, L>
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
pub enum AddMemberError {
    #[error(transparent)]
    AddMemberError(#[from] AddGroupMemberError),

    #[error(transparent)]
    CgkaError(#[from] CgkaError),
}

#[derive(Debug, Error)]
pub enum EncryptError {
    #[error("Encryption failed: {0}")]
    EncryptionFailed(chacha20poly1305::Error),

    #[error("Unable to PCS update: {0}")]
    UnableToPcsUpdate(CgkaError),

    #[error("Failed to make app secret: {0}")]
    FailedToMakeAppSecret(CgkaError),
}

#[derive(Debug, Error)]
pub enum GenerateDocError {
    #[error(transparent)]
    DelegationError(#[from] DelegationError),

    #[error(transparent)]
    SigningError(#[from] SigningError),

    #[error(transparent)]
    CgkaError(#[from] CgkaError),
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
pub enum TryFromDocumentArchiveError<S: AsyncSigner, T: ContentRef> {
    #[error("Cannot find individual: {0}")]
    MissingIndividual(IndividualId),

    #[error("Cannot find delegation: {0}")]
    MissingDelegation(Digest<Signed<Delegation<S, T>>>),

    #[error("Cannot find revocation: {0}")]
    MissingRevocation(Digest<Signed<Revocation<S, T>>>),
}

impl<S: AsyncSigner, T: ContentRef> From<MissingDependency<Digest<Signed<Delegation<S, T>>>>>
    for TryFromDocumentArchiveError<S, T>
{
    fn from(e: MissingDependency<Digest<Signed<Delegation<S, T>>>>) -> Self {
        TryFromDocumentArchiveError::MissingDelegation(e.0)
    }
}
