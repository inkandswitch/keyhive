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
        share_key::{ShareKey, ShareSecretKey},
        signed::{Signed, SigningError},
        signer::{async_signer::AsyncSigner, ephemeral::EphemeralSigner},
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
        individual::Individual,
    },
    store::{delegation::DelegationStore, revocation::RevocationStore},
    util::content_addressed_map::CaMap,
};
use derivative::Derivative;
use derive_where::derive_where;
use dupe::Dupe;
use ed25519_dalek::VerifyingKey;
use futures::{stream, TryStreamExt};
use id::DocumentId;
use nonempty::NonEmpty;
use std::{
    cell::RefCell,
    collections::{BTreeMap, HashMap, HashSet},
    hash::{Hash, Hasher},
    rc::Rc,
};
use thiserror::Error;

#[derive(Clone, Derivative)]
#[derive_where(Debug, PartialEq; T)]
pub struct Document<
    S: AsyncSigner,
    T: ContentRef = [u8; 32],
    L: MembershipListener<S, T> = NoListener,
> {
    pub(crate) group: Group<S, T, L>,
    pub(crate) reader_keys: HashMap<IndividualId, (Rc<RefCell<Individual>>, ShareKey)>,
    pub(crate) content_heads: HashSet<T>,
    pub(crate) content_state: HashSet<T>,
    pub(crate) cgka: Cgka,
}

impl<S: AsyncSigner, T: ContentRef, L: MembershipListener<S, T>> Document<S, T, L> {
    // NOTE doesn't register into the top-level Keyhive context
    pub fn from_group(
        group: Group<S, T, L>,
        viewer: &Active<S, L>,
        content_heads: NonEmpty<T>,
    ) -> Result<Self, CgkaError> {
        let doc_id = DocumentId(group.verifying_key().into());
        let doc_prekey = viewer
            .pick_prekey(doc_id)
            .ok_or(CgkaError::ShareKeyNotFound)?;

        let mut doc = Document {
            cgka: Cgka::new(doc_id, viewer.id(), doc_prekey)?,
            group,
            reader_keys: Default::default(),
            content_heads: content_heads.iter().cloned().collect(),
            content_state: Default::default(),
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
    pub fn members(&self) -> &HashMap<Identifier, NonEmpty<Rc<Signed<Delegation<S, T, L>>>>> {
        self.group.members()
    }

    pub fn transitive_members(&self) -> HashMap<Identifier, (Agent<S, T, L>, Access)> {
        self.group.transitive_members()
    }

    pub fn delegation_heads(&self) -> &CaMap<Signed<Delegation<S, T, L>>> {
        self.group.delegation_heads()
    }

    pub fn revocation_heads(&self) -> &CaMap<Signed<Revocation<S, T, L>>> {
        self.group.revocation_heads()
    }

    pub fn get_capability(
        &self,
        member_id: &Identifier,
    ) -> Option<&Rc<Signed<Delegation<S, T, L>>>> {
        self.group.get_capability(member_id)
    }

    pub async fn generate<R: rand::CryptoRng + rand::RngCore>(
        parents: NonEmpty<Agent<S, T, L>>,
        initial_content_heads: NonEmpty<T>,
        delegations: DelegationStore<S, T, L>,
        revocations: RevocationStore<S, T, L>,
        listener: L,
        signer: &S,
        csprng: &mut R,
    ) -> Result<Self, GenerateDocError> {
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

        let group = group_result?;
        let owner_id = IndividualId(group_vk.into());
        let doc_id = DocumentId(group.id());
        let owner_share_secret_key = ShareSecretKey::generate(csprng);
        let owner_share_key = owner_share_secret_key.share_key();
        let group_members = group.pick_individual_prekeys(doc_id);
        let other_members: Vec<(IndividualId, ShareKey)> = group_members
            .iter()
            .filter(|(id, _sk)| **id != owner_id)
            .map(|(id, pk)| (*id, *pk))
            .collect();
        let mut owner_sks = ShareKeyMap::new();
        owner_sks.insert(owner_share_key, owner_share_secret_key);
        let mut cgka =
            Cgka::new(doc_id, owner_id, owner_share_key)?.with_new_owner(owner_id, owner_sks)?;
        let mut ops: Vec<Signed<CgkaOperation>> = Vec::new();
        if other_members.len() > 1 {
            ops.extend(
                cgka.add_multiple(
                    NonEmpty::from_vec(other_members).expect("there to be multiple other members"),
                    signer,
                )
                .await?
                .iter()
                .cloned(),
            );
        }
        let (_pcs_key, update_op) = cgka
            .update(owner_share_key, owner_share_secret_key, signer, csprng)
            .await?;
        // FIXME: We don't currently do anything with these ops, but need to share them
        // across the network.
        ops.push(update_op);
        Ok(Document {
            group,
            reader_keys: HashMap::new(), // FIXME
            content_state: HashSet::new(),
            content_heads: initial_content_heads.iter().cloned().collect(),
            cgka,
        })
    }

    pub async fn add_member(
        &mut self,
        member_to_add: Agent<S, T, L>,
        can: Access,
        signer: &S,
        other_relevant_docs: &[Rc<RefCell<Document<S, T, L>>>],
    ) -> Result<AddMemberUpdate<S, T, L>, AddMemberError> {
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

        Ok(self
            .group
            .add_member_with_manual_content(member_to_add.dupe(), can, signer, after_content)
            .await?)
    }

    pub async fn add_cgka_member(
        &mut self,
        delegation: &Signed<Delegation<S, T, L>>,
        signer: &S,
    ) -> Result<Vec<Signed<CgkaOperation>>, CgkaError> {
        let prekeys = delegation
            .dupe()
            .payload()
            .delegate
            .pick_individual_prekeys(self.doc_id());

        let cell = Rc::new(RefCell::new(self));

        Ok(stream::iter(prekeys.iter().map(Ok::<_, CgkaError>))
            .try_fold(vec![], |mut acc, (id, pre_key)| async {
                if let Some(op) = cell.borrow_mut().cgka.add(*id, *pre_key, signer).await? {
                    acc.push(op);
                }
                Ok::<_, CgkaError>(acc)
            })
            .await?)
    }

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
        let mut ops = cgka_ops;
        if let Some(delegations) = self.group.members.get(&member_id) {
            for id in delegations
                .iter()
                .flat_map(|d| d.payload().delegate.individual_ids())
            {
                if let Some(op) = self.cgka.remove(id, signer).await? {
                    ops.push(op);
                }
            }
        }

        Ok(RevokeMemberUpdate {
            revocations,
            redelegations,
            cgka_ops: ops,
        })
    }

    pub async fn remove_cgka_member(
        &mut self,
        id: IndividualId,
        signer: &S,
    ) -> Result<Option<Signed<CgkaOperation>>, CgkaError> {
        self.cgka.remove(id, signer).await
    }

    pub fn get_agent_revocations(
        &self,
        agent: &Agent<S, T, L>,
    ) -> Vec<Rc<Signed<Revocation<S, T, L>>>> {
        self.group.get_agent_revocations(agent)
    }

    pub fn rebuild(&mut self) {
        self.group.rebuild()
    }

    pub fn receive_delegation(
        &mut self,
        delegation: Rc<Signed<Delegation<S, T, L>>>,
    ) -> Result<Digest<Signed<Delegation<S, T, L>>>, AddError> {
        self.group.receive_delegation(delegation)
    }

    pub fn receive_revocation(
        &mut self,
        revocation: Rc<Signed<Revocation<S, T, L>>>,
    ) -> Result<Digest<Signed<Revocation<S, T, L>>>, AddError> {
        self.group.receive_revocation(revocation)
    }

    pub fn merge_cgka_op(&mut self, op: Rc<Signed<CgkaOperation>>) -> Result<(), CgkaError> {
        self.cgka.merge_concurrent_operation(op)
    }

    pub fn merge_cgka_invite_op(
        &mut self,
        op: Rc<Signed<CgkaOperation>>,
        sk: &ShareSecretKey,
    ) -> Result<(), CgkaError> {
        let CgkaOperation::Add { added_id, pk, .. } = op.payload else {
            return Err(CgkaError::UnexpectedInviteOperation);
        };
        let mut owner_sks = self.cgka.owner_sks.clone();
        owner_sks.insert(pk.clone(), sk.clone());
        self.cgka = self.cgka.with_new_owner(added_id, owner_sks)?;
        self.merge_cgka_op(op)
    }

    pub fn cgka_ops(&self) -> Result<NonEmpty<CgkaEpoch>, CgkaError> {
        self.cgka.ops()
    }

    pub async fn pcs_update<R: rand::RngCore + rand::CryptoRng>(
        &mut self,
        signer: &S,
        csprng: &mut R,
    ) -> Result<Signed<CgkaOperation>, EncryptError> {
        let new_share_secret_key = ShareSecretKey::generate(csprng);
        let new_share_key = new_share_secret_key.share_key();
        let (_, op) = self
            .cgka
            .update(new_share_key, new_share_secret_key, signer, csprng)
            .await
            .map_err(EncryptError::UnableToPcsUpdate)?;
        Ok(op)
    }

    pub async fn try_encrypt_content<R: rand::CryptoRng + rand::RngCore>(
        &mut self,
        content_ref: &T,
        content: &[u8],
        pred_refs: &Vec<T>,
        signer: &S,
        csprng: &mut R,
    ) -> Result<EncryptedContentWithUpdate<T>, EncryptError> {
        let (app_secret, maybe_update_op) = self
            .cgka
            .new_app_secret_for(content_ref, content, pred_refs, signer, csprng)
            .await
            .map_err(EncryptError::FailedToMakeAppSecret)?;

        Ok(EncryptedContentWithUpdate {
            encrypted_content: app_secret
                .try_encrypt(content)
                .map_err(EncryptError::EncryptionFailed)?,
            update_op: maybe_update_op,
        })
    }

    pub fn try_decrypt_content(
        &mut self,
        encrypted_content: &EncryptedContent<Vec<u8>, T>,
    ) -> Result<Vec<u8>, DecryptError> {
        let decrypt_key = self
            .cgka
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
        // let expected_siv = Siv::new(&decrypt_key, &plaintext, self.doc_id())?;
        // if expected_siv != encrypted_content.nonce {
        //     Err(DecryptError::SivMismatch)?;
        // }
        Ok(plaintext)
    }

    pub fn into_archive(&self) -> DocumentArchive<T> {
        DocumentArchive {
            group: self.group.into_archive(),
            reader_keys: self
                .reader_keys
                .iter()
                .map(|(id, (_, share_key))| (*id, *share_key))
                .collect(),
            content_heads: self.content_heads.clone(),
            content_state: self.content_state.clone(),
            cgka: self.cgka.clone(),
        }
    }

    pub(crate) fn dummy_from_archive(
        archive: DocumentArchive<T>,
        individuals: &HashMap<IndividualId, Rc<RefCell<Individual>>>,
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
            reader_keys: archive.reader_keys.into_iter().try_fold(
                HashMap::new(),
                |mut acc, (id, share_key)| {
                    acc.insert(
                        id,
                        (
                            individuals
                                .get(&id)
                                .ok_or(MissingIndividualError(Box::new(id)))?
                                .dupe(),
                            share_key,
                        ),
                    );
                    Ok(acc)
                },
            )?,
            content_heads: archive.content_heads,
            content_state: archive.content_state,
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
        crate::util::hasher::hash_map_keys(&self.reader_keys, state);
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
    pub delegation: Rc<Signed<Delegation<S, T, L>>>,
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
    pub(crate) revocations: Vec<Rc<Signed<Revocation<S, T, L>>>>,
    pub(crate) redelegations: Vec<Rc<Signed<Delegation<S, T, L>>>>,
    pub(crate) cgka_ops: Vec<Signed<CgkaOperation>>,
}

impl<S: AsyncSigner, T: ContentRef, L: MembershipListener<S, T>> RevokeMemberUpdate<S, T, L> {
    pub fn revocations(&self) -> &[Rc<Signed<Revocation<S, T, L>>>] {
        &self.revocations
    }

    pub fn redelegations(&self) -> &[Rc<Signed<Delegation<S, T, L>>>] {
        &self.redelegations
    }

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
