pub mod id;

use super::{group::AddGroupMemberError, individual::id::IndividualId};
use crate::{
    access::Access,
    cgka::{error::CgkaError, keys::ShareKeyMap, operation::CgkaOperation, Cgka},
    content::reference::ContentRef,
    crypto::{
        digest::Digest,
        encrypted::EncryptedContent,
        share_key::{ShareKey, ShareSecretKey},
        signed::{Signed, SigningError},
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
            Group, GroupArchive, RevokeMemberError,
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
use id::DocumentId;
use nonempty::NonEmpty;
use serde::{Deserialize, Serialize};
use std::{
    cell::RefCell,
    collections::{BTreeMap, HashMap, HashSet},
    hash::{Hash, Hasher},
    rc::Rc,
};
use thiserror::Error;

#[derive(Debug, Clone, Eq, Derivative)]
#[derive_where(PartialEq; T)]
pub struct Document<T: ContentRef = [u8; 32], L: MembershipListener<T> = NoListener> {
    pub(crate) group: Group<T, L>,
    pub(crate) reader_keys: HashMap<IndividualId, (Rc<RefCell<Individual>>, ShareKey)>,
    pub(crate) content_heads: HashSet<T>,
    pub(crate) content_state: HashSet<T>,
    pub(crate) cgka: Cgka,
}

impl<T: ContentRef, L: MembershipListener<T>> Document<T, L> {
    // NOTE doesn't register into the top-level Keyhive context
    pub fn from_group(
        group: Group<T, L>,
        viewer: &Active<L>,
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
    pub fn members(&self) -> &HashMap<Identifier, NonEmpty<Rc<Signed<Delegation<T, L>>>>> {
        self.group.members()
    }

    pub fn transitive_members(&self) -> HashMap<Identifier, (Agent<T, L>, Access)> {
        self.group.transitive_members()
    }

    pub fn delegation_heads(&self) -> &CaMap<Signed<Delegation<T, L>>> {
        self.group.delegation_heads()
    }

    pub fn revocation_heads(&self) -> &CaMap<Signed<Revocation<T, L>>> {
        self.group.revocation_heads()
    }

    pub fn get_capability(&self, member_id: &Identifier) -> Option<&Rc<Signed<Delegation<T, L>>>> {
        self.group.get_capability(member_id)
    }

    pub fn generate<R: rand::RngCore + rand::CryptoRng>(
        parents: NonEmpty<Agent<T, L>>,
        initial_content_heads: NonEmpty<T>,
        delegations: DelegationStore<T, L>,
        revocations: RevocationStore<T, L>,
        listener: L,
        csprng: &mut R,
    ) -> Result<Self, GenerateDocError> {
        let sk = ed25519_dalek::SigningKey::generate(csprng);
        let group = Group::generate_after_content(
            &sk,
            parents,
            delegations,
            revocations,
            BTreeMap::from_iter([(
                DocumentId(sk.verifying_key().into()),
                initial_content_heads.clone().into_iter().collect(),
            )]),
            csprng,
            listener,
        )?;

        let owner_id = IndividualId(sk.verifying_key().into());
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
        let mut ops: Vec<CgkaOperation> = Vec::new();
        if other_members.len() > 1 {
            ops.extend(
                cgka.add_multiple(
                    NonEmpty::from_vec(other_members).expect("there to be multiple other members"),
                )?
                .iter()
                .cloned(),
            );
        }
        let (_pcs_key, update_op) = cgka.update(owner_share_key, owner_share_secret_key, csprng)?;
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

    pub fn add_member(
        &mut self,
        member_to_add: Agent<T, L>,
        can: Access,
        signing_key: &ed25519_dalek::SigningKey,
        other_relevant_docs: &[Rc<RefCell<Document<T, L>>>],
    ) -> Result<AddMemberUpdate<T, L>, AddMemberError> {
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

        Ok(self.group.add_member_with_manual_content(
            member_to_add.dupe(),
            can,
            signing_key,
            after_content,
        )?)
    }

    pub fn add_cgka_member(
        &mut self,
        delegation: &Signed<Delegation<T, L>>,
    ) -> Result<Vec<CgkaOperation>, CgkaError> {
        let mut ops = Vec::new();
        for (id, pre_key) in delegation
            .dupe()
            .payload()
            .delegate
            .pick_individual_prekeys(self.doc_id())
        {
            if let Some(op) = self.cgka.add(id, pre_key)? {
                ops.push(op);
            }
        }
        Ok(ops)
    }

    pub fn revoke_member(
        &mut self,
        member_id: Identifier,
        signing_key: &ed25519_dalek::SigningKey,
        after_other_doc_content: &mut BTreeMap<DocumentId, Vec<T>>,
    ) -> Result<RevokeMemberUpdate<T, L>, RevokeMemberError> {
        after_other_doc_content.insert(self.doc_id(), self.content_state.iter().cloned().collect());
        let revs = self
            .group
            .revoke_member(member_id, signing_key, after_other_doc_content)?;

        Ok(revs)
    }

    pub fn remove_cgka_member(
        &mut self,
        id: IndividualId,
    ) -> Result<Option<CgkaOperation>, CgkaError> {
        self.cgka.remove(id)
    }

    pub fn get_agent_revocations(&self, agent: &Agent<T, L>) -> Vec<Rc<Signed<Revocation<T, L>>>> {
        self.group.get_agent_revocations(agent)
    }

    pub fn rebuild(&mut self) {
        self.group.rebuild()
    }

    pub fn receive_delegation(
        &mut self,
        delegation: Rc<Signed<Delegation<T, L>>>,
    ) -> Result<Digest<Signed<Delegation<T, L>>>, AddError> {
        self.group.receive_delegation(delegation)
    }

    pub fn receive_revocation(
        &mut self,
        revocation: Rc<Signed<Revocation<T, L>>>,
    ) -> Result<Digest<Signed<Revocation<T, L>>>, AddError> {
        self.group.receive_revocation(revocation)
    }

    pub fn merge_cgka_op(&mut self, op: CgkaOperation) -> Result<(), CgkaError> {
        self.cgka.merge_concurrent_operation(Rc::new(op))
    }

    pub fn merge_cgka_invite_op(
        &mut self,
        op: CgkaOperation,
        sk: &ShareSecretKey,
    ) -> Result<(), CgkaError> {
        let CgkaOperation::Add { added_id, pk, .. } = op else {
            return Err(CgkaError::UnexpectedInviteOperation);
        };
        let mut owner_sks = self.cgka.owner_sks.clone();
        owner_sks.insert(pk.clone(), sk.clone());
        self.cgka = self.cgka.with_new_owner(added_id, owner_sks)?;
        self.merge_cgka_op(op)
    }

    pub fn pcs_update<R: rand::RngCore + rand::CryptoRng>(
        &mut self,
        csprng: &mut R,
    ) -> Result<CgkaOperation, EncryptError> {
        let new_share_secret_key = ShareSecretKey::generate(csprng);
        let new_share_key = new_share_secret_key.share_key();
        let (_, op) = self
            .cgka
            .update(new_share_key, new_share_secret_key, csprng)
            .map_err(EncryptError::UnableToPcsUpdate)?;
        Ok(op)
    }

    pub fn try_encrypt_content<R: rand::RngCore + rand::CryptoRng>(
        &mut self,
        content_ref: &T,
        content: &[u8],
        pred_refs: &Vec<T>,
        csprng: &mut R,
    ) -> Result<EncryptedContentWithUpdate<T>, EncryptError> {
        let (app_secret, maybe_update_op) = self
            .cgka
            .new_app_secret_for(content_ref, content, pred_refs, csprng)
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

    pub(crate) fn dummy_from_archive(
        archive: DocumentArchive<T>,
        individuals: &HashMap<IndividualId, Rc<RefCell<Individual>>>,
        delegations: DelegationStore<T, L>,
        revocations: RevocationStore<T, L>,
        listener: L,
    ) -> Result<Self, MissingIndividualError> {
        Ok(Document {
            group: Group::<T, L>::dummy_from_archive(
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

impl<T: ContentRef, L: MembershipListener<T>> Verifiable for Document<T, L> {
    fn verifying_key(&self) -> VerifyingKey {
        self.group.verifying_key()
    }
}

impl<T: ContentRef, L: MembershipListener<T>> Hash for Document<T, L> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.group.hash(state);
        crate::util::hasher::hash_map_keys(&self.reader_keys, state);
        crate::util::hasher::hash_set(&self.content_heads, state);
        crate::util::hasher::hash_set(&self.content_state, state);
        self.cgka.hash(state);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddMemberUpdate<T: ContentRef = [u8; 32], L: MembershipListener<T> = NoListener> {
    pub delegation: Rc<Signed<Delegation<T, L>>>,
    pub cgka_ops: Vec<CgkaOperation>,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("Missing individual: {0}")]
pub struct MissingIndividualError(pub Box<IndividualId>);

#[derive(Debug, Clone, PartialEq)]
pub struct RevokeMemberUpdate<T: ContentRef = [u8; 32], L: MembershipListener<T> = NoListener> {
    pub revocations: Vec<Rc<Signed<Revocation<T, L>>>>,
    pub cgka_ops: Vec<CgkaOperation>,
}

impl<T: ContentRef, L: MembershipListener<T>> Default for RevokeMemberUpdate<T, L> {
    fn default() -> Self {
        Self {
            revocations: Vec::new(),
            cgka_ops: Vec::new(),
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
    pub(crate) update_op: Option<CgkaOperation>,
}

impl<T: ContentRef> EncryptedContentWithUpdate<T> {
    pub fn encrypted_content(&self) -> &EncryptedContent<Vec<u8>, T> {
        &self.encrypted_content
    }

    pub fn update_op(&self) -> Option<&CgkaOperation> {
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct DocumentArchive<T: ContentRef> {
    pub(crate) group: GroupArchive<T>,
    pub(crate) reader_keys: HashMap<IndividualId, ShareKey>,
    pub(crate) content_heads: HashSet<T>,
    pub(crate) content_state: HashSet<T>,
    pub(crate) cgka: Cgka,
}

impl<T: ContentRef, L: MembershipListener<T>> From<Document<T, L>> for DocumentArchive<T> {
    fn from(doc: Document<T, L>) -> Self {
        DocumentArchive {
            group: doc.group.into(),
            reader_keys: doc
                .reader_keys
                .into_iter()
                .map(|(id, (_, share_key))| (id, share_key))
                .collect(),
            content_heads: doc.content_heads,
            content_state: doc.content_state,
            cgka: doc.cgka,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum TryFromDocumentArchiveError<T: ContentRef> {
    #[error("Cannot find individual: {0}")]
    MissingIndividual(IndividualId),

    #[error("Cannot find delegation: {0}")]
    MissingDelegation(Digest<Signed<Delegation<T>>>),

    #[error("Cannot find revocation: {0}")]
    MissingRevocation(Digest<Signed<Revocation<T>>>),
}

impl<T: ContentRef> From<MissingDependency<Digest<Signed<Delegation<T>>>>>
    for TryFromDocumentArchiveError<T>
{
    fn from(e: MissingDependency<Digest<Signed<Delegation<T>>>>) -> Self {
        TryFromDocumentArchiveError::MissingDelegation(e.0)
    }
}
