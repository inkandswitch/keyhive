pub mod id;
pub mod store;

use super::{active::Active, individual::id::IndividualId, verifiable::Verifiable};
use crate::{
    access::Access,
    cgka::{error::CgkaError, keys::ShareKeyMap, Cgka},
    content::reference::ContentRef,
    crypto::{
        encrypted::Encrypted,
        share_key::{ShareKey, ShareSecretKey},
        signed::{Signed, SigningError},
    },
    principal::{
        agent::{Agent, AgentId},
        group::{
            operation::{
                delegation::{Delegation, DelegationError},
                revocation::Revocation,
                AncestorError,
            },
            Group,
        },
        identifier::Identifier,
        individual::Individual,
    },
    util::content_addressed_map::CaMap,
};
use dupe::Dupe;
use ed25519_dalek::VerifyingKey;
use id::DocumentId;
use nonempty::NonEmpty;
use std::{
    cell::RefCell,
    collections::{BTreeMap, HashMap, HashSet},
    rc::Rc,
};
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Document<T: ContentRef> {
    pub(crate) group: Group<T>,
    pub(crate) reader_keys: HashMap<IndividualId, (Rc<Individual>, ShareKey)>,

    pub(crate) content_heads: HashSet<T>,
    pub(crate) content_state: HashSet<T>,

    // FIXME: This doesn't work right now because Cgka is not Eq or PartialEq
    pub(crate) cgka: Cgka,
}

impl<T: ContentRef> Document<T> {
    pub fn id(&self) -> Identifier {
        self.group.id()
    }

    pub fn doc_id(&self) -> DocumentId {
        DocumentId(self.group.id())
    }

    pub fn agent_id(&self) -> AgentId {
        self.doc_id().into()
    }

    pub fn members(&self) -> &HashMap<AgentId, Vec<Rc<Signed<Delegation<T>>>>> {
        self.group.members()
    }

    pub fn delegations(&self) -> &CaMap<Signed<Delegation<T>>> {
        self.group.delegations()
    }

    pub fn get_capabilty(&self, member_id: &AgentId) -> Option<&Rc<Signed<Delegation<T>>>> {
        self.group.get_capability(member_id)
    }

    pub fn generate<R: rand::RngCore + rand::CryptoRng>(
        parents: NonEmpty<Agent<T>>,
        csprng: &mut R,
    ) -> Result<Self, DelegationError> {
        let doc_signer = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
        let group =
            parents
                .iter()
                .try_fold(Group::generate(parents.clone())?, |mut acc, parent| {
                    let dlg = Signed::try_sign(
                        Delegation {
                            delegate: parent.dupe(),
                            can: Access::Admin,
                            proof: None,
                            after_revocations: vec![],
                            after_content: BTreeMap::new(),
                        },
                        &doc_signer,
                    )?;

                    let rc = Rc::new(dlg);
                    acc.state.delegations.insert(rc.dupe());
                    acc.state.delegation_heads.insert(rc.dupe());
                    acc.members.insert(parent.agent_id(), vec![rc]);

                    Ok::<Group<T>, DelegationError>(acc)
                })?;

        // FIXME: Active in the document
        let owner_id = IndividualId(Identifier((&doc_signer).into()));
        let doc_id = DocumentId(group.id());
        let owner_share_secret_key = ShareSecretKey::generate(csprng);
        let owner_share_key = owner_share_secret_key.share_key();
        let mut owner_active = Active::generate(doc_signer, csprng)?;
        owner_active
            .prekey_pairs
            .insert(owner_share_key, owner_share_secret_key);

        let group_members = group.pick_individual_prekeys(csprng);
        let active_member = (owner_id, owner_share_key);
        let other_members: Vec<(IndividualId, ShareKey)> = group_members
            .iter()
            .filter(|(id, _sk)| **id != owner_id)
            .map(|(id, pk)| (*id, *pk))
            .collect();
        let cgka_members = NonEmpty::from((active_member, other_members));
        let mut owner_sks = ShareKeyMap::new();
        owner_sks.insert(owner_share_key, owner_share_secret_key);
        let cgka = Cgka::new(cgka_members, doc_id, owner_id)
            .expect("FIXME")
            .with_new_owner(owner_id, owner_share_key, owner_sks)
            .expect("FIXME");

        Ok(Document {
            group,
            reader_keys: Default::default(), // FIXME
            content_state: Default::default(),
            content_heads: Default::default(),
            cgka,
        })
    }

    pub fn add_member(&mut self, signed_delegation: Signed<Delegation<T>>) {
        // FIXME check subject, signature, find dependencies or quarantine
        // ...look at the quarantine and see if any of them depend on this one
        // ...etc etc
        // FIXME check that delegation is authorized
        let id = signed_delegation.payload().delegate.agent_id();
        let rc = Rc::new(signed_delegation);

        match self.group.members.get_mut(&id) {
            Some(caps) => {
                caps.push(rc);
            }
            None => {
                self.group.members.insert(id, vec![rc]);
            }
        }
    }

    pub fn revoke_member(
        &mut self,
        member_id: AgentId,
        signing_key: &ed25519_dalek::SigningKey,
        relevant_docs: &[&Rc<RefCell<Document<T>>>],
    ) -> Result<(), SigningError> {
        self.group
            .revoke_member(member_id, signing_key, relevant_docs)
    }

    pub fn get_agent_revocations(&self, agent: &Agent<T>) -> Vec<Rc<Signed<Revocation<T>>>> {
        self.group.get_agent_revocations(agent)
    }

    pub fn materialize(&mut self) -> Result<(), AncestorError> {
        self.group.materialize()
    }

    pub fn has_pcs_key(&self) -> bool {
        self.cgka.has_pcs_key()
    }

    pub fn pcs_update<R: rand::RngCore + rand::CryptoRng>(
        &mut self,
        csprng: &mut R,
    ) -> Result<(), EncryptError> {
        let new_share_secret_key = ShareSecretKey::generate(csprng);
        let new_share_key = new_share_secret_key.share_key();
        self.cgka
            .update(new_share_key, new_share_secret_key, csprng)
            .map_err(EncryptError::UnableToPcsUpdate)?;
        Ok(())
    }

    pub fn try_encrypt_content<R: rand::RngCore + rand::CryptoRng>(
        &mut self,
        content_ref: &T,
        content: &[u8],
        pred_refs: &Vec<T>,
        csprng: &mut R,
        // FIXME: What error return type?
    ) -> Result<Encrypted<Vec<u8>, T>, EncryptError> {
        // FIXME: We are automatically doing a PCS update if the tree doesn't have a
        // root secret. That might make sense, but do we need to store this key pair
        // on our Active member?
        if !self.cgka.has_pcs_key() {
            self.pcs_update(csprng)?;
        }
        let app_secret = self
            .cgka
            .new_app_secret_for(content_ref, content, pred_refs, csprng)
            .map_err(EncryptError::FailedToMakeAppSecret)?;

        app_secret
            .try_encrypt(content)
            .map_err(EncryptError::EncryptionFailed)
    }

    pub fn try_decrypt_content(
        &mut self,
        encrypted_content: &Encrypted<Vec<u8>, T>,
        // FIXME: What error return type?
    ) -> Result<Vec<u8>, DecryptError> {
        let decrypt_key = self
            .cgka
            .decryption_key_for(encrypted_content)
            .map_err(|_| DecryptError::KeyNotFound)?;

        let mut plaintext = encrypted_content.ciphertext.clone();
        decrypt_key
            .try_decrypt(encrypted_content.nonce, &mut plaintext)
            .map_err(DecryptError::DecryptionFailed)?;
        Ok(plaintext)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum EncryptError {
    #[error("Encryption failed: {0}")]
    EncryptionFailed(chacha20poly1305::Error),

    #[error("Unable to PCS update: {0}")]
    UnableToPcsUpdate(CgkaError),

    #[error("Failed to make app secret: {0}")]
    FailedToMakeAppSecret(CgkaError),
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum DecryptError {
    #[error("Key not found")]
    KeyNotFound,

    #[error("Decryption error: {0}")]
    DecryptionFailed(chacha20poly1305::Error),
}

// FIXME test
impl<T: ContentRef> std::hash::Hash for Document<T> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.group.hash(state);

        for key in self.reader_keys.keys() {
            key.hash(state);
        }

        for c in self.content_state.iter() {
            c.hash(state);
        }
    }
}

impl<T: ContentRef> Verifiable for Document<T> {
    fn verifying_key(&self) -> VerifyingKey {
        self.group.verifying_key()
    }
}
