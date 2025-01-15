pub mod id;

use super::{individual::id::IndividualId, verifiable::Verifiable};
use crate::{
    access::Access,
    cgka::{error::CgkaError, keys::ShareKeyMap, operation::CgkaOperation, Cgka},
    content::reference::ContentRef,
    crypto::{
        digest::Digest,
        encrypted::Encrypted,
        share_key::{ShareKey, ShareSecretKey},
        signed::Signed,
    },
    principal::{
        active::Active,
        agent::{id::AgentId, Agent},
        group::{
            error::AddError,
            operation::{
                delegation::{Delegation, DelegationError},
                revocation::Revocation,
            },
            Group, RevokeMemberError,
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
    pub(crate) cgka: Cgka,
}

impl<T: ContentRef> Document<T> {
    // NOTE doesn't register into the top-level Beehive context
    pub fn from_group(group: Group<T>, viewer: &Active) -> Result<Self, CgkaError> {
        let doc_id = DocumentId(group.verifying_key().into());
        let mut doc = Document {
            cgka: Cgka::new(doc_id, viewer.id(), viewer.pick_prekey(doc_id))?,
            group,
            reader_keys: Default::default(),
            content_heads: Default::default(),
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

    pub fn members(&self) -> &HashMap<AgentId, Vec<Rc<Signed<Delegation<T>>>>> {
        self.group.members()
    }

    pub fn transitive_members(&self) -> HashMap<AgentId, (Agent<T>, Access)> {
        self.group.transitive_members()
    }

    pub fn delegation_heads(&self) -> &CaMap<Signed<Delegation<T>>> {
        self.group.delegation_heads()
    }

    pub fn get_capabilty(&self, member_id: &AgentId) -> Option<&Rc<Signed<Delegation<T>>>> {
        self.group.get_capability(member_id)
    }

    pub fn generate<R: rand::RngCore + rand::CryptoRng>(
        parents: NonEmpty<Agent<T>>,
        delegations: Rc<RefCell<CaMap<Signed<Delegation<T>>>>>,
        revocations: Rc<RefCell<CaMap<Signed<Revocation<T>>>>>,
        csprng: &mut R,
    ) -> Result<Self, DelegationError> {
        let sk = ed25519_dalek::SigningKey::generate(csprng);

        let group = parents.iter().try_fold(
            Group::generate(parents.clone(), delegations, revocations, csprng)?,
            |mut acc, parent| {
                let dlg = Signed::try_sign(
                    Delegation {
                        delegate: parent.dupe(),
                        can: Access::Admin,
                        proof: None,
                        after_revocations: vec![],
                        after_content: BTreeMap::new(),
                    },
                    &sk,
                )?;
                let rc = Rc::new(dlg);
                acc.state.delegation_heads.insert(rc.dupe());
                acc.members.insert(parent.agent_id(), vec![rc]);
                Ok::<Group<T>, DelegationError>(acc)
            },
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
        let mut cgka = Cgka::new(doc_id, owner_id, owner_share_key)
            .expect("FIXME")
            .with_new_owner(owner_id, owner_sks)
            .expect("FIXME");
        let mut ops: Vec<CgkaOperation> = Vec::new();
        if other_members.len() > 1 {
            ops.extend(
                cgka.add_multiple(
                    NonEmpty::from_vec(other_members).expect("there to be multiple other members"),
                )
                .expect("FIXME")
                .iter()
                .cloned(),
            );
        }
        let (_pcs_key, update_op) = cgka
            .update(owner_share_key, owner_share_secret_key, csprng)
            .expect("FIXME");
        // FIXME: We don't currently do anything with these ops, but need to share them
        // across the network.
        ops.push(update_op);
        Ok(Document {
            group,
            reader_keys: HashMap::new(), // FIXME
            content_state: HashSet::new(),
            content_heads: HashSet::new(),
            cgka,
        })
    }

    pub fn add_member(&mut self, signed_delegation: Signed<Delegation<T>>) -> Vec<CgkaOperation> {
        // FIXME check subject, signature, find dependencies or quarantine
        // ...look at the quarantine and see if any of them depend on this one
        // ...etc etc
        // FIXME check that delegation is authorized
        let agent_id = signed_delegation.payload().delegate.agent_id();
        let rc = Rc::new(signed_delegation);
        match self.group.members.get_mut(&agent_id) {
            Some(caps) => {
                caps.push(rc.clone());
            }
            None => {
                self.group.members.insert(agent_id, vec![rc.clone()]);
            }
        }
        let mut ops = Vec::new();
        for (id, pre_key) in rc
            .clone()
            .payload()
            .delegate
            .pick_individual_prekeys(self.doc_id())
        {
            let op = self.cgka.add(id, pre_key).expect("FIXME");
            ops.push(op);
        }
        // FIXME: We don't currently do anything with these ops, but need to share them
        // across the network.
        ops
    }

    pub fn revoke_member(
        &mut self,
        member_id: AgentId,
        signing_key: &ed25519_dalek::SigningKey,
        after_other_doc_content: &mut BTreeMap<DocumentId, Vec<T>>,
    ) -> Result<(Vec<Rc<Signed<Revocation<T>>>>, Vec<CgkaOperation>), RevokeMemberError> {
        // FIXME: Convert revocations into CgkaOperations by calling remove on Cgka.
        // FIXME: We need to check if this has revoked the last member in our group?
        let mut ops = Vec::new();
        if let Some(delegations) = self.group.members.get(&member_id) {
            for id in delegations
                .iter()
                .flat_map(|d| d.payload().delegate.individual_ids())
            {
                let op = self.cgka.remove(id).expect("FIXME");
                ops.push(op);
            }
        }

        after_other_doc_content.insert(self.doc_id(), self.content_state.iter().cloned().collect());
        let revs = self
            .group
            .revoke_member(member_id, signing_key, &after_other_doc_content)?;

        Ok((revs, ops))
    }

    pub fn get_agent_revocations(&self, agent: &Agent<T>) -> Vec<Rc<Signed<Revocation<T>>>> {
        self.group.get_agent_revocations(agent)
    }

    pub fn rebuild(&mut self) {
        self.group.rebuild()
    }

    pub fn receive_delegation(
        &mut self,
        signed_delegation: Rc<Signed<Delegation<T>>>,
    ) -> Result<Digest<Signed<Delegation<T>>>, AddError> {
        let digest = self.group.receive_delegation(signed_delegation)?;
        self.rebuild();
        Ok(digest)
    }

    pub fn receive_revocation(
        &mut self,
        signed_revocation: Rc<Signed<Revocation<T>>>,
    ) -> Result<Digest<Signed<Revocation<T>>>, AddError> {
        let hash = self.group.receive_revocation(signed_revocation)?;
        self.rebuild();
        Ok(hash)
    }

    pub fn pcs_update<R: rand::RngCore + rand::CryptoRng>(
        &mut self,
        csprng: &mut R,
    ) -> Result<(), EncryptError> {
        let new_share_secret_key = ShareSecretKey::generate(csprng);
        let new_share_key = new_share_secret_key.share_key();
        let (_, _op) = self
            .cgka
            .update(new_share_key, new_share_secret_key, csprng)
            .map_err(EncryptError::UnableToPcsUpdate)?;
        // FIXME: We need to share this op over the network.
        Ok(())
    }

    pub fn try_encrypt_content<R: rand::RngCore + rand::CryptoRng>(
        &mut self,
        content_ref: &T,
        content: &[u8],
        pred_refs: &Vec<T>,
        csprng: &mut R,
    ) -> Result<(Encrypted<Vec<u8>, T>, Option<CgkaOperation>), EncryptError> {
        let (app_secret, maybe_update_op) = self
            .cgka
            .new_app_secret_for(content_ref, content, pred_refs, csprng)
            .map_err(EncryptError::FailedToMakeAppSecret)?;

        Ok((
            app_secret
                .try_encrypt(content)
                .map_err(EncryptError::EncryptionFailed)?,
            maybe_update_op,
        ))
    }

    pub fn try_decrypt_content(
        &mut self,
        encrypted_content: &Encrypted<Vec<u8>, T>,
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

impl<T: ContentRef> Verifiable for Document<T> {
    fn verifying_key(&self) -> VerifyingKey {
        self.group.verifying_key()
    }
}
