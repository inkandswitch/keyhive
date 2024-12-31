pub mod id;
pub mod store;
use super::{individual::id::IndividualId, verifiable::Verifiable};
use crate::{
    access::Access,
    cgka::{error::CgkaError, keys::ShareKeyMap, operation::CgkaOperation, Cgka},
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
pub struct Document<T: ContentRef, S: ed25519_dalek::Signer<ed25519_dalek::Signature> + Verifiable>
{
    pub(crate) group: Group<T, S>,
    pub(crate) reader_keys: HashMap<IndividualId, (Rc<Individual>, ShareKey)>,
    pub(crate) content_heads: HashSet<T>,
    pub(crate) content_state: HashSet<T>,
    pub(crate) cgka: Cgka,
}

impl<T: ContentRef, S: ed25519_dalek::Signer<ed25519_dalek::Signature> + Verifiable>
    Document<T, S>
{
    pub fn id(&self) -> Identifier {
        self.group.id()
    }

    pub fn doc_id(&self) -> DocumentId {
        DocumentId(self.group.id())
    }

    pub fn agent_id(&self) -> AgentId {
        self.doc_id().into()
    }

    pub fn members(&self) -> &HashMap<AgentId, Vec<Rc<Signed<Delegation<T, S>>>>> {
        self.group.members()
    }

    pub fn delegations(&self) -> &CaMap<Signed<Delegation<T, S>>> {
        self.group.delegations()
    }

    pub fn get_capabilty(&self, member_id: &AgentId) -> Option<&Rc<Signed<Delegation<T, S>>>> {
        self.group.get_capability(member_id)
    }

    pub fn generate<R: rand::RngCore + rand::CryptoRng>(
        parents: NonEmpty<Agent<T, S>>,
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

                    Ok::<Group<T, S>, DelegationError>(acc)
                })?;
        let owner_id = IndividualId(Identifier((&doc_signer).into()));
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
            reader_keys: Default::default(), // FIXME
            content_state: Default::default(),
            content_heads: Default::default(),
            cgka,
        })
    }

    pub fn add_member(
        &mut self,
        signed_delegation: Signed<Delegation<T, S>>,
    ) -> Vec<CgkaOperation> {
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
        relevant_docs: &[&Rc<RefCell<Document<T, S>>>],
    ) -> Result<(), SigningError> {
        // FIXME: Convert revocations into CgkaOperations by calling remove on Cgka.
        // FIXME: We need to check if this has revoked the last member in our group?
        // let mut ops = Vec::new();
        // for delegations in self.group.members.get(&member_id) {
        //     for delegation in delegations.flatmap(|d| {
        //         d.payload().individual_ids()
        //     }) {
        //         // FIXME: We'll need Cgka to check for duplicate remove ids
        //         let op = self.cgka.remove(id, csprng).expect("FIXME");
        //         ops.push(op);
        //     }
        // }
        self.group
            .revoke_member(member_id, signing_key, relevant_docs)
    }

    pub fn get_agent_revocations(&self, agent: &Agent<T, S>) -> Vec<Rc<Signed<Revocation<T, S>>>> {
        self.group.get_agent_revocations(agent)
    }

    pub fn materialize(&mut self) {
        self.group.materialize()
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

// FIXME test
impl<T: ContentRef, S: ed25519_dalek::Signer<ed25519_dalek::Signature> + Verifiable> std::hash::Hash
    for Document<T, S>
{
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

impl<T: ContentRef, S: ed25519_dalek::Signer<ed25519_dalek::Signature> + Verifiable> Verifiable
    for Document<T, S>
{
    fn verifying_key(&self) -> VerifyingKey {
        self.group.verifying_key()
    }
}
