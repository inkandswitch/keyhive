pub mod id;
pub mod store;

use super::{
    active::Active, group::operation::Operation, individual::id::IndividualId,
    verifiable::Verifiable,
};
use crate::{
    access::Access,
    cgka::{
        error::CgkaError,
        keys::ShareKeyMap,
        operation::{CgkaOperation, CgkaOperationGraph},
        Cgka,
    },
    content::reference::ContentRef,
    crypto::{
        digest::Digest,
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
    collections::{BTreeMap, HashMap, HashSet, VecDeque},
    rc::Rc,
};
use thiserror::Error;
use topological_sort::TopologicalSort;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Document<T: ContentRef> {
    pub(crate) group: Group<T>,
    pub(crate) reader_keys: HashMap<IndividualId, (Rc<Individual>, ShareKey)>,

    pub(crate) content_heads: HashSet<T>,
    pub(crate) content_state: HashSet<T>,

    pub(crate) cgka: Cgka,
    pub(crate) cgka_op_to_membership_op: HashMap<Digest<CgkaOperation>, Operation<T>>,
    pub(crate) membership_op_to_cgka_op: HashMap<Operation<T>, Digest<CgkaOperation>>,
    // FIXME
    // pub(crate) cgka_ops_graph: CgkaOperationGraph<T>,
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
        let mut cgka = Cgka::new(&cgka_members, doc_id, owner_id)
            .expect("FIXME")
            .with_new_owner(owner_id, owner_share_key, owner_sks)
            .expect("FIXME");
        let initial_op = cgka
            .update(owner_share_key, owner_share_secret_key, csprng)
            .expect("FIXME");
        // let initial_op_hash = Digest::hash(&initial_op);
        let mut cgka_ops_graph = CgkaOperationGraph::new();
        cgka_ops_graph.add_local_op(&initial_op);

        // let mut cgka_ops_predecessors = HashMap::new();
        // cgka_ops_predecessors.insert(initial_op_hash, Default::default());
        // let mut cgka_ops = CaMap::new();
        // cgka_ops.insert(initial_op.into());
        // let mut cgka_op_heads = HashSet::new();
        // cgka_op_heads.insert(initial_op_hash);

        Ok(Document {
            group,
            reader_keys: Default::default(), // FIXME
            content_state: Default::default(),
            content_heads: Default::default(),
            cgka,
            cgka_op_to_membership_op: Default::default(),
            membership_op_to_cgka_op: Default::default(),
        })
    }

    pub fn add_member<R: rand::CryptoRng + rand::RngCore>(
        &mut self,
        signed_delegation: Signed<Delegation<T>>,
        csprng: &mut R,
    ) {
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
        // FIXME: Get individual ids/pre_keys for transitive members of added agent
        for (id, pre_key) in rc
            .clone()
            .payload()
            .delegate
            .pick_individual_prekeys(csprng)
        {
            // FIXME: We'll need Cgka to check for duplicate add ids
            let op = self.cgka.add(id, pre_key).expect("FIXME");
            self.cgka_op_to_membership_op
                .insert(Digest::hash(&op), rc.clone().into());
            self.membership_op_to_cgka_op
                .insert(rc.clone().into(), Digest::hash(&op));
        }
    }

    pub fn revoke_member(
        &mut self,
        member_id: AgentId,
        signing_key: &ed25519_dalek::SigningKey,
        relevant_docs: &[&Rc<RefCell<Document<T>>>],
    ) -> Result<(), SigningError> {
        // FIXME: We need to check if this has revoked the last member in our group?
        // for delegations in self.group.members.get(&member_id) {
        //     for delegation in delegations.flatmap(|d| {
        //         d.payload().individual_ids()
        //     }) {
        //         // FIXME: We'll need Cgka to check for duplicate remove ids
        //         self.cgka.remove(id).expect("FIXME");
        //     }
        // }
        // FIXME: This revocation needs to be predecessor to next pcs update CgkaOperation

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

    // // FIXME: Where should this logic go?
    pub fn rebuild_pcs_key(&mut self, pcs_update_head: Digest<CgkaOperation>) {
        let ops = self
            .cgka_ops_for_update_head(pcs_update_head)
            .iter()
            .map(|hash| {
                Rc::unwrap_or_clone(
                    self.cgka
                        .ops_graph()
                        .get_cgka_op(hash)
                        .expect("hash to be present")
                        .clone(),
                )
            })
            .collect::<Vec<CgkaOperation>>();
        if ops.is_empty() {
            panic!("FIXME");
        } else {
            let head = ops.first().expect("FIXME").clone();
            let tail = ops.iter().skip(1).cloned().collect::<Vec<_>>();
            let nonempty_ops = NonEmpty { head, tail };
            self.cgka
                .rebuild_pcs_key(self.doc_id(), nonempty_ops)
                .expect("FIXME");
        }
    }

    fn cgka_ops_for_update_head(
        &self,
        update_head: Digest<CgkaOperation>,
    ) -> Vec<Digest<CgkaOperation>> {
        // Topsort membership ops and updates separately.
        // To build total order, take updates until one has a dependency on a
        // membership op. Then take membership ops until all those dependencies are
        // found. Then go back to taking updates until one with a dependency on a
        // membership op is found. etc.

        let mut op_hashes = Vec::new();
        let mut dependencies = TopologicalSort::<Digest<CgkaOperation>>::new();
        let mut ordered_update_hashes = Vec::new();
        let mut membership_op_head_hashes = HashSet::new();

        let mut update_frontier = VecDeque::new();
        update_frontier.push_back(update_head);
        while let Some(op_hash) = update_frontier.pop_front() {
            let preds = self
                .cgka
                .ops_graph()
                .predecessors_for(&op_hash)
                .expect("FIXME");
            for update_pred in &preds.update_preds {
                dependencies.add_dependency(*update_pred, op_hash);
                update_frontier.push_back(*update_pred);
            }
            membership_op_head_hashes.extend(preds.membership_preds.clone());
        }
        for hash in dependencies.pop_all() {
            ordered_update_hashes.push(hash);
        }

        let (delegation_heads, revocation_heads) = membership_op_head_hashes
            .iter()
            .map(|cgka_hash| {
                self.cgka_op_to_membership_op
                    .get(cgka_hash)
                    .expect("hash to be in set")
            })
            .fold((HashSet::new(), HashSet::new()), |mut acc, op| {
                match op {
                    Operation::Delegation(d) => acc.0.insert(d.clone()),
                    Operation::Revocation(r) => acc.1.insert(r.clone()),
                };
                acc
            });
        let ordered_membership_ops =
            Operation::topsort(&delegation_heads, &revocation_heads).expect("FIXME");

        let mut update_idx = 0;
        let mut membership_idx = 0;
        while update_idx < ordered_update_hashes.len()
            && membership_idx < ordered_membership_ops.len()
        {
            if update_idx < ordered_update_hashes.len() {
                let update = ordered_update_hashes[update_idx];
                let preds = self
                    .cgka
                    .ops_graph()
                    .predecessors_for(&update)
                    .expect("FIXME");
                let mut membership_preds = preds
                    .membership_preds
                    .iter()
                    .cloned()
                    .map(|cgka_op| {
                        self.cgka_op_to_membership_op
                            .get(&cgka_op)
                            .expect("known op to be in map")
                    })
                    .collect::<HashSet<_>>();
                // FIXME: We assume we will see all preds. This should be guaranteed by
                // causal delivery but this could lead to an infinite loop as written.
                // Do we actually remove old operations in such a way in the Beehive
                // CRDT in such a way that this will never terminate for outdated predecessors?
                while !membership_preds.is_empty() {
                    let (_member_op_hash, member_op) = &ordered_membership_ops[membership_idx];
                    op_hashes.push(*self.membership_op_to_cgka_op.get(member_op).expect("FIXME"));
                    membership_preds.remove(member_op);
                    membership_idx += 1;
                }
                op_hashes.push(update);
                update_idx += 1;
            } else {
                while membership_idx < ordered_membership_ops.len() {
                    let (_member_op_hash, member_op) = &ordered_membership_ops[membership_idx];
                    op_hashes.push(*self.membership_op_to_cgka_op.get(member_op).expect("FIXME"));
                    membership_idx += 1;
                }
            }
        }

        // FIXME
        // let mut heads = HashSet::new();
        // for hash in op_hashes {
        //     let op = self.cgka_ops_graph.get_cgka_op(&hash).expect("op to be in graph");
        //     if matches!(op, CgkaOperation::Add { .. }) {
        //         if self.cgka_ops_graph.predecessors_for(&hash);
        //         for d in preds.deleg {
        //             heads.remove(h);
        //         }
        //         heads.insert(self.cgka_ops_graph.get_membership_op_for_cgka_op(&hash));
        //     }
        // }

        op_hashes
    }

    // FIXME: Remove
    // pub(crate) cgka_ops: CaMap<CgkaOperation>,
    // pub(crate) cgka_ops_predecessors: HashMap<Digest<CgkaOperation>, CgkaOperationPredecessors<T>>,
    // pub(crate) cgka_op_heads: HashSet<Digest<CgkaOperation>>,
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
