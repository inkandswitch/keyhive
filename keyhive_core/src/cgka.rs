//! Thin wrapper around [`beekem::cgka::Cgka`] that converts between
//! keyhive_core domain IDs ([`IndividualId`] / [`DocumentId`]) and
//! beekem IDs ([`MemberId`](beekem::id::MemberId) /
//! [`TreeId`](beekem::id::TreeId)) at the API boundary.

use crate::{
    principal::{document::id::DocumentId, identifier::Identifier, individual::id::IndividualId},
    transact::{fork::Fork, merge::Merge},
};
use beekem::{
    encrypted::EncryptedContent,
    error::CgkaError,
    id::{MemberId, TreeId},
    keys::ShareKeyMap,
    operation::{CgkaEpoch, CgkaOperation},
    pcs_key::{ApplicationSecret, PcsKey},
};
use future_form::FutureForm;
use keyhive_crypto::{
    content::reference::ContentRef,
    digest::Digest,
    share_key::{ShareKey, ShareSecretKey},
    signed::Signed,
    signer::async_signer::AsyncSigner,
    symmetric_key::SymmetricKey,
    verifiable::Verifiable,
};
use nonempty::NonEmpty;
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    hash::{Hash, Hasher},
    sync::Arc,
};

/// Exposes CGKA (Continuous Group Key Agreement) operations like deriving
/// a new application secret, rotating keys, and adding and removing members
/// from the group.
///
/// A CGKA protocol is responsible for maintaining a stream of shared group keys
/// updated over time. We are using a variant of the TreeKEM protocol (which
/// we call BeeKEM) adapted for local-first contexts.
///
/// We assume that all operations are received in causal order (a property
/// guaranteed by Keyhive as a whole).
///
/// This is a thin wrapper around [`beekem::cgka::Cgka`] that converts between
/// keyhive_core domain IDs and beekem IDs at the API boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Cgka(beekem::cgka::Cgka);

impl Hash for Cgka {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

impl Cgka {
    pub async fn new<F: FutureForm, S: AsyncSigner<F>>(
        doc_id: DocumentId,
        owner_id: IndividualId,
        owner_pk: ShareKey,
        signer: &S,
    ) -> Result<Self, CgkaError> {
        beekem::cgka::Cgka::new(
            TreeId(doc_id.verifying_key()),
            MemberId(owner_id.verifying_key()),
            owner_pk,
            signer,
        )
        .await
        .map(Cgka)
    }

    pub fn new_from_init_add(
        doc_id: DocumentId,
        owner_id: IndividualId,
        owner_pk: ShareKey,
        init_add_op: Signed<CgkaOperation>,
    ) -> Result<Self, CgkaError> {
        beekem::cgka::Cgka::new_from_init_add(
            TreeId(doc_id.verifying_key()),
            MemberId(owner_id.verifying_key()),
            owner_pk,
            init_add_op,
        )
        .map(Cgka)
    }

    pub fn with_new_owner(
        &self,
        my_id: IndividualId,
        owner_sks: ShareKeyMap,
    ) -> Result<Self, CgkaError> {
        self.0
            .with_new_owner(MemberId(my_id.verifying_key()), owner_sks)
            .map(Cgka)
    }

    pub fn init_add_op(&self) -> Signed<CgkaOperation> {
        self.0.init_add_op()
    }

    pub fn ops_count(&self) -> usize {
        self.0.ops_count()
    }

    pub fn owner_sks(&self) -> &ShareKeyMap {
        &self.0.owner_sks
    }

    pub fn owner_sks_mut(&mut self) -> &mut ShareKeyMap {
        &mut self.0.owner_sks
    }

    pub async fn new_app_secret_for<
        F: FutureForm,
        S: AsyncSigner<F>,
        T: ContentRef,
        R: rand::CryptoRng + rand::RngCore,
    >(
        &mut self,
        content_ref: &T,
        content: &[u8],
        pred_refs: &Vec<T>,
        signer: &S,
        csprng: &mut R,
    ) -> Result<(ApplicationSecret<T>, Option<Signed<CgkaOperation>>), CgkaError> {
        self.0
            .new_app_secret_for(content_ref, content, pred_refs, signer, csprng)
            .await
    }

    pub fn decryption_key_for<T, Cr: ContentRef>(
        &mut self,
        encrypted: &EncryptedContent<T, Cr>,
    ) -> Result<SymmetricKey, CgkaError> {
        self.0.decryption_key_for(encrypted)
    }

    pub fn has_pcs_key(&self) -> bool {
        self.0.has_pcs_key()
    }

    pub async fn add<F: FutureForm, S: AsyncSigner<F>>(
        &mut self,
        id: IndividualId,
        pk: ShareKey,
        signer: &S,
    ) -> Result<Option<Signed<CgkaOperation>>, CgkaError> {
        self.0.add(MemberId(id.verifying_key()), pk, signer).await
    }

    pub async fn add_multiple<F: FutureForm, S: AsyncSigner<F>>(
        &mut self,
        members: NonEmpty<(IndividualId, ShareKey)>,
        signer: &S,
    ) -> Result<Vec<Signed<CgkaOperation>>, CgkaError> {
        let converted = members.map(|(id, pk)| (MemberId(id.verifying_key()), pk));
        self.0.add_multiple(converted, signer).await
    }

    pub async fn remove<F: FutureForm, S: AsyncSigner<F>>(
        &mut self,
        id: IndividualId,
        signer: &S,
    ) -> Result<Option<Signed<CgkaOperation>>, CgkaError> {
        self.0.remove(MemberId(id.verifying_key()), signer).await
    }

    pub async fn update<F: FutureForm, S: AsyncSigner<F>, R: rand::CryptoRng + rand::RngCore>(
        &mut self,
        new_pk: ShareKey,
        new_sk: ShareSecretKey,
        signer: &S,
        csprng: &mut R,
    ) -> Result<(PcsKey, Signed<CgkaOperation>), CgkaError> {
        self.0.update(new_pk, new_sk, signer, csprng).await
    }

    pub fn group_size(&self) -> u32 {
        self.0.group_size()
    }

    pub fn merge_concurrent_operation(
        &mut self,
        op: Arc<Signed<CgkaOperation>>,
    ) -> Result<bool, CgkaError> {
        self.0.merge_concurrent_operation(op)
    }

    pub fn ops(&self) -> Result<NonEmpty<CgkaEpoch>, CgkaError> {
        self.0.ops()
    }

    pub fn contains_predecessors(&self, preds: &HashSet<Digest<Signed<CgkaOperation>>>) -> bool {
        self.0.contains_predecessors(preds)
    }
}

impl Fork for Cgka {
    type Forked = Self;

    fn fork(&self) -> Self::Forked {
        self.clone()
    }
}

impl Merge for Cgka {
    fn merge(&mut self, fork: Self::Forked) {
        beekem::transact::Merge::merge(&mut self.0, fork.0);
    }
}

#[cfg(feature = "test_utils")]
impl Cgka {
    pub fn secret_from_root(&mut self) -> Result<PcsKey, CgkaError> {
        self.0.secret_from_root()
    }

    pub fn secret(
        &mut self,
        pcs_key_hash: &Digest<PcsKey>,
        update_op_hash: &Digest<Signed<CgkaOperation>>,
    ) -> Result<PcsKey, CgkaError> {
        self.0.secret(pcs_key_hash, update_op_hash)
    }
}

/// CGKA ops for all agents, with shared storage.
///
/// CGKA ops are stored per document. Each agent has an index pointing to the
/// documents whose CGKA ops it can reach (via `transitive_members`).
#[derive(Debug)]
pub struct AllCgkaOps {
    /// CGKA ops per doc, keyed by doc Identifier.
    pub ops: HashMap<Identifier, Vec<Arc<Signed<CgkaOperation>>>>,

    /// For each agent: the set of doc identifiers whose ops are reachable.
    pub index: HashMap<Identifier, HashSet<Identifier>>,
}

impl AllCgkaOps {
    /// Returns the set of agent identifiers that have reachable CGKA ops.
    pub fn agents(&self) -> impl Iterator<Item = &Identifier> {
        self.index.keys()
    }

    /// Returns an iterator over all reachable CGKA ops for the given agent
    /// (flattened across all documents), or `None` if the agent is not in the index.
    pub fn ops_for_agent(
        &self,
        agent_id: &Identifier,
    ) -> Option<impl Iterator<Item = &Arc<Signed<CgkaOperation>>>> {
        self.index.get(agent_id).map(|doc_ids| {
            doc_ids
                .iter()
                .filter_map(|doc_id| self.ops.get(doc_id))
                .flat_map(|ops| ops.iter())
        })
    }
}
