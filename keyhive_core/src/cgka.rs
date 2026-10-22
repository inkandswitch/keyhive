//! Thin wrapper around [`beekem::cgka::Cgka`] that converts between
//! keyhive_core domain IDs ([`IndividualId`] / [`DocumentId`]) and
//! beekem IDs ([`beekem::id::MemberId`] /
//! [`beekem::id::TreeId`]) at the API boundary.

use crate::principal::{document::id::DocumentId, individual::id::IndividualId};
use beekem::{
    encrypted::EncryptedContent,
    error::CgkaError,
    id::{MemberId, TreeId},
    keys::{LeafKeyPair, ShareKeyMap},
    operation::{CgkaAuthorization, CgkaBatch, CgkaOperation},
    pcs_key::{ApplicationSecret, PcsKey},
};
use future_form::FutureForm;
use keyhive_crypto::{
    content::reference::ContentRef,
    digest::Digest,
    identifier::Identifier,
    share_key::{ShareKey, ShareSecretKey},
    signed::SerdeSigned,
    signer::async_signer::AsyncSigner,
    symmetric_key::SymmetricKey,
};
use nonempty::NonEmpty;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
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

impl Cgka {
    pub fn new(doc_id: DocumentId, owner_id: IndividualId, owner_sks: ShareKeyMap) -> Self {
        Cgka(beekem::cgka::Cgka::new(
            TreeId::from(doc_id),
            MemberId::from(owner_id),
            owner_sks,
        ))
    }

    pub fn with_new_owner(
        &self,
        my_id: IndividualId,
        owner_sks: ShareKeyMap,
    ) -> Result<Self, CgkaError> {
        Ok(Cgka(
            self.0.with_new_owner(MemberId::from(my_id), owner_sks)?,
        ))
    }

    pub fn ops_count(&self) -> usize {
        self.0.ops_count()
    }

    pub fn try_pcs_key_hash(&mut self) -> Result<Digest<PcsKey>, CgkaError> {
        let pcs_key = self.0.decrypt_tree_root_secret()?;
        Ok(pcs_key.digest())
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
        R: CryptoRng + RngCore,
    >(
        &mut self,
        content_ref: &T,
        pred_refs: &[T],
        signer: &S,
        csprng: &mut R,
    ) -> Result<
        (
            ApplicationSecret<T>,
            Option<(SerdeSigned<CgkaOperation>, LeafKeyPair)>,
        ),
        CgkaError,
    > {
        self.0
            .new_app_secret_for(content_ref, pred_refs, signer, csprng)
            .await
    }

    pub fn decryption_key_for<T, Cr: ContentRef>(
        &mut self,
        encrypted: &EncryptedContent<T, Cr>,
    ) -> Result<SymmetricKey, CgkaError> {
        self.0.decryption_key_for(encrypted)
    }

    /// Add a member, returning its add operation or `None` if the member
    /// is already in the tree.
    pub async fn add<F: FutureForm, S: AsyncSigner<F>>(
        &mut self,
        id: IndividualId,
        pk: ShareKey,
        authorization: CgkaAuthorization,
        signer: &S,
    ) -> Result<Option<SerdeSigned<CgkaOperation>>, CgkaError> {
        self.0
            .add(MemberId::from(id), pk, authorization, signer)
            .await
    }

    pub async fn add_multiple<F: FutureForm, S: AsyncSigner<F>>(
        &mut self,
        members: NonEmpty<(IndividualId, ShareKey, CgkaAuthorization)>,
        signer: &S,
    ) -> Result<Vec<SerdeSigned<CgkaOperation>>, CgkaError> {
        let converted = members.map(|(id, pk, auth)| (MemberId::from(id), pk, auth));
        self.0.add_multiple(converted, signer).await
    }

    pub async fn remove<F: FutureForm, S: AsyncSigner<F>>(
        &mut self,
        id: IndividualId,
        authorization: CgkaAuthorization,
        signer: &S,
    ) -> Result<Option<SerdeSigned<CgkaOperation>>, CgkaError> {
        self.0
            .remove(MemberId::from(id), authorization, signer)
            .await
    }

    pub async fn update<F: FutureForm, S: AsyncSigner<F>, R: CryptoRng + RngCore>(
        &mut self,
        new_pk: ShareKey,
        new_sk: ShareSecretKey,
        signer: &S,
        csprng: &mut R,
    ) -> Result<(PcsKey, SerdeSigned<CgkaOperation>, LeafKeyPair), CgkaError> {
        self.0.update(new_pk, new_sk, signer, csprng).await
    }

    pub fn owner_leaf_key(&self) -> Option<ShareKey> {
        self.0.owner_leaf_key()
    }

    pub fn group_size(&self) -> u32 {
        self.0.group_size()
    }

    /// The individuals currently in this document's CGKA tree.
    pub fn member_ids(&mut self) -> Result<impl Iterator<Item = IndividualId> + '_, CgkaError> {
        Ok(self.0.member_ids()?.map(IndividualId::from))
    }

    pub fn merge_concurrent_operation(
        &mut self,
        op: Arc<SerdeSigned<CgkaOperation>>,
    ) -> Result<bool, CgkaError> {
        self.0.merge_concurrent_operation(op)
    }

    pub fn ops(&self) -> Result<NonEmpty<CgkaBatch>, CgkaError> {
        self.0.ops()
    }

    pub fn contains_predecessors(
        &self,
        preds: &HashSet<Digest<SerdeSigned<CgkaOperation>>>,
    ) -> bool {
        self.0.contains_predecessors(preds)
    }

    /// Merge an add of a leaf whose secret `sk` this replica holds: an
    /// invitation to it. The added member becomes the owner, holding `sk`.
    pub fn merge_invite(
        &mut self,
        op: Arc<SerdeSigned<CgkaOperation>>,
        sk: &ShareSecretKey,
    ) -> Result<bool, CgkaError> {
        let CgkaOperation::Add {
            added_id,
            pk,
            ref predecessors,
            ..
        } = op.payload
        else {
            return Err(CgkaError::UnexpectedInviteOperation);
        };
        if !self.contains_predecessors(&predecessors.iter().cloned().collect()) {
            return Err(CgkaError::OutOfOrderOperation);
        }
        let mut owner_sks = self.owner_sks().clone();
        owner_sks.insert(pk, *sk);
        *self = self.with_new_owner(added_id.into(), owner_sks)?;
        self.merge_concurrent_operation(op)
    }
}

/// CGKA ops for all principals, with shared storage.
///
/// CGKA ops are stored per document. Each principal has an index pointing to the
/// documents it has standing over in Keyline.
#[derive(Debug)]
pub struct AllCgkaOps {
    /// CGKA ops per doc, keyed by doc Identifier.
    pub ops: HashMap<Identifier, Vec<Arc<SerdeSigned<CgkaOperation>>>>,

    /// For each principal: the set of doc identifiers whose ops are reachable.
    pub index: HashMap<Identifier, HashSet<Identifier>>,
}

impl AllCgkaOps {
    /// Returns the set of principal identifiers that have reachable CGKA ops.
    pub fn agents(&self) -> impl Iterator<Item = &Identifier> {
        self.index.keys()
    }

    /// Returns an iterator over all reachable CGKA ops for the given principal
    /// (flattened across all documents), or `None` if the principal is not in the index.
    pub fn ops_for_agent(
        &self,
        agent_id: &Identifier,
    ) -> Option<impl Iterator<Item = &Arc<SerdeSigned<CgkaOperation>>>> {
        self.index.get(agent_id).map(|doc_ids| {
            doc_ids
                .iter()
                .filter_map(|doc_id| self.ops.get(doc_id))
                .flat_map(|ops| ops.iter())
        })
    }
}
