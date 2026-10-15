//! Thin wrapper around [`beekem::cgka::Cgka`] that converts between
//! keyhive_core domain IDs ([`IndividualId`] / [`DocumentId`]) and
//! beekem IDs ([`beekem::id::MemberId`] /
//! [`beekem::id::TreeId`]) at the API boundary.

pub mod store;

use crate::{
    principal::{document::id::DocumentId, identifier::Identifier, individual::id::IndividualId},
    transact::{fork::Fork, merge::Merge},
};
use beekem::{
    encrypted::EncryptedContent,
    error::CgkaError,
    id::{MemberId, TreeId},
    keys::{LeafKeyPair, ShareKeyMap},
    operation::{CgkaAuthorization, CgkaBatch, CgkaOperation},
    pcs_key::{ApplicationSecret, PcsKey},
    transact::Merge as _,
};
use future_form::FutureForm;
use keyhive_crypto::{
    content::reference::ContentRef,
    digest::Digest,
    id::InvalidId,
    share_key::{ShareKey, ShareSecretKey},
    signed::Signed,
    signer::async_signer::AsyncSigner,
    symmetric_key::SymmetricKey,
};
use nonempty::NonEmpty;
use rand::{CryptoRng, RngCore};
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
    pub fn new(
        doc_id: DocumentId,
        owner_id: IndividualId,
        owner_sks: ShareKeyMap,
    ) -> Result<Self, CgkaError> {
        Ok(Cgka(beekem::cgka::Cgka::new(
            TreeId::try_from(doc_id)?,
            MemberId::try_from(owner_id)?,
            owner_sks,
        )))
    }

    pub fn with_new_owner(
        &self,
        my_id: IndividualId,
        owner_sks: ShareKeyMap,
    ) -> Result<Self, CgkaError> {
        Ok(Cgka(
            self.0
                .with_new_owner(MemberId::try_from(my_id)?, owner_sks)?,
        ))
    }

    pub fn ops_count(&self) -> usize {
        self.0.ops_count()
    }

    pub fn try_pcs_key_hash(&mut self) -> Result<Digest<PcsKey>, CgkaError> {
        let pcs_key = self.0.decrypt_tree_root_secret()?;
        Ok(Digest::hash(&pcs_key))
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
        content: &[u8],
        pred_refs: &Vec<T>,
        signer: &S,
        csprng: &mut R,
    ) -> Result<
        (
            ApplicationSecret<T>,
            Option<(Signed<CgkaOperation>, LeafKeyPair)>,
        ),
        CgkaError,
    > {
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

    /// Add a member, returning its add operation or `None` if the member
    /// is already in the tree.
    pub async fn add<F: FutureForm, S: AsyncSigner<F>>(
        &mut self,
        id: IndividualId,
        pk: ShareKey,
        authorization: CgkaAuthorization,
        signer: &S,
    ) -> Result<Option<Signed<CgkaOperation>>, CgkaError> {
        self.0
            .add(MemberId::try_from(id)?, pk, authorization, signer)
            .await
    }

    pub async fn add_multiple<F: FutureForm, S: AsyncSigner<F>>(
        &mut self,
        members: NonEmpty<(IndividualId, ShareKey, CgkaAuthorization)>,
        signer: &S,
    ) -> Result<Vec<Signed<CgkaOperation>>, CgkaError> {
        let (head, tail) = (members.head, members.tail);
        let converted = NonEmpty {
            head: (MemberId::try_from(head.0)?, head.1, head.2),
            tail: tail
                .into_iter()
                .map(|(id, pk, auth)| Ok((MemberId::try_from(id)?, pk, auth)))
                .collect::<Result<_, InvalidId>>()?,
        };
        self.0.add_multiple(converted, signer).await
    }

    pub async fn remove<F: FutureForm, S: AsyncSigner<F>>(
        &mut self,
        id: IndividualId,
        authorization: CgkaAuthorization,
        signer: &S,
    ) -> Result<Option<Signed<CgkaOperation>>, CgkaError> {
        self.0
            .remove(MemberId::try_from(id)?, authorization, signer)
            .await
    }

    pub async fn update<F: FutureForm, S: AsyncSigner<F>, R: CryptoRng + RngCore>(
        &mut self,
        new_pk: ShareKey,
        new_sk: ShareSecretKey,
        signer: &S,
        csprng: &mut R,
    ) -> Result<(PcsKey, Signed<CgkaOperation>, LeafKeyPair), CgkaError> {
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
        op: Arc<Signed<CgkaOperation>>,
    ) -> Result<bool, CgkaError> {
        self.0.merge_concurrent_operation(op)
    }

    pub fn ops(&self) -> Result<NonEmpty<CgkaBatch>, CgkaError> {
        self.0.ops()
    }

    pub fn contains_predecessors(&self, preds: &HashSet<Digest<Signed<CgkaOperation>>>) -> bool {
        self.0.contains_predecessors(preds)
    }

    /// Merge an add of a leaf whose secret `sk` this replica holds: an
    /// invitation to it. The added member becomes the owner, holding `sk`.
    pub fn merge_invite(
        &mut self,
        op: Arc<Signed<CgkaOperation>>,
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

impl Fork for Cgka {
    type Forked = Self;

    fn fork(&self) -> Self::Forked {
        self.clone()
    }
}

impl Merge for Cgka {
    fn merge(&mut self, fork: Self::Forked) {
        self.0.merge(fork.0);
    }
}

/// CGKA ops for all principals, with shared storage.
///
/// CGKA ops are stored per document. Each principal has an index pointing to the
/// documents it has standing over in Keyline.
#[derive(Debug)]
pub struct AllCgkaOps {
    /// CGKA ops per doc, keyed by doc Identifier.
    pub ops: HashMap<Identifier, Vec<Arc<Signed<CgkaOperation>>>>,

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
    ) -> Option<impl Iterator<Item = &Arc<Signed<CgkaOperation>>>> {
        self.index.get(agent_id).map(|doc_ids| {
            doc_ids
                .iter()
                .filter_map(|doc_id| self.ops.get(doc_id))
                .flat_map(|ops| ops.iter())
        })
    }
}
