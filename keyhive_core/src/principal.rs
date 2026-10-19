//! The principals: everything that can hold or grant authority.
//!
//! A replica keeps state only where a layer needs it, in two tables: prekeys
//! for individuals and key agreement for documents. What it hands out
//! are transient handles over the keyhive, built on demand and never stored.
//! [`Principal`] stands for any identifier; [`individual::Individual`],
//! [`group::Group`] and [`document::Document`] narrow it when the tables say
//! so. Any principal can be a Keyline subject, and so have members; groups
//! and documents are the ones Keyhive manages members for.

pub mod active;
pub mod document;
pub mod group;
pub mod individual;
pub mod membered;

use self::{
    document::{id::DocumentId, Document},
    group::{id::GroupId, Group},
    individual::{id::IndividualId, Individual},
};
use crate::{
    certificate::KeylineStorageError,
    content::heads::ContentHeads,
    keyhive::Keyhive,
    listener::membership::MembershipListener,
    store::ciphertext::{CiphertextStore, CiphertextStoreExt},
};
use future_form::FutureForm;
use keyhive_codec::traits::{Encode, StreamDecode};
use keyhive_crypto::{
    content::reference::ContentRef, identifier::Identifier, signer::async_signer::AsyncSigner,
    verified::Signed,
};
use keyline::{contract::Keyline, delegation::Delegation, power::Power};
use rand::{CryptoRng, RngCore};
use serde::Deserialize;
use std::{collections::BTreeMap, sync::Arc};

/// Any identifier, as this replica knows it.
#[derive(Debug, Clone)]
pub struct Principal<KH> {
    keyhive: KH,
    id: Identifier,
}

impl<KH> Principal<KH> {
    pub(crate) fn new(keyhive: KH, id: Identifier) -> Self {
        Principal { keyhive, id }
    }

    /// The keyhive this handle reads through.
    pub fn keyhive(&self) -> &KH {
        &self.keyhive
    }

    pub fn id(&self) -> Identifier {
        self.id
    }
}

impl<F, S, T, P, C, L, R, K> Principal<Keyhive<F, S, T, P, C, L, R, K>>
where
    F: FutureForm,
    S: AsyncSigner<F> + Clone,
    T: ContentRef + Encode + StreamDecode,
    P: for<'de> Deserialize<'de>,
    C: CiphertextStore<F, T, P> + CiphertextStoreExt<F, T, P> + Clone,
    L: MembershipListener<F, T>,
    R: CryptoRng + RngCore,
    K: Keyline<F, RetentionWatermark = ContentHeads<T>>,
    K::Error: Send + Sync + 'static,
{
    /// Whether this is the active identity.
    pub fn is_active(&self) -> bool {
        IndividualId(self.id) == self.keyhive.id()
    }

    /// As an individual, if this replica holds its prekeys.
    pub async fn as_individual(&self) -> Option<Individual<Keyhive<F, S, T, P, C, L, R, K>>> {
        self.keyhive.get_individual(IndividualId(self.id)).await
    }

    /// As a document, if this replica holds an authorized key agreement
    /// operation for it.
    pub async fn as_document(&self) -> Option<Document<Keyhive<F, S, T, P, C, L, R, K>>> {
        self.keyhive.get_document(DocumentId(self.id)).await
    }

    /// As a group: a Keyline subject that is neither of the others.
    pub async fn as_group(
        &self,
    ) -> Result<Option<Group<Keyhive<F, S, T, P, C, L, R, K>>>, KeylineStorageError<K::Error>> {
        self.keyhive.get_group(GroupId(self.id)).await
    }

    /// The live delegations about this principal: its direct members.
    #[allow(clippy::type_complexity)]
    pub async fn members(
        &self,
    ) -> Result<Vec<Arc<Signed<Delegation>>>, KeylineStorageError<K::Error>> {
        self.keyhive.delegations_about(self.id).await
    }

    /// Everyone with a live route to this principal, with their power.
    pub async fn transitive_members(
        &self,
    ) -> Result<BTreeMap<Identifier, Power>, KeylineStorageError<K::Error>> {
        self.keyhive.members_of(self.id).await
    }
}
