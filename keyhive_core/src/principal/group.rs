//! A group: a principal with no content of its own. Its membership is the
//! Keyline certificate set, so a replica stores nothing for it.

pub mod id;

use super::membered::id::MemberedId;
use crate::{
    certificate::{CertificateError, KeylineStorageError},
    content::heads::ContentHeads,
    error::not_found::NotFound,
    keyhive::Keyhive,
    listener::membership::MembershipListener,
    principal::document::AddMemberError,
    store::ciphertext::{CiphertextStore, CiphertextStoreExt},
    update::{AddMemberUpdate, RevokeMemberUpdate},
};
use beekem::error::CgkaError;
use future_form::FutureForm;
use id::GroupId;
use keyhive_codec::traits::Decode;
use keyhive_crypto::{
    content::reference::ContentRef, identifier::Identifier, signer::async_signer::AsyncSigner,
    verified::Signed,
};
use keyline::{contract::Keyline, delegation::Delegation, power::Power};
use rand::{CryptoRng, RngCore};
use std::{collections::BTreeMap, sync::Arc};
use thiserror::Error;

/// A group, as a transient handle over the keyhive.
#[derive(Debug, Clone)]
pub struct Group<KH> {
    keyhive: KH,
    id: GroupId,
}

impl<KH> Group<KH> {
    pub(crate) fn new(keyhive: KH, id: GroupId) -> Self {
        Group { keyhive, id }
    }

    /// The keyhive this handle reads through.
    pub fn keyhive(&self) -> &KH {
        &self.keyhive
    }

    pub fn id(&self) -> Identifier {
        self.id.into()
    }

    pub fn group_id(&self) -> GroupId {
        self.id
    }
}

impl<F, S, T, P, C, L, R, K> Group<Keyhive<F, S, T, P, C, L, R, K>>
where
    F: FutureForm,
    S: AsyncSigner<F> + Clone,
    T: ContentRef,
    P: Decode,
    C: CiphertextStore<F, T, P> + CiphertextStoreExt<F, T, P> + Clone,
    L: MembershipListener<F, T>,
    R: CryptoRng + RngCore,
    K: Keyline<F, RetentionWatermark = ContentHeads<T>>,
    K::Error: Send + Sync + 'static,
{
    /// The live delegations about this group: its direct members.
    #[allow(clippy::type_complexity)]
    pub async fn members(
        &self,
    ) -> Result<Vec<Arc<Signed<Delegation>>>, KeylineStorageError<K::Error>> {
        self.keyhive.delegations_about(self.id).await
    }

    /// Everyone with a live route to this group, with their power.
    pub async fn transitive_members(
        &self,
    ) -> Result<BTreeMap<Identifier, Power>, KeylineStorageError<K::Error>> {
        self.keyhive.members_of(self.id.into()).await
    }

    /// Grant `to_add` power over this group.
    pub async fn add_member(
        &self,
        to_add: Identifier,
        can: Power,
    ) -> Result<AddMemberUpdate, AddMemberError<K::Error>> {
        self.keyhive
            .add_member(to_add, MemberedId::GroupId(self.id), can)
            .await
    }

    /// Revoke `to_revoke` from this group; with `retain_all_other_members`,
    /// the revoker adopts the members it had admitted.
    pub async fn revoke_member(
        &self,
        to_revoke: Identifier,
        retain_all_other_members: bool,
    ) -> Result<RevokeMemberUpdate<T>, RevokeMemberError<K::Error>> {
        self.keyhive
            .revoke_member(to_revoke, retain_all_other_members, self.id)
            .await
    }
}

/// Why revoking a member failed.
#[derive(Debug, Error)]
pub enum RevokeMemberError<E: core::error::Error + 'static> {
    /// The identifier was not found.
    #[error(transparent)]
    NotFound(#[from] NotFound),

    #[error(transparent)]
    CgkaError(#[from] CgkaError),

    #[error(transparent)]
    Certificate(#[from] CertificateError),

    /// The writer has no standing over the resource in Keyline, or none that
    /// reaches any delegation to the member.
    #[error("no standing to revoke that member")]
    NoAuthority,

    /// The member holds no delegation from the resource itself: it reaches
    /// it only through a group or document, which is what to revoke instead.
    #[error("{0} holds no delegation from the resource")]
    NotADirectMember(Identifier),

    #[error(transparent)]
    KeylineStorage(#[from] KeylineStorageError<E>),
}
