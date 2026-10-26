//! What a membership write produced: the Keyline certificates it inserted,
//! the CGKA adds and removes it issued for each local document whose
//! readers those certificates changed.

use crate::content::heads::ContentHeads;
use beekem::operation::CgkaOperation;
use keyhive_crypto::{content::reference::ContentRef, verified::Verified};
use keyline::{delegation::Delegation, revocation::Revocation};
use std::sync::Arc;

/// What [`Keyhive::add_member`](crate::keyhive::Keyhive::add_member) produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddMemberUpdate {
    /// The delegation granting the new member its power.
    pub delegation: Arc<Verified<Delegation>>,

    /// The CGKA operations issued for each local document whose readers
    /// this write changed.
    pub cgka_ops: Vec<Verified<CgkaOperation>>,
}

/// What [`Keyhive::revoke_member`](crate::keyhive::Keyhive::revoke_member) produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevokeMemberUpdate<T: ContentRef> {
    pub(crate) revocations: Vec<Arc<Verified<Revocation<ContentHeads<T>>>>>,
    pub(crate) redelegations: Vec<Arc<Verified<Delegation>>>,
    pub(crate) cgka_ops: Vec<Verified<CgkaOperation>>,
}

impl<T: ContentRef> RevokeMemberUpdate<T> {
    /// A revocation of every delegation from the resource to the member that
    /// the writer could revoke.
    pub fn revocations(&self) -> &[Arc<Verified<Revocation<ContentHeads<T>>>>] {
        &self.revocations
    }

    /// Adoption: delegations from the revoker that keep the members the
    /// revoked member had admitted.
    pub fn redelegations(&self) -> &[Arc<Verified<Delegation>>] {
        &self.redelegations
    }

    /// The CGKA operations issued for each local document whose readers
    /// this write changed.
    pub fn cgka_ops(&self) -> &[Verified<CgkaOperation>] {
        &self.cgka_ops
    }
}
