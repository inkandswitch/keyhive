//! Stub out listener functionality.

use super::{cgka::CgkaListener, membership::MembershipListener, prekey::PrekeyListener};
use crate::{
    cgka::operation::CgkaOperation,
    content::reference::ContentRef,
    crypto::{signed::Signed, signer::async_signer::AsyncSigner},
    principal::{
        group::{delegation::Delegation, revocation::Revocation},
        individual::op::{add_key::AddKeyOp, rotate_key::RotateKeyOp},
    },
};
use derive_more::derive::Debug;
use dupe::Dupe;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Stub out listener functionality.
///
/// This is the default listener. Generally you don't need to manually specify this as an option.
#[derive(Debug, Default, Clone, Dupe, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct NoListener;

impl PrekeyListener for NoListener {
    async fn on_prekeys_expanded(&self, _e: &Arc<Signed<AddKeyOp>>) {}
    async fn on_prekey_rotated(&self, _e: &Arc<Signed<RotateKeyOp>>) {}
}

impl<S: AsyncSigner, T: ContentRef> MembershipListener<S, T> for NoListener {
    async fn on_delegation(&self, _data: &Arc<Signed<Delegation<S, T, NoListener>>>) {}
    async fn on_revocation(&self, _data: &Arc<Signed<Revocation<S, T, NoListener>>>) {}
}

impl CgkaListener for NoListener {
    async fn on_cgka_op(&self, _data: &Arc<Signed<CgkaOperation>>) {}
}
