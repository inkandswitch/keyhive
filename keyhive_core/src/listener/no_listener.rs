//! Stub out listener functionality.

use super::{cgka::CgkaListener, membership::MembershipListener, prekey::PrekeyListener};
use crate::{
    cgka::operation::CgkaOperation,
    content::reference::ContentRef,
    crypto::{share_key::ShareSecretStore, signed::Signed, signer::async_signer::AsyncSigner},
    principal::{
        group::{delegation::Delegation, revocation::Revocation},
        individual::op::{add_key::AddKeyOp, rotate_key::RotateKeyOp},
    },
};
use derive_more::derive::Debug;
use dupe::Dupe;
use serde::{Deserialize, Serialize};
use std::rc::Rc;

/// Stub out listener functionality.
///
/// This is the default listener. Generally you don't need to manually specify this as an option.
#[derive(Debug, Default, Clone, Dupe, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct NoListener;

impl PrekeyListener for NoListener {
    async fn on_prekeys_expanded(&self, _e: &Rc<Signed<AddKeyOp>>) {}
    async fn on_prekey_rotated(&self, _e: &Rc<Signed<RotateKeyOp>>) {}
}

impl<S: AsyncSigner, K: ShareSecretStore, T: ContentRef> MembershipListener<S, K, T>
    for NoListener
{
    async fn on_delegation(&self, _data: &Rc<Signed<Delegation<S, K, T, NoListener>>>) {}
    async fn on_revocation(&self, _data: &Rc<Signed<Revocation<S, K, T, NoListener>>>) {}
}

impl CgkaListener for NoListener {
    async fn on_cgka_op(&self, _data: &Rc<Signed<CgkaOperation>>) {}
}
