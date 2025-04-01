//! Stub out listener functionality.

use super::{
    cgka::CgkaListener, membership::MembershipListener, prekey::PrekeyListener,
    secret::SecretListener,
};
use crate::{
    cgka::operation::CgkaOperation,
    content::reference::ContentRef,
    crypto::{
        share_key::{ShareKey, ShareSecretKey},
        signed::Signed,
        signer::async_signer::AsyncSigner,
    },
    principal::{
        document::id::DocumentId,
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

impl<S: AsyncSigner, T: ContentRef> MembershipListener<S, T> for NoListener {
    async fn on_delegation(&self, _data: &Rc<Signed<Delegation<S, T, NoListener>>>) {}
    async fn on_revocation(&self, _data: &Rc<Signed<Revocation<S, T, NoListener>>>) {}
}

impl CgkaListener for NoListener {
    async fn on_cgka_op(&self, _data: &Rc<Signed<CgkaOperation>>) {}
}

impl SecretListener for NoListener {
    async fn on_active_prekey_pair(
        &self,
        _new_public_key: ShareKey,
        _new_secret_key: ShareSecretKey,
    ) {
    }

    async fn on_doc_sharing_secret(
        &self,
        _doc_id: DocumentId,
        _new_public_key: ShareKey,
        _new_secret_key: ShareSecretKey,
    ) {
    }
}
