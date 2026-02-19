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
use future_form::{future_form, FutureForm, Local, Sendable};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Stub out listener functionality.
///
/// This is the default listener. Generally you don't need to manually specify this as an option.
#[derive(Debug, Default, Clone, Dupe, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct NoListener;

#[future_form(Sendable, Local)]
impl<K: FutureForm> PrekeyListener<K> for NoListener {
    fn on_prekeys_expanded<'a>(
        &'a self,
        _new_prekey: &'a Arc<Signed<AddKeyOp>>,
    ) -> K::Future<'a, ()> {
        K::from_future(async {})
    }

    fn on_prekey_rotated<'a>(
        &'a self,
        _rotate_key: &'a Arc<Signed<RotateKeyOp>>,
    ) -> K::Future<'a, ()> {
        K::from_future(async {})
    }
}

#[future_form(Sendable where S: Send + Sync, T: Send + Sync, Local)]
impl<K: FutureForm, S: AsyncSigner<K>, T: ContentRef> MembershipListener<K, S, T> for NoListener {
    fn on_delegation<'a>(
        &'a self,
        _data: &'a Arc<Signed<Delegation<S, T, NoListener>>>,
    ) -> K::Future<'a, ()> {
        K::from_future(async {})
    }

    fn on_revocation<'a>(
        &'a self,
        _data: &'a Arc<Signed<Revocation<S, T, NoListener>>>,
    ) -> K::Future<'a, ()> {
        K::from_future(async {})
    }
}

#[future_form(Sendable, Local)]
impl<K: FutureForm> CgkaListener<K> for NoListener {
    fn on_cgka_op<'a>(&'a self, _data: &'a Arc<Signed<CgkaOperation>>) -> K::Future<'a, ()> {
        K::from_future(async {})
    }
}
