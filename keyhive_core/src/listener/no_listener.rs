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
use future_form::{FutureForm, Local, Sendable};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Stub out listener functionality.
///
/// This is the default listener. Generally you don't need to manually specify this as an option.
#[derive(Debug, Default, Clone, Dupe, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct NoListener;

#[future_form::future_form(Sendable, Local)]
impl<K: FutureForm + ?Sized> PrekeyListener<K> for NoListener {
    fn on_prekeys_expanded<'a>(
        &'a self,
        _e: &'a Arc<Signed<AddKeyOp>>,
    ) -> K::Future<'a, ()> {
        K::from_future(async {})
    }

    fn on_prekey_rotated<'a>(
        &'a self,
        _e: &'a Arc<Signed<RotateKeyOp>>,
    ) -> K::Future<'a, ()> {
        K::from_future(async {})
    }
}

#[future_form::future_form(Sendable, Local)]
impl<K: FutureForm + ?Sized> CgkaListener<K> for NoListener {
    fn on_cgka_op<'a>(
        &'a self,
        _data: &'a Arc<Signed<CgkaOperation>>,
    ) -> K::Future<'a, ()> {
        K::from_future(async {})
    }
}

#[future_form::future_form(Sendable, Local)]
impl<K: FutureForm + ?Sized, S: AsyncSigner, T: ContentRef> MembershipListener<S, T, K>
    for NoListener
{
    fn on_delegation<'a, DL: MembershipListener<S, T>>(
        &'a self,
        _data: &'a Arc<Signed<Delegation<S, T, DL>>>,
    ) -> K::Future<'a, ()> {
        K::from_future(async {})
    }

    fn on_revocation<'a, DL: MembershipListener<S, T>>(
        &'a self,
        _data: &'a Arc<Signed<Revocation<S, T, DL>>>,
    ) -> K::Future<'a, ()> {
        K::from_future(async {})
    }
}
