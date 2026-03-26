//! Stub out listener functionality.

use super::{cgka::CgkaListener, membership::MembershipListener, prekey::PrekeyListener};
use crate::principal::{
    group::{delegation::Delegation, revocation::Revocation},
    individual::op::{add_key::AddKeyOp, rotate_key::RotateKeyOp},
};
use beekem::operation::CgkaOperation;
use derive_more::derive::Debug;
use dupe::Dupe;
use future_form::{future_form, FutureForm, Local, Sendable};
use keyhive_crypto::{
    content::reference::ContentRef, signed::Signed, signer::async_signer::AsyncSigner,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Stub out listener functionality.
///
/// This is the default listener. Generally you don't need to manually specify this as an option.
#[derive(Debug, Default, Clone, Dupe, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct NoListener;

#[future_form(Sendable, Local)]
impl<F: FutureForm> PrekeyListener<F> for NoListener {
    fn on_prekeys_expanded<'a>(&'a self, _e: &'a Arc<Signed<AddKeyOp>>) -> F::Future<'a, ()> {
        F::ready(())
    }

    fn on_prekey_rotated<'a>(&'a self, _e: &'a Arc<Signed<RotateKeyOp>>) -> F::Future<'a, ()> {
        F::ready(())
    }
}

#[future_form(Sendable, Local)]
impl<F: FutureForm, S: AsyncSigner<F>, T: ContentRef> MembershipListener<F, S, T> for NoListener {
    fn on_delegation<'a>(
        &'a self,
        _data: &'a Arc<Signed<Delegation<F, S, T, NoListener>>>,
    ) -> F::Future<'a, ()> {
        F::ready(())
    }

    fn on_revocation<'a>(
        &'a self,
        _data: &'a Arc<Signed<Revocation<F, S, T, NoListener>>>,
    ) -> F::Future<'a, ()> {
        F::ready(())
    }
}

#[future_form(Sendable, Local)]
impl<F: FutureForm> CgkaListener<F> for NoListener {
    fn on_cgka_op<'a>(&'a self, _data: &'a Arc<Signed<CgkaOperation>>) -> F::Future<'a, ()> {
        F::ready(())
    }
}
