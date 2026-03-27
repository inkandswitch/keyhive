use super::{change_id::JsChangeId, event::JsEvent, signer::JsSigner};
use beekem::operation::CgkaOperation;
use derive_more::{From, Into};
use dupe::Dupe;
use future_form::Local;
use futures::future::LocalBoxFuture;
use keyhive_core::{
    event::Event,
    listener::{cgka::CgkaListener, membership::MembershipListener, prekey::PrekeyListener},
    principal::{
        group::{delegation::Delegation, revocation::Revocation},
        individual::op::{add_key::AddKeyOp, rotate_key::RotateKeyOp},
    },
};
use keyhive_crypto::signed::Signed;
use std::sync::Arc;
use wasm_bindgen::prelude::*;

#[derive(Debug, Clone, From, Into)]
pub struct JsEventHandler(pub(crate) js_sys::Function);

impl JsEventHandler {
    pub fn call(&self, event: JsEvent) {
        self.0.call1(&JsValue::NULL, &event.into()).unwrap();
    }
}

impl Dupe for JsEventHandler {
    fn dupe(&self) -> Self {
        self.clone()
    }
}

impl PrekeyListener<Local> for JsEventHandler {
    fn on_prekeys_expanded<'a>(&'a self, e: &'a Arc<Signed<AddKeyOp>>) -> LocalBoxFuture<'a, ()> {
        Box::pin(async move { self.call(Event::PrekeysExpanded(e.dupe()).into()) })
    }

    fn on_prekey_rotated<'a>(&'a self, e: &'a Arc<Signed<RotateKeyOp>>) -> LocalBoxFuture<'a, ()> {
        Box::pin(async move { self.call(Event::PrekeyRotated(e.dupe()).into()) })
    }
}

impl MembershipListener<Local, JsSigner, JsChangeId> for JsEventHandler {
    fn on_delegation<'a>(
        &'a self,
        data: &'a Arc<Signed<Delegation<Local, JsSigner, JsChangeId, Self>>>,
    ) -> LocalBoxFuture<'a, ()> {
        Box::pin(async move { self.call(Event::Delegated(data.dupe()).into()) })
    }

    fn on_revocation<'a>(
        &'a self,
        data: &'a Arc<Signed<Revocation<Local, JsSigner, JsChangeId, Self>>>,
    ) -> LocalBoxFuture<'a, ()> {
        Box::pin(async move { self.call(Event::Revoked(data.dupe()).into()) })
    }
}

impl CgkaListener<Local> for JsEventHandler {
    fn on_cgka_op<'a>(&'a self, data: &'a Arc<Signed<CgkaOperation>>) -> LocalBoxFuture<'a, ()> {
        Box::pin(async move { self.call(Event::CgkaOperation(data.dupe()).into()) })
    }
}
