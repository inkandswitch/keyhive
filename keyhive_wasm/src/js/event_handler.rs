use super::{change_id::JsChangeId, event::JsEvent, signer::JsSigner};
use derive_more::{From, Into};
use dupe::Dupe;
use future_form::Local;
use futures::future::{FutureExt, LocalBoxFuture};
use keyhive_core::{
    cgka::operation::CgkaOperation,
    crypto::signed::Signed,
    event::Event,
    listener::{cgka::CgkaListener, membership::MembershipListener, prekey::PrekeyListener},
    principal::{
        group::{delegation::Delegation, revocation::Revocation},
        individual::op::{add_key::AddKeyOp, rotate_key::RotateKeyOp},
    },
};
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
        let event = Event::PrekeysExpanded(e.dupe()).into();
        async move { self.call(event) }.boxed_local()
    }

    fn on_prekey_rotated<'a>(&'a self, e: &'a Arc<Signed<RotateKeyOp>>) -> LocalBoxFuture<'a, ()> {
        let event = Event::PrekeyRotated(e.dupe()).into();
        async move { self.call(event) }.boxed_local()
    }
}

impl MembershipListener<Local, JsSigner, JsChangeId> for JsEventHandler {
    fn on_delegation<'a>(
        &'a self,
        data: &'a Arc<Signed<Delegation<JsSigner, JsChangeId, Self>>>,
    ) -> LocalBoxFuture<'a, ()> {
        let event = Event::Delegated(data.dupe()).into();
        async move { self.call(event) }.boxed_local()
    }

    fn on_revocation<'a>(
        &'a self,
        data: &'a Arc<Signed<Revocation<JsSigner, JsChangeId, Self>>>,
    ) -> LocalBoxFuture<'a, ()> {
        let event = Event::Revoked(data.dupe()).into();
        async move { self.call(event) }.boxed_local()
    }
}

impl CgkaListener<Local> for JsEventHandler {
    fn on_cgka_op<'a>(&'a self, data: &'a Arc<Signed<CgkaOperation>>) -> LocalBoxFuture<'a, ()> {
        let event = Event::CgkaOperation(data.dupe()).into();
        async move { self.call(event) }.boxed_local()
    }
}
