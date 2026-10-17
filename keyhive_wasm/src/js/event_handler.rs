use super::{change_id::JsChangeId, event::JsEvent};
use beekem::operation::CgkaOperation;
use derive_more::{From, Into};
use dupe::Dupe;
use future_form::Local;
use futures::future::LocalBoxFuture;
use keyhive_core::{
    content::heads::ContentHeads,
    event::Event,
    listener::{cgka::CgkaListener, membership::MembershipListener, prekey::PrekeyListener},
    principal::individual::op::{add_key::AddKeyOp, rotate_key::RotateKeyOp},
};
use keyhive_crypto::{
    signed::Signed,
    verified::{self, Verified},
};
use keyline::{delegation::Delegation, revocation::Revocation};
use std::sync::Arc;
use wasm_bindgen::prelude::*;

#[derive(Debug, Clone, From, Into)]
pub struct JsEventHandler(pub(crate) js_sys::Function);

impl JsEventHandler {
    pub fn call(&self, event: JsEvent) {
        // A listener is application code and may throw. The event is dispatched
        // while a lock is held, so unwrapping the error unwinds without dropping
        // the guard, and every later locking call then blocks forever.
        if let Err(err) = self.0.call1(&JsValue::NULL, &event.into()) {
            tracing::warn!(?err, "event listener threw");
        }
    }
}

impl Dupe for JsEventHandler {
    fn dupe(&self) -> Self {
        self.clone()
    }
}

impl PrekeyListener<Local> for JsEventHandler {
    fn on_prekeys_expanded<'a>(
        &'a self,
        e: &'a Arc<verified::Signed<AddKeyOp>>,
    ) -> LocalBoxFuture<'a, ()> {
        Box::pin(async move { self.call(Event::PrekeysExpanded(e.dupe()).into()) })
    }

    fn on_prekey_rotated<'a>(
        &'a self,
        e: &'a Arc<verified::Signed<RotateKeyOp>>,
    ) -> LocalBoxFuture<'a, ()> {
        Box::pin(async move { self.call(Event::PrekeyRotated(e.dupe()).into()) })
    }
}

impl MembershipListener<Local, JsChangeId> for JsEventHandler {
    fn on_delegation<'a>(&'a self, data: &'a Arc<Verified<Delegation>>) -> LocalBoxFuture<'a, ()> {
        Box::pin(async move { self.call(Event::Delegated(data.signed().dupe()).into()) })
    }

    fn on_revocation<'a>(
        &'a self,
        data: &'a Arc<Verified<Revocation<ContentHeads<JsChangeId>>>>,
    ) -> LocalBoxFuture<'a, ()> {
        Box::pin(async move { self.call(Event::Revoked(data.signed().dupe()).into()) })
    }
}

impl CgkaListener<Local> for JsEventHandler {
    fn on_cgka_op<'a>(&'a self, data: &'a Arc<Signed<CgkaOperation>>) -> LocalBoxFuture<'a, ()> {
        Box::pin(async move { self.call(Event::CgkaOperation(data.dupe()).into()) })
    }
}
