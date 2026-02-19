use super::{change_id::JsChangeId, event::JsEvent, signer::JsSigner};
use derive_more::{From, Into};
use dupe::Dupe;
use future_form::Local;
use keyhive_core::{
    cgka::operation::CgkaOperation,
    crypto::signed::Signed,
    event::static_event::StaticEvent,
    listener::{cgka::CgkaListener, membership::MembershipListener, prekey::PrekeyListener},
    principal::group::{
        delegation::{Delegation, StaticDelegation},
        revocation::{Revocation, StaticRevocation},
    },
    principal::individual::op::{add_key::AddKeyOp, rotate_key::RotateKeyOp},
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
    fn on_prekeys_expanded<'a>(
        &'a self,
        e: &'a Arc<Signed<AddKeyOp>>,
    ) -> <Local as future_form::FutureForm>::Future<'a, ()> {
        let event = StaticEvent::PrekeysExpanded(Box::new(e.as_ref().clone()));
        Box::pin(async move {
            self.call(event.into())
        })
    }

    fn on_prekey_rotated<'a>(
        &'a self,
        e: &'a Arc<Signed<RotateKeyOp>>,
    ) -> <Local as future_form::FutureForm>::Future<'a, ()> {
        let event = StaticEvent::PrekeyRotated(Box::new(e.as_ref().clone()));
        Box::pin(async move {
            self.call(event.into())
        })
    }
}

impl MembershipListener<Local, JsSigner, JsChangeId> for JsEventHandler {
    fn on_delegation<'a>(
        &'a self,
        data: &'a Arc<Signed<Delegation<Local, JsSigner, JsChangeId, Self>>>,
    ) -> <Local as future_form::FutureForm>::Future<'a, ()> {
        let static_dlg: StaticDelegation<JsChangeId> = data.payload().clone().into();
        let signed_static = data.as_ref().clone().map(|_| static_dlg);
        let event = StaticEvent::Delegated(signed_static);
        Box::pin(async move {
            self.call(event.into())
        })
    }

    fn on_revocation<'a>(
        &'a self,
        data: &'a Arc<Signed<Revocation<Local, JsSigner, JsChangeId, Self>>>,
    ) -> <Local as future_form::FutureForm>::Future<'a, ()> {
        let static_rev: StaticRevocation<JsChangeId> = data.payload().clone().into();
        let signed_static = data.as_ref().clone().map(|_| static_rev);
        let event = StaticEvent::Revoked(signed_static);
        Box::pin(async move {
            self.call(event.into())
        })
    }
}

impl CgkaListener<Local> for JsEventHandler {
    fn on_cgka_op<'a>(
        &'a self,
        data: &'a Arc<Signed<CgkaOperation>>,
    ) -> <Local as future_form::FutureForm>::Future<'a, ()> {
        let event = StaticEvent::CgkaOperation(Box::new(data.as_ref().clone()));
        Box::pin(async move {
            self.call(event.into())
        })
    }
}
