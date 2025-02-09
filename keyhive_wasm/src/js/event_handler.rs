use super::{change_ref::JsChangeRef, event::JsEvent, signer::JsSigner};
use derive_more::{From, Into};
use dupe::Dupe;
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
use std::rc::Rc;
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

impl PrekeyListener for JsEventHandler {
    async fn on_prekeys_expanded(&self, e: &Rc<Signed<AddKeyOp>>) {
        self.call(Event::PrekeysExpanded(e.dupe()).into())
    }

    async fn on_prekey_rotated(&self, e: &Rc<Signed<RotateKeyOp>>) {
        self.call(Event::PrekeyRotated(e.dupe()).into())
    }
}

impl MembershipListener<JsSigner, JsChangeRef> for JsEventHandler {
    async fn on_delegation(&self, data: &Rc<Signed<Delegation<JsSigner, JsChangeRef, Self>>>) {
        self.call(Event::Delegated(data.dupe()).into())
    }

    async fn on_revocation(&self, data: &Rc<Signed<Revocation<JsSigner, JsChangeRef, Self>>>) {
        self.call(Event::Revoked(data.dupe()).into())
    }
}

impl CgkaListener for JsEventHandler {
    fn on_cgka_op(&self, data: &Rc<Signed<CgkaOperation>>) {
        self.call(Event::CgkaOperation(data.dupe()).into())
    }
}
