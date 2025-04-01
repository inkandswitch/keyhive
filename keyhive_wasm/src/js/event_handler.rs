use super::{change_ref::JsChangeRef, event::JsEvent, signer::JsSigner};
use derive_more::{From, Into};
use dupe::Dupe;
use keyhive_core::{
    cgka::operation::CgkaOperation,
    crypto::{
        share_key::{ShareKey, ShareSecretKey},
        signed::Signed,
    },
    event::Event,
    listener::{
        cgka::CgkaListener, membership::MembershipListener, prekey::PrekeyListener,
        secret::SecretListener,
    },
    principal::{
        document::id::DocumentId,
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
    async fn on_cgka_op(&self, data: &Rc<Signed<CgkaOperation>>) {
        self.call(Event::CgkaOperation(data.dupe()).into())
    }
}

impl SecretListener for JsEventHandler {
    async fn on_active_prekey_pair(
        &self,
        new_public_key: ShareKey,
        new_secret_key: ShareSecretKey,
    ) {
        self.call(
            Event::ActiveAgentSecret {
                public_key: new_public_key,
                secret_key: new_secret_key,
            }
            .into(),
        )
    }

    async fn on_doc_sharing_secret(
        &self,
        doc_id: DocumentId,
        new_public_key: ShareKey,
        new_secret_key: ShareSecretKey,
    ) {
        self.call(
            Event::DocumentSecret {
                doc_id,
                public_key: new_public_key,
                secret_key: new_secret_key,
            }
            .into(),
        )
    }
}
