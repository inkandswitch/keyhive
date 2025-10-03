use super::{
    change_ref::JsChangeRef, event_handler::JsEventHandler, revocation::JsRevocation,
    signer::JsSigner,
};
use dupe::Dupe;
use keyhive_core::{
    crypto::{signed::Signed, verifiable::Verifiable},
    principal::group::revocation::Revocation,
};
use std::sync::Arc;
use wasm_bindgen::prelude::*;

#[wasm_bindgen(js_name = SignedRevocation)]
#[derive(Debug, Dupe, Clone)]
pub struct JsSignedRevocation(
    pub(crate) Arc<Signed<Revocation<JsSigner, JsChangeRef, JsEventHandler>>>,
);

#[wasm_bindgen(js_class = SignedRevocation)]
impl JsSignedRevocation {
    pub fn verify(&self) -> bool {
        self.0.try_verify().is_ok()
    }

    #[wasm_bindgen(getter)]
    pub fn delegation(&self) -> JsRevocation {
        self.0.payload().clone().into()
    }

    #[wasm_bindgen(getter, js_name = verifyingKey)]
    pub fn verifying_key(&self) -> Vec<u8> {
        self.0.verifying_key().to_bytes().to_vec()
    }

    #[wasm_bindgen(getter)]
    pub fn signature(&self) -> Vec<u8> {
        self.0.signature().to_vec()
    }
}

impl From<Arc<Signed<Revocation<JsSigner, JsChangeRef, JsEventHandler>>>> for JsSignedRevocation {
    fn from(signed: Arc<Signed<Revocation<JsSigner, JsChangeRef, JsEventHandler>>>) -> Self {
        Self(signed)
    }
}

impl From<JsSignedRevocation> for Arc<Signed<Revocation<JsSigner, JsChangeRef, JsEventHandler>>> {
    fn from(js_signed: JsSignedRevocation) -> Self {
        js_signed.0
    }
}
