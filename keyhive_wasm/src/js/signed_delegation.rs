use super::{
    change_ref::JsChangeRef, delegation::JsDelegation, event_handler::JsEventHandler,
    signer::JsSigner,
};
use derive_more::{From, Into};
use dupe::Dupe;
use keyhive_core::{
    crypto::{signed::Signed, verifiable::Verifiable},
    principal::group::delegation::Delegation,
};
use std::sync::Arc;
use wasm_bindgen::prelude::*;

#[derive(Debug, Clone, Dupe, From, Into)]
#[wasm_bindgen(js_name = SignedDelegation)]
pub struct JsSignedDelegation(
    pub(crate) Arc<Signed<Delegation<JsSigner, JsChangeRef, JsEventHandler>>>,
);

#[wasm_bindgen(js_class = SignedDelegation)]
impl JsSignedDelegation {
    pub fn verify(&self) -> bool {
        self.0.try_verify().is_ok()
    }

    #[wasm_bindgen(getter)]
    pub fn delegation(&self) -> JsDelegation {
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
