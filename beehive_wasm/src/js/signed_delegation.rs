use super::{change_ref::JsChangeRef, delegation::JsDelegation, signer::JsSigner};
use beehive_core::{crypto::signed::Signed, principal::group::operation::delegation::Delegation};
use wasm_bindgen::prelude::*;

#[wasm_bindgen(js_name = SignedDelegation)]
pub struct JsSignedDelegation(pub(crate) Signed<Delegation<JsChangeRef, JsSigner>>);

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

impl From<Signed<Delegation<JsChangeRef, JsSigner>>> for JsSignedDelegation {
    fn from(signed: Signed<Delegation<JsChangeRef, JsSigner>>) -> Self {
        Self(signed)
    }
}

impl From<JsSignedDelegation> for Signed<Delegation<JsChangeRef, JsSigner>> {
    fn from(js_signed: JsSignedDelegation) -> Self {
        js_signed.0
    }
}
