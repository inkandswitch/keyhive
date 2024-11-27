use super::{change_ref::JsChangeRef, revocation::JsRevocation};
use beehive_core::{crypto::signed::Signed, principal::group::operation::revocation::Revocation};
use wasm_bindgen::prelude::*;

#[wasm_bindgen(js_name = SignedRevocation)]
pub struct JsSignedRevocation(pub(crate) Signed<Revocation<JsChangeRef>>);

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

impl From<Signed<Revocation<JsChangeRef>>> for JsSignedRevocation {
    fn from(signed: Signed<Revocation<JsChangeRef>>) -> Self {
        Self(signed)
    }
}

impl From<JsSignedRevocation> for Signed<Revocation<JsChangeRef>> {
    fn from(js_signed: JsSignedRevocation) -> Self {
        js_signed.0
    }
}
