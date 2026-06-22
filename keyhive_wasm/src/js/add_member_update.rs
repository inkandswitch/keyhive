use super::signed_delegation::JsSignedDelegation;
use wasm_bindgen::prelude::*;

/// The result of adding a member: the membership delegation.
#[wasm_bindgen(js_name = AddMemberUpdate)]
pub struct JsAddMemberUpdate {
    pub(crate) delegation: JsSignedDelegation,
}

#[wasm_bindgen(js_class = AddMemberUpdate)]
impl JsAddMemberUpdate {
    #[wasm_bindgen(getter)]
    pub fn delegation(&self) -> JsSignedDelegation {
        self.delegation.clone()
    }
}
