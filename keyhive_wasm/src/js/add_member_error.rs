use keyhive_core::principal::document::AddMemberError;
use thiserror::Error;
use wasm_bindgen::prelude::*;

#[derive(Debug, Error)]
#[wasm_bindgen(js_name = AddMemberError)]
#[error(transparent)]
pub struct JsAddMemberError(#[from] pub(crate) AddMemberError);

#[wasm_bindgen(js_class = "AddMemberError")]
impl JsAddMemberError {
    pub fn message(&self) -> String {
        self.0.to_string()
    }
}
