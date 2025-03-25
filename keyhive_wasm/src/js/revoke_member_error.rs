use keyhive_core::principal::group::RevokeMemberError;
use thiserror::Error;
use wasm_bindgen::prelude::*;

#[derive(Debug, Error)]
#[error(transparent)]
#[wasm_bindgen(js_name = RevokeMemberError)]
pub struct JsRevokeMemberError(#[from] pub(crate) RevokeMemberError);

#[wasm_bindgen(js_class = "RevokeMemberError")]
impl JsRevokeMemberError {
    #[wasm_bindgen(getter)]
    pub fn message(&self) -> String {
        self.0.to_string()
    }
}
