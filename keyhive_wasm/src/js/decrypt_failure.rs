use super::change_id::JsChangeId;
use wasm_bindgen::prelude::*;

/// A block a causal decryption could not read.
#[wasm_bindgen(js_name = DecryptFailure)]
#[derive(Debug, Clone)]
pub struct JsDecryptFailure {
    pub(crate) content_ref: JsChangeId,
    pub(crate) reason: String,
}

#[wasm_bindgen(js_class = DecryptFailure)]
impl JsDecryptFailure {
    /// The `ChangeId` of the block that could not be read.
    #[wasm_bindgen(getter, js_name = contentRef)]
    pub fn content_ref(&self) -> JsChangeId {
        self.content_ref.clone()
    }

    /// The reason for the failure.
    #[wasm_bindgen(getter)]
    pub fn reason(&self) -> String {
        self.reason.clone()
    }
}
