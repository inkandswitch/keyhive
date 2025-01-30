use derive_more::{Display, From, Into};
use wasm_bindgen::prelude::*;

#[wasm_bindgen(js_name = DocumentId)]
#[derive(Debug, Clone, Copy, Display, From, Into)]
pub struct JsDocumentId(pub(crate) keyhive_core::principal::document::id::DocumentId);

#[wasm_bindgen(js_class = DocumentId)]
impl JsDocumentId {
    #[wasm_bindgen(js_name = fromString)]
    pub fn to_js_string(&self) -> String {
        self.to_string()
    }

    #[wasm_bindgen(js_name = toJsValue)]
    pub fn to_js_value(&self) -> JsValue {
        JsValue::from(self.to_js_string())
    }
}
