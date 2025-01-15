use std::fmt::{Display, Formatter};
use wasm_bindgen::prelude::*;

#[wasm_bindgen(js_name = DocumentId)]
#[derive(Debug, Clone, Copy)]
pub struct JsDocumentId(pub(crate) beehive_core::principal::document::id::DocumentId);

#[wasm_bindgen(js_class = DocumentId)]
impl JsDocumentId {
    #[wasm_bindgen(js_name = fromString)]
    pub fn to_js_string(&self) -> String {
        self.0.to_string()
    }

    #[wasm_bindgen(js_name = toJsValue)]
    pub fn to_js_value(&self) -> JsValue {
        JsValue::from(self.to_js_string())
    }
}

impl Display for JsDocumentId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.0)
    }
}
