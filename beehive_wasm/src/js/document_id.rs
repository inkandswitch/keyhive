use wasm_bindgen::prelude::*;

#[wasm_bindgen(js_name = DocumentId)]
#[derive(Debug, Clone, Copy)]
pub struct JsDocumentId(pub(crate) beehive_core::principal::document::id::DocumentId);

#[wasm_bindgen(js_class = DocumentId)]
impl JsDocumentId {
    #[wasm_bindgen(js_name = fromString)]
    pub fn to_string(&self) -> String {
        format!("{:?}", self.0)
    }

    #[wasm_bindgen(js_name = toJsValue)]
    pub fn to_js_value(&self) -> JsValue {
        JsValue::from(self.to_string())
    }
}
