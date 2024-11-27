use std::fmt::{Display, Formatter};
use wasm_bindgen::prelude::*;

#[wasm_bindgen(js_name = DocumentId)]
#[derive(Debug, Clone, Copy)]
pub struct JsDocumentId(pub(crate) beehive_core::principal::document::id::DocumentId);

#[wasm_bindgen(js_class = DocumentId)]
impl JsDocumentId {
    #[wasm_bindgen(js_name = toString)]
    pub fn to_js_string(&self) -> String {
        self.0.to_string()
    }
}

impl Display for JsDocumentId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}
