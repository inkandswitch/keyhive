use super::{access::JsAccess, document::JsDocument};
use dupe::Dupe;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct Summary {
    pub(crate) doc: JsDocument,
    pub(crate) access: JsAccess,
}

#[wasm_bindgen]
impl Summary {
    #[wasm_bindgen(getter)]
    pub fn doc(&self) -> JsDocument {
        self.doc.dupe()
    }

    #[wasm_bindgen(getter)]
    pub fn access(&self) -> JsAccess {
        self.access.dupe()
    }
}
