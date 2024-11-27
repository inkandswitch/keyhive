use super::{change_ref::JsChangeRef, document::JsDocument};
use dupe::Dupe;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct DocContentRefs {
    pub(crate) doc: JsDocument,
    pub(crate) change_hashes: Vec<JsChangeRef>,
}

#[wasm_bindgen]
impl DocContentRefs {
    #[wasm_bindgen(constructor)]
    pub fn new(doc: JsDocument, change_hashes: Vec<JsChangeRef>) -> Result<Self, String> {
        Ok(Self { doc, change_hashes })
    }

    #[wasm_bindgen(js_name = addChangeRef)]
    pub fn add_change_hash(&mut self, hash: JsChangeRef) {
        self.change_hashes.push(hash)
    }

    #[wasm_bindgen(getter)]
    pub fn doc(&self) -> JsDocument {
        self.doc.dupe()
    }

    #[wasm_bindgen(getter)]
    pub fn change_hashes(&self) -> Vec<JsChangeRef> {
        self.change_hashes.clone()
    }
}
