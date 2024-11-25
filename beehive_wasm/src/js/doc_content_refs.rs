use super::{change_hash::JsChangeHash, document::JsDocument};
use dupe::Dupe;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct DocContentRefs {
    doc: JsDocument,
    change_hashes: Vec<JsChangeHash>,
}

#[wasm_bindgen]
impl DocContentRefs {
    #[wasm_bindgen(constructor)]
    pub fn new(doc: JsDocument, change_hashes: Vec<JsChangeHash>) -> Result<Self, String> {
        Ok(Self { doc, change_hashes })
    }

    #[wasm_bindgen(js_name = addChangeHash)]
    pub fn add_change_hash(&mut self, hash: JsChangeHash) {
        self.change_hashes.push(hash)
    }

    #[wasm_bindgen(getter)]
    pub fn doc(&self) -> JsDocument {
        self.doc.dupe()
    }

    #[wasm_bindgen(getter)]
    pub fn change_hashes(&self) -> Vec<JsChangeHash> {
        self.change_hashes.clone()
    }
}
