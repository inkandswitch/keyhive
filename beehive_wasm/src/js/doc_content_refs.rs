use super::{change_ref::JsChangeRef, document_id::JsDocumentId};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct DocContentRefs {
    pub(crate) doc_id: JsDocumentId,
    pub(crate) change_hashes: Vec<JsChangeRef>,
}

#[wasm_bindgen]
impl DocContentRefs {
    #[wasm_bindgen(constructor)]
    pub fn new(doc_id: JsDocumentId, change_hashes: Vec<JsChangeRef>) -> Result<Self, String> {
        Ok(Self {
            doc_id,
            change_hashes,
        })
    }

    #[wasm_bindgen(js_name = addChangeRef)]
    pub fn add_change_hash(&mut self, hash: JsChangeRef) {
        self.change_hashes.push(hash)
    }

    #[wasm_bindgen(getter, js_name = docId)]
    pub fn doc_id(&self) -> JsDocumentId {
        self.doc_id
    }

    #[wasm_bindgen(getter)]
    pub fn change_hashes(&self) -> Vec<JsChangeRef> {
        self.change_hashes.clone()
    }
}
