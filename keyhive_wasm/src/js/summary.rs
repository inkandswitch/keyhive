use super::{document::JsDocument, power::JsPower};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct Summary {
    pub(crate) doc: JsDocument,
    pub(crate) access: JsPower,
}

#[wasm_bindgen]
impl Summary {
    #[wasm_bindgen(getter)]
    pub fn doc(&self) -> JsDocument {
        self.doc.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn access(&self) -> JsPower {
        self.access
    }
}
