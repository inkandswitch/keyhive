use wasm_bindgen::prelude::*;

#[wasm_bindgen(js_name = ChangeHash)]
#[derive(Clone, Debug)]
pub struct JsChangeHash(pub(crate) automerge::ChangeHash);

impl JsChangeHash {
    pub fn into_inner(self) -> automerge::ChangeHash {
        self.0
    }
}

impl std::ops::Deref for JsChangeHash {
    type Target = automerge::ChangeHash;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
