use super::change_id::JsChangeId;
use keyhive_crypto::symmetric_key::SymmetricKey;
use std::rc::Rc;
use wasm_bindgen::prelude::*;

/// A decrypted block.
#[wasm_bindgen(js_name = DecryptedContent)]
#[derive(Debug, Clone)]
pub struct JsDecryptedContent {
    pub(crate) content_ref: JsChangeId,
    pub(crate) content: Rc<[u8]>,
    pub(crate) key: SymmetricKey,
}

#[wasm_bindgen(js_class = DecryptedContent)]
impl JsDecryptedContent {
    /// The block's `ChangeId`.
    #[wasm_bindgen(getter, js_name = contentRef)]
    pub fn content_ref(&self) -> JsChangeId {
        self.content_ref.clone()
    }

    /// Copies the content out of wasm memory on every call.
    pub fn content(&self) -> Vec<u8> {
        self.content.to_vec()
    }

    /// The block's 32-byte application secret.
    /// Treat as secret: do not log or persist unencrypted.
    #[wasm_bindgen(getter, js_name = applicationSecret)]
    pub fn application_secret(&self) -> Vec<u8> {
        self.key.as_slice().to_vec()
    }
}
