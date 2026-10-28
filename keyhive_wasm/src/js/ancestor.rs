use super::{change_id::JsChangeId, symmetric::key_from_bytes};
use keyhive_crypto::symmetric_key::SymmetricKey;
use wasm_bindgen::prelude::*;
use wasm_refgen::wasm_refgen;

/// A block's `ChangeId` and the key that opens it.
#[wasm_bindgen(js_name = Ancestor)]
#[derive(Debug, Clone)]
pub struct JsAncestor {
    /// The change ID for this ancestor.
    pub(crate) content_ref: JsChangeId,
    /// The key to decrypt this ancestor.
    pub(crate) key: SymmetricKey,
}

#[wasm_refgen(js_ref = JsAncestorRef)]
#[wasm_bindgen(js_class = Ancestor)]
impl JsAncestor {
    /// `key` is the ancestor's 32-byte application secret.
    #[wasm_bindgen(constructor)]
    pub fn new(content_ref: &JsChangeId, key: &[u8]) -> Result<JsAncestor, JsValue> {
        Ok(JsAncestor {
            content_ref: content_ref.clone(),
            key: key_from_bytes(key)?,
        })
    }

    /// The block's `ChangeId`.
    #[wasm_bindgen(getter, js_name = contentRef)]
    pub fn content_ref(&self) -> JsChangeId {
        self.content_ref.clone()
    }

    /// Treat as secret: do not log or persist unencrypted.
    #[wasm_bindgen(getter)]
    pub fn key(&self) -> Vec<u8> {
        self.key.as_slice().to_vec()
    }
}

impl JsAncestor {
    pub(crate) fn into_parts(self) -> (JsChangeId, SymmetricKey) {
        (self.content_ref, self.key)
    }
}
