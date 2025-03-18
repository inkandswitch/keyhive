use super::change_ref::JsChangeRef;
use keyhive_core::crypto::encrypted::EncryptedContent;
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

#[wasm_bindgen(js_name = Encrypted)]
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct JsEncrypted(pub(crate) EncryptedContent<Vec<u8>, JsChangeRef>);

#[wasm_bindgen(js_class = Encrypted)]
impl JsEncrypted {
    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.ciphertext.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn ciphertext(&self) -> Vec<u8> {
        self.0.ciphertext.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn nonce(&self) -> Vec<u8> {
        self.0.nonce.as_bytes().to_vec()
    }

    #[wasm_bindgen(getter)]
    pub fn pcs_key_hash(&self) -> Vec<u8> {
        self.0.pcs_key_hash.raw.as_bytes().to_vec()
    }

    #[wasm_bindgen(getter)]
    pub fn content_ref(&self) -> Vec<u8> {
        self.0.content_ref.bytes().to_vec()
    }

    #[wasm_bindgen(getter)]
    pub fn pred_refs(&self) -> Vec<u8> {
        self.0.pred_refs.raw.as_bytes().to_vec()
    }
}

impl From<EncryptedContent<Vec<u8>, JsChangeRef>> for JsEncrypted {
    fn from(encrypted: EncryptedContent<Vec<u8>, JsChangeRef>) -> Self {
        JsEncrypted(encrypted)
    }
}
