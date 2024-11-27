use super::change_ref::JsChangeRef;
use beehive_core::crypto::encrypted::Encrypted;
use wasm_bindgen::prelude::*;

#[wasm_bindgen(js_name = Encrypted)]
pub struct JsEncrypted(Encrypted<Vec<u8>, JsChangeRef>);

#[wasm_bindgen(js_class = Encrypted)]
impl JsEncrypted {
    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.ciphertext.clone() // FIXME
    }

    #[wasm_bindgen(getter)]
    pub fn ciphertext(&self) -> Vec<u8> {
        self.0.ciphertext.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn nonce(&self) -> Vec<u8> {
        self.0.nonce.as_bytes().to_vec()
    }
}

impl From<Encrypted<Vec<u8>, JsChangeRef>> for JsEncrypted {
    fn from(encrypted: Encrypted<Vec<u8>, JsChangeRef>) -> Self {
        JsEncrypted(encrypted)
    }
}
