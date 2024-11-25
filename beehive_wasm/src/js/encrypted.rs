use beehive_core::crypto::encrypted::Encrypted;
use wasm_bindgen::prelude::*;

#[wasm_bindgen(js_name = Encrypted)]
pub struct JsEncrypted(Encrypted<Vec<u8>>);

#[wasm_bindgen(js_class = Encrypted)]
impl JsEncrypted {
    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.ciphertext.clone() // FIXME
    }
}

impl From<Encrypted<Vec<u8>>> for JsEncrypted {
    fn from(encrypted: Encrypted<Vec<u8>>) -> Self {
        JsEncrypted(encrypted)
    }
}
