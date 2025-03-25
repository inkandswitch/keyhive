use js_sys::Uint8Array;
use wasm_bindgen::prelude::*;

#[wasm_bindgen(module = "/src/snippets/base64.js")] // FIXME move
extern "C" {
    // This exposes the functions to JS from the inline block
    fn uint8ArrayToBase64(bytes: Uint8Array) -> String;
    fn base64ToUint8Array(base64Str: String) -> Uint8Array;
}

#[derive(Debug, Clone)]
pub(crate) struct Base64(pub(crate) String);

impl Base64 {
    #[allow(dead_code)]
    pub fn from_uint8array(bytes: Uint8Array) -> Self {
        Self(uint8ArrayToBase64(bytes))
    }

    #[allow(dead_code)]
    pub fn to_uint8array(&self) -> Uint8Array {
        base64ToUint8Array(self.0.clone())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn to_vec(&self) -> Vec<u8> {
        self.0.as_bytes().to_vec()
    }
}
