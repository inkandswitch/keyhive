use super::base64::Base64;
use derive_more::{From, Into};
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

#[wasm_bindgen(js_name = ChangeRef)]
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Into, From,
)]
pub struct JsChangeRef(pub(crate) Vec<u8>);

#[wasm_bindgen(js_class = ChangeRef)]
impl JsChangeRef {
    #[wasm_bindgen(constructor)]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    #[wasm_bindgen(getter)]
    pub fn bytes(&self) -> Vec<u8> {
        self.0.clone()
    }

    pub(crate) fn to_base64(&self) -> Base64 {
        Base64::from_uint8array(js_sys::Uint8Array::from(self.0.as_slice()))
    }

    #[allow(dead_code)]
    pub(crate) fn from_base64(base64: Base64) -> Self {
        Self(base64.to_uint8array().to_vec())
    }
}
