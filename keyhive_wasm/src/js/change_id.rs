use super::base64::Base64;
use derive_more::{From, Into};
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;
use wasm_refgen::wasm_refgen;

#[wasm_bindgen(js_name = ChangeId)]
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Into, From,
)]
pub struct JsChangeId(pub(crate) Vec<u8>);

#[wasm_refgen(js_ref = JsChangeIdRef)]
#[wasm_bindgen(js_class = ChangeId)]
impl JsChangeId {
    #[wasm_bindgen(constructor)]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    #[wasm_bindgen(getter)]
    pub fn bytes(&self) -> Vec<u8> {
        self.0.clone()
    }

    pub(crate) fn to_base64(&self) -> Base64 {
        Base64::from_vec(self.0.clone())
    }

    #[allow(dead_code)]
    pub(crate) fn from_base64(b64: Base64) -> Result<Self, base64_simd::Error> {
        Ok(Self(b64.into_vec()?))
    }
}
