use super::hex_string::HexString;
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

    pub(crate) fn to_hex_string(&self) -> HexString {
        HexString::from_vec(self.0.to_vec())
    }

    #[allow(dead_code)]
    pub(crate) fn from_hex_string(hex_string: HexString) -> Result<Self, String> {
        hex_string.to_vec().map(Self)
    }
}
