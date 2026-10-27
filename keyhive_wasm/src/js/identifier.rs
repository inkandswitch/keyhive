use keyhive_crypto::identifier::Identifier;
use thiserror::Error;
use wasm_bindgen::prelude::*;
use wasm_refgen::wasm_refgen;

#[wasm_bindgen(js_name = Identifier)]
#[derive(Debug, Clone, Copy)]
pub struct JsIdentifier(pub(crate) Identifier);

#[wasm_refgen(js_ref = JsIdentifierRef)]
#[wasm_bindgen(js_class = Identifier)]
impl JsIdentifier {
    #[wasm_bindgen(constructor)]
    pub fn new(bytes: Vec<u8>) -> Result<Self, CannotParseIdentifier> {
        let vec: [u8; 32] = bytes.try_into().map_err(|_| CannotParseIdentifier)?;
        let id = Identifier::from_bytes(vec).map_err(|_| CannotParseIdentifier)?;
        Ok(JsIdentifier(id))
    }

    #[wasm_bindgen(js_name = toString)]
    pub fn to_js_string(&self) -> String {
        format!("{:#x}", self.0)
    }

    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.as_bytes().to_vec()
    }
}

impl From<Identifier> for JsIdentifier {
    fn from(id: Identifier) -> Self {
        JsIdentifier(id)
    }
}

#[wasm_bindgen]
#[derive(Debug, Clone, Copy, Error)]
#[error("Cannot parse identifier")]
pub struct CannotParseIdentifier;
