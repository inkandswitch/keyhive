use keyhive_core::principal::identifier::Identifier;
use thiserror::Error;
use wasm_bindgen::prelude::*;

#[wasm_bindgen(js_name = Identifier)]
#[derive(Debug, Clone, Copy)]
pub struct JsIdentifier(pub(crate) Identifier);

#[wasm_bindgen(js_class = Identifier)]
impl JsIdentifier {
    #[wasm_bindgen(constructor)]
    pub fn new(bytes: Vec<u8>) -> Result<Self, CannotParseIdentifier> {
        let vec: [u8; 32] = bytes.try_into().map_err(|_| CannotParseIdentifier)?;

        // NOTE signature::Error is opaque, so we can just ignore the inbuilt error
        let vk =
            ed25519_dalek::VerifyingKey::from_bytes(&vec).map_err(|_| CannotParseIdentifier)?;

        Ok(JsIdentifier(Identifier::from(vk)))
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
