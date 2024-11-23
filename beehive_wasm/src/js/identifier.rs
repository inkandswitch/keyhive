use beehive_core::principal::identifier::Identifier;
use wasm_bindgen::prelude::*;

#[wasm_bindgen(js_name = Identifier)]
#[derive(Debug, Clone, Copy)]
pub struct JsIdentifier(pub(crate) Identifier);

#[wasm_bindgen(js_class = Identifier)]
impl JsIdentifier {
    pub fn new(bytes: Vec<u8>) -> Result<Self, CannotParseIdentifier> {
        let vec: [u8; 32] = bytes.try_into().map_err(|_| CannotParseIdentifier)?;

        // NOTE signature::Error is opaque, so we can just ignore the inbuilt error
        let vk =
            ed25519_dalek::VerifyingKey::from_bytes(&vec).map_err(|_| CannotParseIdentifier)?;

        Ok(JsIdentifier(Identifier::from(vk)))
    }
}

#[wasm_bindgen]
#[derive(Debug, Clone, Copy)]
pub struct CannotParseIdentifier;
