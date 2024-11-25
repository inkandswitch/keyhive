use beehive_core::{crypto::verifying_key::VerifyingKey, principal::identifier::Identifier};
use wasm_bindgen::prelude::*;

#[wasm_bindgen(js_name = Identifier)]
#[derive(Debug, Clone, Copy)]
pub struct JsIdentifier(pub(crate) Identifier);

#[wasm_bindgen(js_class = Identifier)]
impl JsIdentifier {
    pub fn new(bytes: Vec<u8>) -> Result<Self, CannotParseIdentifier> {
        let arr: [u8; 32] = bytes.try_into().map_err(|_| CannotParseIdentifier)?;

        // NOTE signature::Error is opaque, so we can just ignore the inbuilt error
        let vk = VerifyingKey::from_bytes(arr).map_err(|_| CannotParseIdentifier)?;

        Ok(JsIdentifier(Identifier::from(vk)))
    }
}

#[wasm_bindgen]
#[derive(Debug, Clone, Copy)]
pub struct CannotParseIdentifier;
