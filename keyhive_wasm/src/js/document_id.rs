use derive_more::{Display, From, Into};
use keyhive_core::principal::{document::id::DocumentId, identifier::Identifier};
use wasm_bindgen::prelude::*;

use crate::js::identifier::CannotParseIdentifier;

#[wasm_bindgen(js_name = DocumentId)]
#[derive(Debug, Clone, Copy, Display, From, Into)]
pub struct JsDocumentId(pub(crate) keyhive_core::principal::document::id::DocumentId);

#[wasm_bindgen(js_class = DocumentId)]
impl JsDocumentId {
    #[wasm_bindgen(constructor)]
    pub fn new(bytes: Vec<u8>) -> Result<Self, CannotParseIdentifier> {
        let vec: [u8; 32] = bytes.try_into().map_err(|_| CannotParseIdentifier)?;

        // NOTE signature::Error is opaque, so we can just ignore the inbuilt error
        let vk =
            ed25519_dalek::VerifyingKey::from_bytes(&vec).map_err(|_| CannotParseIdentifier)?;

        Ok(JsDocumentId(DocumentId::from(Identifier::from(vk))))
    }

    #[wasm_bindgen(js_name = fromString)]
    pub fn to_js_string(&self) -> String {
        self.to_string()
    }

    #[wasm_bindgen(js_name = toJsValue)]
    pub fn to_js_value(&self) -> JsValue {
        JsValue::from(self.to_js_string())
    }

    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.as_bytes().to_vec()
    }
}
