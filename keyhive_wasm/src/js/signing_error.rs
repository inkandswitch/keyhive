use keyhive_core::crypto::signed::SigningError;
use thiserror::Error;
use wasm_bindgen::prelude::*;

#[wasm_bindgen(js_name = "SigningError")]
#[derive(Debug, Error)]
#[error(transparent)]
pub struct JsSigningError(Box<SigningError>);

#[wasm_bindgen(js_class = "SigningError")]
impl JsSigningError {
    pub fn message(&self) -> String {
        self.0.to_string()
    }
}

impl From<SigningError> for JsSigningError {
    fn from(e: SigningError) -> Self {
        JsSigningError(Box::new(e))
    }
}
