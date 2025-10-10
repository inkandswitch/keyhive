use keyhive_core::crypto::signed::SigningError;
use thiserror::Error;
use wasm_bindgen::prelude::*;

#[derive(Debug, Error)]
#[error(transparent)]
pub struct JsSigningError(#[from] SigningError);

impl From<JsSigningError> for JsValue {
    fn from(err: JsSigningError) -> Self {
        let err = js_sys::Error::new(&err.to_string());
        err.set_name("SigningError");
        err.into()
    }
}
