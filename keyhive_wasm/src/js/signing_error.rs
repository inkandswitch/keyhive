use keyhive_crypto::{signed::SigningError, verified::SignError};
use thiserror::Error;
use wasm_bindgen::prelude::*;

#[derive(Debug, Error)]
#[error(transparent)]
pub struct JsSigningError(#[from] SignError);

impl From<SigningError> for JsSigningError {
    fn from(err: SigningError) -> Self {
        JsSigningError(SignError::from(err))
    }
}

impl From<JsSigningError> for JsValue {
    fn from(err: JsSigningError) -> Self {
        let err = js_sys::Error::new(&err.to_string());
        err.set_name("SigningError");
        err.into()
    }
}
