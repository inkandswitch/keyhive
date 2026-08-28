use derive_more::Display;
use keyhive_core::keyhive::NotFound;
use keyhive_crypto::signed::SigningError;
use thiserror::Error;
use wasm_bindgen::prelude::*;

#[derive(Debug, Display, Error)]
pub enum JsGenerateGroupError {
    #[display("{_0}")]
    Signing(SigningError),

    /// The group was created and could not then be read back.
    #[display("{_0}")]
    NotFound(NotFound),
}

impl From<SigningError> for JsGenerateGroupError {
    fn from(e: SigningError) -> Self {
        JsGenerateGroupError::Signing(e)
    }
}

impl From<NotFound> for JsGenerateGroupError {
    fn from(e: NotFound) -> Self {
        JsGenerateGroupError::NotFound(e)
    }
}

impl From<JsGenerateGroupError> for JsValue {
    fn from(err: JsGenerateGroupError) -> Self {
        let err = js_sys::Error::new(&err.to_string());
        err.set_name("GenerateGroupError");
        err.into()
    }
}
