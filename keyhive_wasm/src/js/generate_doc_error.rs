use derive_more::Display;
use keyhive_core::{keyhive::NotFound, principal::document::GenerateDocError};
use thiserror::Error;
use wasm_bindgen::prelude::*;

#[derive(Debug, Display, Error)]
pub enum JsGenerateDocError {
    #[display("{_0}")]
    GenerateDoc(GenerateDocError),

    /// The document was created and could not then be read back.
    #[display("{_0}")]
    NotFound(NotFound),
}

impl From<GenerateDocError> for JsGenerateDocError {
    fn from(e: GenerateDocError) -> Self {
        JsGenerateDocError::GenerateDoc(e)
    }
}

impl From<NotFound> for JsGenerateDocError {
    fn from(e: NotFound) -> Self {
        JsGenerateDocError::NotFound(e)
    }
}

impl From<JsGenerateDocError> for JsValue {
    fn from(err: JsGenerateDocError) -> Self {
        let err = js_sys::Error::new(&err.to_string());
        err.set_name("GenerateDocError");
        err.into()
    }
}
