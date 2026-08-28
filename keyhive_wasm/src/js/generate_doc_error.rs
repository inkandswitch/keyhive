use derive_more::{Display, From};
use keyhive_core::{error::not_found::NotFound, principal::document::GenerateDocError};
use thiserror::Error;
use wasm_bindgen::prelude::*;

#[derive(Debug, Display, Error, From)]
pub enum JsGenerateDocError {
    #[display("{_0}")]
    GenerateDoc(GenerateDocError),

    /// The document was created and could not then be read back.
    #[display("{_0}")]
    NotFound(NotFound),
}

impl From<JsGenerateDocError> for JsValue {
    fn from(err: JsGenerateDocError) -> Self {
        let err = js_sys::Error::new(&err.to_string());
        err.set_name("GenerateDocError");
        err.into()
    }
}
