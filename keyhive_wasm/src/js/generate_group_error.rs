use derive_more::{Display, From};
use keyhive_core::{error::not_found::NotFound, keyhive::GenerateGroupError};
use thiserror::Error;
use wasm_bindgen::prelude::*;

#[derive(Debug, Display, Error, From)]
pub enum JsGenerateGroupError {
    /// Generating the group failed.
    #[display("{_0}")]
    GenerateGroup(GenerateGroupError),

    /// The group was created and could not then be read back.
    #[display("{_0}")]
    NotFound(NotFound),
}

impl From<JsGenerateGroupError> for JsValue {
    fn from(err: JsGenerateGroupError) -> Self {
        let err = js_sys::Error::new(&err.to_string());
        err.set_name("GenerateGroupError");
        err.into()
    }
}
