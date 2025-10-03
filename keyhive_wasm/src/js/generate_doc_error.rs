use derive_more::{From, Into};
use keyhive_core::principal::document::GenerateDocError;
use wasm_bindgen::prelude::*;

pub struct JsGenerateDocError(String);

impl From<GenerateDocError> for JsGenerateDocError {
    fn from(err: GenerateDocError) -> Self {
        JsGenerateDocError(err.to_string())
    }
}

impl From<JsGenerateDocError> for JsValue {
    fn from(err: JsGenerateDocError) -> Self {
        JsError::new(&err.0).into()
    }
}
