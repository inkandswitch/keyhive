use derive_more::{Display, From, Into};
use keyhive_core::principal::document::GenerateDocError;
use thiserror::Error;
use wasm_bindgen::prelude::*;

#[wasm_bindgen(js_name = "GenerateDocError")]
#[derive(Debug, Display, From, Into, Error)]
pub struct JsGenerateDocError(pub(crate) GenerateDocError);

#[wasm_bindgen(js_class = "GenerateDocError")]
impl JsGenerateDocError {
    pub fn message(&self) -> String {
        self.0.to_string()
    }
}
