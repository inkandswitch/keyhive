use derive_more::{Display, From, Into};
use keyhive_core::principal::document::GenerateDocError;
use thiserror::Error;
use wasm_bindgen::prelude::*;

#[derive(Debug, Display, From, Into, Error)]
pub struct JsGenerateDocError(pub(crate) GenerateDocError);

impl From<JsGenerateDocError> for JsValue {
    fn from(err: JsGenerateDocError) -> Self {
        let err = js_sys::Error::new(&err.to_string());
        err.set_name("GenerateDocError");
        err.into()
    }
}
