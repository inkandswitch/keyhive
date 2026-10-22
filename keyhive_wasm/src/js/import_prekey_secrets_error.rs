use keyhive_core::principal::active::ImportPrekeySecretsError;
use thiserror::Error;
use wasm_bindgen::prelude::*;

#[derive(Debug, Error)]
#[error(transparent)]
pub struct JsImportPrekeySecretsError(#[from] ImportPrekeySecretsError);

impl From<JsImportPrekeySecretsError> for JsValue {
    fn from(err: JsImportPrekeySecretsError) -> Self {
        let err = js_sys::Error::new(&err.to_string());
        err.set_name("ImportPrekeySecretsError");
        err.into()
    }
}
