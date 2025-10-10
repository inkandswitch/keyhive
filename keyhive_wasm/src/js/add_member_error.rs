use keyhive_core::principal::document::AddMemberError;
use thiserror::Error;
use wasm_bindgen::JsValue;

#[derive(Debug, Error)]
#[error(transparent)]
pub struct JsAddMemberError(#[from] pub(crate) AddMemberError);

impl From<JsAddMemberError> for JsValue {
    fn from(err: JsAddMemberError) -> Self {
        let err = js_sys::Error::new(&err.to_string());
        err.set_name("AddMemberError");
        err.into()
    }
}
