use keyhive_core::principal::group::RevokeMemberError;
use thiserror::Error;
use wasm_bindgen::prelude::*;

#[derive(Debug, Error)]
#[error(transparent)]
pub struct JsRevokeMemberError(#[from] pub(crate) RevokeMemberError);

impl From<JsRevokeMemberError> for JsValue {
    fn from(err: JsRevokeMemberError) -> Self {
        let err = js_sys::Error::new(&err.to_string());
        err.set_name("RevokeMemberError");
        err.into()
    }
}
