use std::fmt::{Display, Formatter};
use wasm_bindgen::prelude::*;

#[wasm_bindgen(js_name = GroupId)]
#[derive(Debug)]
pub struct JsGroupId(pub(crate) keyhive_core::principal::group::id::GroupId);

#[wasm_bindgen(js_class = GroupId)]
impl JsGroupId {
    #[wasm_bindgen(js_name = toString)]
    pub fn to_js_string(&self) -> String {
        self.0.to_string()
    }
}

impl Display for JsGroupId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.0)
    }
}
