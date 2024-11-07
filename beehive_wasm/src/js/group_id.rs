use wasm_bindgen::prelude::*;

#[wasm_bindgen(js_name = GroupId)]
#[derive(Debug)]
pub struct JsGroupId(pub(crate) beehive_core::principal::group::id::GroupId);

#[wasm_bindgen(js_class = GroupId)]
impl JsGroupId {
    #[wasm_bindgen(js_name = toString)]
    pub fn to_string(&self) -> String {
        format!("{:?}", self.0)
    }
}
