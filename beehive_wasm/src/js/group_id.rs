use wasm_bindgen::prelude::*;

#[wasm_bindgen(js_name = GroupId)]
#[derive(Debug)]
pub struct JsGroupId(pub(crate) beehive_core::principal::group::id::GroupId);

#[wasm_bindgen(js_class = JsGroupId)]
impl JsGroupId {
    #[wasm_bindgen(js_name = fromString)]
    pub fn to_string(&self) -> String {
        format!("{:?}", self.0)
    }
}
