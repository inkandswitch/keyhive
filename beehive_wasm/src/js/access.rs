use beehive_core::access::Access;
use dupe::Dupe;
use wasm_bindgen::prelude::*;

#[wasm_bindgen(js_name = Access)]
#[derive(Debug, Clone, Dupe, Copy)]
pub struct JsAccess(pub(crate) Access);

#[wasm_bindgen(js_class = Access)]
impl JsAccess {
    #[wasm_bindgen(js_name = tryFromString)]
    pub fn try_from_string(s: String) -> Option<JsAccess> {
        match s.as_str() {
            "pull" => Some(JsAccess(Access::Pull)),
            "read" => Some(JsAccess(Access::Read)),
            "write" => Some(JsAccess(Access::Write)),
            "admin" => Some(JsAccess(Access::Admin)),
            _ => None,
        }
    }

    #[wasm_bindgen(js_name = toString)]
    pub fn to_string(&self) -> String {
        self.0.to_string()
    }
}
