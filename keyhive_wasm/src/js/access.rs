use derive_more::{Deref, Display, From, Into};
use dupe::Dupe;
use keyhive_core::access::Access;
use wasm_bindgen::prelude::*;

#[wasm_bindgen(js_name = Access)]
#[derive(Debug, Clone, Dupe, Copy, Deref, Display, From, Into)]
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
    pub fn to_js_string(&self) -> String {
        self.to_string()
    }
}
