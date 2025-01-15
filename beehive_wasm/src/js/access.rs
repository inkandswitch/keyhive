use beehive_core::access::Access;
use dupe::Dupe;
use std::{
    fmt::{self, Display, Formatter},
    ops::Deref,
};
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
    pub fn to_js_string(&self) -> String {
        self.to_string()
    }
}

impl From<JsAccess> for Access {
    fn from(js_access: JsAccess) -> Self {
        js_access.0
    }
}

impl From<Access> for JsAccess {
    fn from(access: Access) -> Self {
        JsAccess(access)
    }
}

impl Deref for JsAccess {
    type Target = Access;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Display for JsAccess {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}
