use derive_more::{Deref, Display, From, Into};
use dupe::Dupe;
use keyhive_core::access::Access;
use std::cmp::Ordering;
use wasm_bindgen::prelude::*;

#[wasm_bindgen(js_name = Access)]
#[derive(Debug, Clone, Dupe, Copy, Deref, Display, From, Into)]
pub struct JsAccess(pub(crate) Access);

#[wasm_bindgen(js_class = Access)]
impl JsAccess {
    /// The ability to retrieve bytes over the network.
    pub fn relay() -> JsAccess {
        JsAccess(Access::Relay)
    }

    /// The ability to read (decrypt) the content of a document.
    pub fn read() -> JsAccess {
        JsAccess(Access::Read)
    }

    /// The ability to edit (append ops to) the content of a document.
    pub fn edit() -> JsAccess {
        JsAccess(Access::Edit)
    }

    /// The ability to revoke any members of a group, not just those that they have causal seniority over.
    pub fn admin() -> JsAccess {
        JsAccess(Access::Admin)
    }

    /// Parse an access level, throwing on invalid input.
    /// Accepts "relay", "read", "edit", or "admin" (case-insensitive).
    #[wasm_bindgen(js_name = fromString)]
    pub fn from_string(s: String) -> Result<JsAccess, JsError> {
        JsAccess::try_from_string(s.clone()).ok_or_else(|| {
            JsError::new(&format!(
                "invalid access level {s:?}: expected \"relay\", \"read\", \"edit\", or \"admin\""
            ))
        })
    }

    /// Parse an access level, returning undefined on invalid input.
    /// Prefer `fromString`, which throws a descriptive error instead.
    #[wasm_bindgen(js_name = tryFromString)]
    pub fn try_from_string(s: String) -> Option<JsAccess> {
        match s.to_lowercase().as_str() {
            "relay" => Some(JsAccess(Access::Relay)),
            "read" => Some(JsAccess(Access::Read)),
            "edit" => Some(JsAccess(Access::Edit)),
            "admin" => Some(JsAccess(Access::Admin)),
            _ => None,
        }
    }

    /// Numeric level for ordering: Relay = 0, Read = 1, Edit = 2, Admin = 3.
    /// Higher levels imply all lower levels.
    #[wasm_bindgen(getter)]
    pub fn level(&self) -> u8 {
        match self.0 {
            Access::Relay => 0,
            Access::Read => 1,
            Access::Edit => 2,
            Access::Admin => 3,
        }
    }

    /// Standard comparator result: -1 if less permissive than `other`,
    /// 0 if equal, 1 if more permissive.
    #[wasm_bindgen(js_name = compareTo)]
    pub fn compare_to(&self, other: &JsAccess) -> i8 {
        match self.0.cmp(&other.0) {
            Ordering::Less => -1,
            Ordering::Equal => 0,
            Ordering::Greater => 1,
        }
    }

    /// True if this level is at least as permissive as `other`.
    #[wasm_bindgen(js_name = atLeast)]
    pub fn at_least(&self, other: &JsAccess) -> bool {
        self.0 >= other.0
    }

    #[wasm_bindgen(js_name = equals)]
    pub fn equals(&self, other: &JsAccess) -> bool {
        self.0 == other.0
    }

    /// True for Read access or higher.
    #[wasm_bindgen(getter, js_name = isReader)]
    pub fn is_reader(&self) -> bool {
        self.0.is_reader()
    }

    /// True for Edit access or higher.
    #[wasm_bindgen(getter, js_name = isEditor)]
    pub fn is_editor(&self) -> bool {
        self.0.is_editor()
    }

    #[wasm_bindgen(js_name = toString)]
    pub fn to_js_string(&self) -> String {
        self.to_string()
    }
}
