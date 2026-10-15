use derive_more::{Deref, Display, From, Into};
use keyline::power::Power;
use std::cmp::Ordering;
use wasm_bindgen::prelude::*;

#[wasm_bindgen(js_name = Power)]
#[derive(Debug, Clone, Copy, Deref, Display, From, Into)]
pub struct JsPower(pub(crate) Power);

#[wasm_bindgen(js_class = Power)]
impl JsPower {
    /// The ability to retrieve bytes over the network.
    pub fn relay() -> JsPower {
        JsPower(Power::Relay)
    }

    /// The ability to read (decrypt) the content of a document.
    pub fn read() -> JsPower {
        JsPower(Power::Read)
    }

    /// The ability to edit (append ops to) the content of a document.
    pub fn edit() -> JsPower {
        JsPower(Power::Edit)
    }

    /// Authority over the graph: revoke any delegation on a route through this
    /// group or document, and so manage its members.
    pub fn admin() -> JsPower {
        JsPower(Power::Admin)
    }

    /// Parse a power level, throwing on invalid input.
    /// Accepts "relay", "read", "edit", or "admin" (case-insensitive).
    #[wasm_bindgen(js_name = fromString)]
    pub fn from_string(s: String) -> Result<JsPower, JsError> {
        JsPower::try_from_string(s.clone()).ok_or_else(|| {
            JsError::new(&format!(
                "invalid power level {s:?}: expected \"relay\", \"read\", \"edit\", or \"admin\""
            ))
        })
    }

    /// Parse a power level, returning undefined on invalid input.
    /// Prefer `fromString`, which throws a descriptive error instead.
    #[wasm_bindgen(js_name = tryFromString)]
    pub fn try_from_string(s: String) -> Option<JsPower> {
        match s.to_lowercase().as_str() {
            "relay" => Some(JsPower(Power::Relay)),
            "read" => Some(JsPower(Power::Read)),
            "edit" => Some(JsPower(Power::Edit)),
            "admin" => Some(JsPower(Power::Admin)),
            _ => None,
        }
    }

    /// Numeric level for ordering: Relay = 0, Read = 1, Edit = 2, Admin = 3.
    /// Higher levels imply all lower levels.
    #[wasm_bindgen(getter)]
    pub fn level(&self) -> u8 {
        match self.0 {
            Power::Relay => 0,
            Power::Read => 1,
            Power::Edit => 2,
            Power::Admin => 3,
        }
    }

    /// Standard comparator result: -1 if less permissive than `other`,
    /// 0 if equal, 1 if more permissive.
    #[wasm_bindgen(js_name = compareTo)]
    pub fn compare_to(&self, other: &JsPower) -> i8 {
        match self.0.cmp(&other.0) {
            Ordering::Less => -1,
            Ordering::Equal => 0,
            Ordering::Greater => 1,
        }
    }

    /// True if this level is at least as permissive as `other`.
    #[wasm_bindgen(js_name = atLeast)]
    pub fn at_least(&self, other: &JsPower) -> bool {
        self.0 >= other.0
    }

    #[wasm_bindgen(js_name = equals)]
    pub fn equals(&self, other: &JsPower) -> bool {
        self.0 == other.0
    }

    /// True for Read power or higher.
    #[wasm_bindgen(getter, js_name = isReader)]
    pub fn is_reader(&self) -> bool {
        self.0.is_reader()
    }

    /// True for Edit power or higher.
    #[wasm_bindgen(getter, js_name = isEditor)]
    pub fn is_editor(&self) -> bool {
        self.0.is_editor()
    }

    #[wasm_bindgen(js_name = toString)]
    pub fn to_js_string(&self) -> String {
        self.to_string()
    }
}
