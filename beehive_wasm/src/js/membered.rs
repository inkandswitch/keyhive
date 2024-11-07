use beehive_core::principal::membered::Membered;
use wasm_bindgen::prelude::*;

#[wasm_bindgen(js_name = Membered)]
#[derive(Debug, Clone)]
pub struct JsMembered(pub(crate) Membered<automerge::ChangeHash>);
