use keyhive_core::stats::Stats;
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::wasm_bindgen;

#[wasm_bindgen(js_name = Stats)]
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct JsStats(pub(crate) Stats);
