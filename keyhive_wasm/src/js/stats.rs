use keyhive_core::stats::Stats;
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::wasm_bindgen;

#[wasm_bindgen(js_name = Stats)]
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct JsStats(pub(crate) Stats);

#[wasm_bindgen(js_class = Stats)]
impl JsStats {
    #[wasm_bindgen(getter)]
    pub fn individuals(&self) -> u64 {
        self.0.individuals
    }

    #[wasm_bindgen(getter)]
    pub fn groups(&self) -> u64 {
        self.0.groups
    }

    #[wasm_bindgen(getter)]
    pub fn docs(&self) -> u64 {
        self.0.docs
    }

    #[wasm_bindgen(getter)]
    pub fn delegations(&self) -> u64 {
        self.0.delegations
    }

    #[wasm_bindgen(getter)]
    pub fn revocations(&self) -> u64 {
        self.0.revocations
    }

    #[wasm_bindgen(js_name = toString)]
    pub fn to_string(&self) -> String {
        format!(
            "Stats {{ individuals: {}, groups: {}, docs: {}, delegations: {}, revocations: {} }}",
            self.0.individuals, self.0.groups, self.0.docs, self.0.delegations, self.0.revocations
        )
    }
}
