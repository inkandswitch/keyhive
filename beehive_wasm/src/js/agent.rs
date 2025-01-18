use super::change_ref::JsChangeRef;
use beehive_core::principal::agent::Agent;
use derive_more::{From, Into};
use std::ops::Deref;
use wasm_bindgen::prelude::*;

#[wasm_bindgen(js_name = Agent)]
#[derive(Debug, Clone, From, Into)]
pub struct JsAgent(pub(crate) Agent<JsChangeRef>);

#[wasm_bindgen(js_class = Agent)]
impl JsAgent {
    #[wasm_bindgen(js_name = toString)]
    pub fn to_string(&self) -> String {
        self.0
            .id()
            .as_slice()
            .iter()
            .fold(String::new(), |mut acc, byte| {
                acc.push_str(&format!("{:#x}", byte));
                acc
            })
    }

    #[wasm_bindgen(js_name = isIndividual)]
    pub fn is_individual(&self) -> bool {
        matches!(self.0, Agent::Individual(_))
    }

    #[wasm_bindgen(js_name = isGroup)]
    pub fn is_group(&self) -> bool {
        matches!(self.0, Agent::Group(_))
    }

    #[wasm_bindgen(js_name = isDocument)]
    pub fn is_document(&self) -> bool {
        matches!(self.0, Agent::Document(_))
    }
}

impl Deref for JsAgent {
    type Target = Agent<JsChangeRef>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
