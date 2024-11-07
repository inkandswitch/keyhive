use beehive_core::principal::agent::Agent;
use wasm_bindgen::prelude::*;

#[wasm_bindgen(js_name = Agent)]
#[derive(Debug, Clone)]
pub struct JsAgent(pub(crate) Agent<automerge::ChangeHash>);

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
        match self.0 {
            Agent::Individual(_) => true,
            _ => false,
        }
    }

    #[wasm_bindgen(js_name = isGroup)]
    pub fn is_group(&self) -> bool {
        match self.0 {
            Agent::Group(_) => true,
            _ => false,
        }
    }

    #[wasm_bindgen(js_name = isDocument)]
    pub fn is_document(&self) -> bool {
        match self.0 {
            Agent::Document(_) => true,
            _ => false,
        }
    }
}
