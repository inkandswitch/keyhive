use beehive_core::principal::agent::id::AgentId;
use std::fmt::{Display, Formatter};
use wasm_bindgen::prelude::*;

#[wasm_bindgen(js_name = AgentId)]
#[derive(Debug, Clone, Copy)]
pub struct JsAgentId(pub(crate) AgentId);

#[wasm_bindgen(js_class = AgentId)]
impl JsAgentId {
    #[wasm_bindgen(js_name = toString)]
    pub fn to_js_string(&self) -> String {
        self.0.to_string()
    }
}

impl From<AgentId> for JsAgentId {
    fn from(agent_id: AgentId) -> Self {
        JsAgentId(agent_id)
    }
}

impl From<JsAgentId> for AgentId {
    fn from(js_agent_id: JsAgentId) -> Self {
        js_agent_id.0
    }
}

impl Display for JsAgentId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}
