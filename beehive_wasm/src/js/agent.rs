use super::{agent_id::JsAgentId, change_ref::JsChangeRef};
use beehive_core::principal::agent::Agent;
use std::ops::Deref;
use wasm_bindgen::prelude::*;

#[wasm_bindgen(js_name = Agent)]
#[derive(Debug, Clone)]
pub struct JsAgent(pub(crate) Agent<JsChangeRef>);

#[wasm_bindgen(js_class = Agent)]
impl JsAgent {
    #[wasm_bindgen(js_name = agentId)]
    pub fn js_agent_id(&self) -> JsAgentId {
        self.0.agent_id().into()
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

impl From<Agent<JsChangeRef>> for JsAgent {
    fn from(agent: Agent<JsChangeRef>) -> Self {
        JsAgent(agent)
    }
}

impl From<JsAgent> for Agent<JsChangeRef> {
    fn from(agent: JsAgent) -> Self {
        agent.0
    }
}

impl Deref for JsAgent {
    type Target = Agent<JsChangeRef>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
