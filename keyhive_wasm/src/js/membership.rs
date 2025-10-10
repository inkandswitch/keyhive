use super::{
    access::JsAccess, agent::JsAgent, change_id::JsChangeId, event_handler::JsEventHandler,
    signer::JsSigner,
};
use dupe::Dupe;
use keyhive_core::{access::Access, principal::agent::Agent};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
#[derive(Debug, Clone, Dupe)]
pub struct Membership {
    pub(crate) who: Agent<JsSigner, JsChangeId, JsEventHandler>,
    pub(crate) can: Access,
}

#[wasm_bindgen]
impl Membership {
    #[wasm_bindgen(getter)]
    pub fn who(&self) -> JsAgent {
        JsAgent(self.who.dupe())
    }

    #[wasm_bindgen(getter)]
    pub fn can(&self) -> JsAccess {
        JsAccess(self.can.dupe())
    }
}
