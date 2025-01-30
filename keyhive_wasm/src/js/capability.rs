use super::{
    access::JsAccess, agent::JsAgent, change_ref::JsChangeRef, event_handler::JsEventHandler,
    signed_delegation::JsSignedDelegation,
};
use dupe::Dupe;
use keyhive_core::{
    crypto::signed::Signed,
    principal::{agent::Agent, group::delegation::Delegation},
};
use std::rc::Rc;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
#[derive(Debug, Clone, Dupe)]
pub struct Capability {
    pub(crate) who: Agent<JsChangeRef, JsEventHandler>,
    pub(crate) proof: Rc<Signed<Delegation<JsChangeRef, JsEventHandler>>>,
}

#[wasm_bindgen]
impl Capability {
    #[wasm_bindgen(getter)]
    pub fn who(&self) -> JsAgent {
        JsAgent(self.who.clone())
    }

    #[wasm_bindgen(getter)]
    pub fn can(&self) -> JsAccess {
        JsAccess(self.proof.payload().can())
    }

    #[wasm_bindgen(getter)]
    pub fn proof(&self) -> JsSignedDelegation {
        self.proof.dupe().into()
    }
}
