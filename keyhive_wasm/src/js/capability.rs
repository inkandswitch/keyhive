use super::{
    access::JsAccess, agent::JsAgent, change_id::JsChangeId, event_handler::JsEventHandler,
    signed_delegation::JsSignedDelegation, signer::JsSigner,
};
use dupe::Dupe;
use keyhive_core::principal::{agent::Agent, group::delegation::Delegation};
use keyhive_crypto::signed::Signed;
use future_form::Local;
use std::sync::Arc;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
#[derive(Debug, Clone, Dupe)]
pub struct Capability {
    pub(crate) who: Agent<Local, JsSigner, JsChangeId, JsEventHandler>,
    pub(crate) proof: Arc<Signed<Delegation<Local, JsSigner, JsChangeId, JsEventHandler>>>,
}

#[wasm_bindgen]
impl Capability {
    #[wasm_bindgen(getter)]
    pub fn who(&self) -> JsAgent {
        JsAgent(self.who.dupe())
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
