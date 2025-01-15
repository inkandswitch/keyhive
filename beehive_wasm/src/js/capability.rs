use super::{
    access::JsAccess, agent::JsAgent, change_ref::JsChangeRef,
    signed_delegation::JsSignedDelegation,
};
use beehive_core::{
    crypto::signed::Signed,
    principal::{agent::Agent, group::operation::delegation::Delegation},
};
use dupe::Dupe;
use std::rc::Rc;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
#[derive(Debug, Clone, Dupe)]
pub struct Capability {
    pub(crate) who: Agent<JsChangeRef>,
    pub(crate) proof: Rc<Signed<Delegation<JsChangeRef>>>,
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
