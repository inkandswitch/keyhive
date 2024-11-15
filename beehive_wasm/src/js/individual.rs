use super::{agent::JsAgent, individual_id::JsIndividualId, peer::JsPeer};
use beehive_core::principal::individual::Individual;
use derive_more::{From, Into};
use dupe::Dupe;
use std::{cell::RefCell, rc::Rc};
use wasm_bindgen::prelude::*;

#[derive(Debug, Clone, Dupe, PartialEq, Eq, From, Into)]
#[wasm_bindgen(js_name = Individual)]
pub struct JsIndividual(pub(crate) Rc<RefCell<Individual>>);

#[wasm_bindgen(js_class = Individual)]
impl JsIndividual {
    #[wasm_bindgen(constructor)]
    pub fn new(id: JsIndividualId) -> Self {
        Rc::new(RefCell::new(Individual::new(id.0))).into()
    }

    #[wasm_bindgen(js_name = toPeer)]
    pub fn to_peer(&self) -> JsPeer {
        JsPeer(self.0.dupe().into())
    }

    #[wasm_bindgen(js_name = toAgent)]
    pub fn to_agent(&self) -> JsAgent {
        JsAgent(self.0.dupe().into())
    }
}
