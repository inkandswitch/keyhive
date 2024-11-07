use super::{access::JsAccess, agent::JsAgent};
use beehive_core::{
    crypto::signed::Signed,
    principal::{
        agent::Agent,
        group::{operation::delegation::Delegation, Group},
    },
};
use dupe::Dupe;
use std::{cell::RefCell, rc::Rc};
use wasm_bindgen::prelude::*;

#[wasm_bindgen(js_name = Group)]
#[derive(Debug, Clone, Dupe)]
pub struct JsGroup(pub(crate) Rc<RefCell<Group<automerge::ChangeHash>>>);

#[wasm_bindgen(js_class = Group)]
impl JsGroup {
    pub fn members(&self) -> Vec<Capability> {
        self.0
            .borrow()
            .members()
            .iter()
            .map(|(_agent_id, dlgs)| {
                let best = dlgs
                    .iter()
                    .max_by_key(|dlg| dlg.payload().can())
                    .expect("should have at least one member");

                Capability {
                    who: dlgs.iter().next().unwrap().payload().delegate().clone(),
                    proof: best.clone(),
                }
            })
            .collect()
    }
}

#[wasm_bindgen]
#[derive(Debug, Clone, Dupe)]
pub struct Capability {
    who: Agent<automerge::ChangeHash>,
    proof: Rc<Signed<Delegation<automerge::ChangeHash>>>,
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
    pub fn proof(&self) -> JsAccess {
        todo!()
    }
}
