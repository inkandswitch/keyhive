use super::{
    agent::JsAgent, document_id::JsDocumentId, identifier::JsIdentifier,
    individual_id::JsIndividualId, peer::JsPeer, share_key::JsShareKey,
};
use derive_more::{From, Into};
use dupe::Dupe;
use keyhive_core::principal::individual::Individual;
use std::{cell::RefCell, rc::Rc};
use wasm_bindgen::prelude::*;

#[derive(Debug, Clone, Dupe, PartialEq, Eq, From, Into)]
#[wasm_bindgen(js_name = Individual)]
pub struct JsIndividual(pub(crate) Rc<RefCell<Individual>>);

#[wasm_bindgen(js_class = Individual)]
impl JsIndividual {
    #[wasm_bindgen(js_name = toPeer)]
    pub fn to_peer(&self) -> JsPeer {
        JsPeer(self.0.dupe().into())
    }

    #[wasm_bindgen(js_name = toAgent)]
    pub fn to_agent(&self) -> JsAgent {
        JsAgent(self.0.dupe().into())
    }

    #[wasm_bindgen(getter)]
    pub fn id(&self) -> JsIdentifier {
        JsIdentifier(self.0.borrow().id().into())
    }

    #[wasm_bindgen(getter, js_name = individualId)]
    pub fn individual_id(&self) -> JsIndividualId {
        JsIndividualId(self.0.borrow().id())
    }

    #[wasm_bindgen(js_name = pickPrekey)]
    pub fn pick_prekey(&self, doc_id: JsDocumentId) -> JsShareKey {
        JsShareKey(*self.0.borrow().pick_prekey(doc_id.0))
    }
}
