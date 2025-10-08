use super::{
    agent::JsAgent, document_id::JsDocumentId, identifier::JsIdentifier,
    individual_id::JsIndividualId, peer::JsPeer, share_key::JsShareKey,
};
use dupe::Dupe;
use futures::lock::Mutex;
use keyhive_core::principal::{
    agent::Agent,
    individual::{id::IndividualId, Individual},
    peer::Peer,
};
use std::sync::Arc;
use wasm_bindgen::prelude::*;

#[derive(Debug, Clone, Dupe)]
#[wasm_bindgen(js_name = Individual)]
pub struct JsIndividual {
    pub(crate) id: IndividualId,
    pub(crate) inner: Arc<Mutex<Individual>>,
}

#[wasm_bindgen(js_class = Individual)]
impl JsIndividual {
    #[wasm_bindgen(getter)]
    pub fn id(&self) -> JsIdentifier {
        JsIdentifier(self.id.into())
    }

    #[wasm_bindgen(getter, js_name = individualId)]
    pub async fn individual_id(&self) -> JsIndividualId {
        JsIndividualId(self.id)
    }

    #[wasm_bindgen(js_name = toPeer)]
    pub fn to_peer(&self) -> JsPeer {
        JsPeer(Peer::Individual(self.id, self.inner.dupe()))
    }

    #[wasm_bindgen(js_name = toAgent)]
    pub fn to_agent(&self) -> JsAgent {
        JsAgent(Agent::Individual(self.id, self.inner.dupe()))
    }

    #[wasm_bindgen(js_name = pickPrekey)]
    pub async fn pick_prekey(&self, doc_id: JsDocumentId) -> JsShareKey {
        let locked = self.inner.lock().await;
        JsShareKey(*locked.pick_prekey(doc_id.0))
    }
}
