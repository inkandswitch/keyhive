use super::{
    agent::JsAgent, document_id::JsDocumentId, identifier::JsIdentifier,
    individual_id::JsIndividualId, peer::JsPeer, share_key::JsShareKey,
};
use derive_more::{From, Into};
use dupe::Dupe;
use futures::lock::Mutex;
use keyhive_core::principal::individual::Individual;
use std::sync::Arc;
use wasm_bindgen::prelude::*;

#[derive(Debug, Clone, Dupe, PartialEq, Eq, From, Into)]
#[wasm_bindgen(js_name = Individual)]
pub struct JsIndividual(pub(crate) Arc<Mutex<Individual>>);

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
    pub async fn id(&self) -> JsIdentifier {
        let locked = self.0.lock().await;
        JsIdentifier(locked.id().into())
    }

    #[wasm_bindgen(getter, js_name = individualId)]
    pub async fn individual_id(&self) -> JsIndividualId {
        let locked = self.0.lock().await;
        JsIndividualId(locked.id())
    }

    #[wasm_bindgen(js_name = pickPrekey)]
    pub fn pick_prekey(&self, doc_id: JsDocumentId) -> JsShareKey {
        JsShareKey(*self.0.pick_prekey(doc_id.0))
    }
}
