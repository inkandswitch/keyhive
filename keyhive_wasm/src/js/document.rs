use super::{
    agent::JsAgent, change_ref::JsChangeRef, event_handler::JsEventHandler,
    identifier::JsIdentifier, peer::JsPeer, signer::JsSigner,
};
use derive_more::{Deref, From, Into};
use dupe::Dupe;
use futures::lock::Mutex;
use keyhive_core::principal::document::Document;
use std::sync::Arc;
use wasm_bindgen::prelude::*;

#[wasm_bindgen(js_name = Document)]
#[derive(Debug, Clone, Dupe, From, Into, Deref)]
pub struct JsDocument(pub(crate) Arc<Mutex<Document<JsSigner, JsChangeRef, JsEventHandler>>>);

#[wasm_bindgen(js_class = Document)]
impl JsDocument {
    #[wasm_bindgen(getter)]
    pub async fn id(&self) -> JsIdentifier {
        let locked = self.0.lock().await;
        JsIdentifier(locked.id())
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
