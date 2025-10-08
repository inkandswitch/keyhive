use crate::js::{document_id::JsDocumentId, membered::JsMembered};

use super::{
    agent::JsAgent, change_ref::JsChangeRef, event_handler::JsEventHandler,
    identifier::JsIdentifier, peer::JsPeer, signer::JsSigner,
};
use dupe::Dupe;
use futures::lock::Mutex;
use keyhive_core::principal::{
    agent::Agent,
    document::{id::DocumentId, Document},
    membered::Membered,
    peer::Peer,
};
use std::sync::Arc;
use wasm_bindgen::prelude::*;

#[wasm_bindgen(js_name = Document)]
#[derive(Debug, Clone, Dupe)]
pub struct JsDocument {
    pub(crate) doc_id: DocumentId,
    pub(crate) inner: Arc<Mutex<Document<JsSigner, JsChangeRef, JsEventHandler>>>,
}

#[wasm_bindgen(js_class = Document)]
impl JsDocument {
    #[wasm_bindgen(getter)]
    pub fn id(&self) -> JsIdentifier {
        JsIdentifier(self.doc_id.into())
    }

    #[wasm_bindgen(getter)]
    pub fn doc_id(&self) -> JsDocumentId {
        JsDocumentId(self.doc_id)
    }

    #[wasm_bindgen(js_name = toPeer)]
    pub fn to_peer(&self) -> JsPeer {
        JsPeer(Peer::Document(self.doc_id, self.inner.dupe()))
    }

    #[wasm_bindgen(js_name = toAgent)]
    pub fn to_agent(&self) -> JsAgent {
        tracing::debug!("JsDocument::to_agent");
        JsAgent(Agent::Document(self.doc_id, self.inner.dupe()))
    }

    #[wasm_bindgen(js_name = toMembered)]
    pub fn to_membered(&self) -> JsMembered {
        JsMembered(Membered::Document(self.doc_id, self.inner.dupe()))
    }
}
