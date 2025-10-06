use crate::js::{document_id::JsDocumentId, membered::JsMembered};

use super::{
    agent::JsAgent, change_ref::JsChangeRef, event_handler::JsEventHandler,
    identifier::JsIdentifier, peer::JsPeer, signer::JsSigner,
};
use derive_more::{Deref, From, Into};
use dupe::Dupe;
use keyhive_core::principal::document::Document;
use std::{cell::RefCell, rc::Rc};
use wasm_bindgen::prelude::*;

#[wasm_bindgen(js_name = Document)]
#[derive(Debug, Clone, Dupe, From, Into, Deref)]
pub struct JsDocument(pub(crate) Rc<RefCell<Document<JsSigner, JsChangeRef, JsEventHandler>>>);

#[wasm_bindgen(js_class = Document)]
impl JsDocument {
    #[wasm_bindgen(getter)]
    pub fn id(&self) -> JsIdentifier {
        JsIdentifier(self.0.borrow().id())
    }

    #[wasm_bindgen(getter)]
    pub fn doc_id(&self) -> JsDocumentId {
        JsDocumentId(self.0.borrow().doc_id())
    }

    #[wasm_bindgen(js_name = toPeer)]
    pub fn to_peer(&self) -> JsPeer {
        JsPeer(self.0.dupe().into())
    }

    #[wasm_bindgen(js_name = toAgent)]
    pub fn to_agent(&self) -> JsAgent {
        tracing::debug!("JsDocument::to_agent");
        JsAgent(self.0.dupe().into())
    }

    #[wasm_bindgen(js_name = toMembered)]
    pub fn to_membered(&self) -> JsMembered {
        JsMembered(self.0.dupe().into())
    }
}
