use super::{agent::JsAgent, change_ref::JsChangeRef, identifier::JsIdentifier, peer::JsPeer};
use beehive_core::principal::document::Document;
use derive_more::{Deref, From, Into};
use dupe::Dupe;
use std::{cell::RefCell, rc::Rc};
use wasm_bindgen::prelude::*;

#[wasm_bindgen(js_name = Document)]
#[derive(Debug, Clone, Dupe, From, Into, Deref)]
pub struct JsDocument(pub(crate) Rc<RefCell<Document<JsChangeRef>>>);

#[wasm_bindgen(js_class = Document)]
impl JsDocument {
    #[wasm_bindgen(getter)]
    pub fn id(&self) -> JsIdentifier {
        JsIdentifier(self.0.borrow().id())
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
