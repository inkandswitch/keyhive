use super::identifier::JsIdentifier;
use beehive_core::principal::document::Document;
use dupe::Dupe;
use std::{cell::RefCell, ops::Deref, rc::Rc};
use wasm_bindgen::prelude::*;

#[wasm_bindgen(js_name = Document)]
#[derive(Debug, Clone, Dupe)]
pub struct JsDocument(pub(crate) Rc<RefCell<Document<automerge::ChangeHash>>>);

#[wasm_bindgen(js_class = Document)]
impl JsDocument {
    pub fn id(&self) -> JsIdentifier {
        JsIdentifier(self.0.borrow().id())
    }
}

impl Deref for JsDocument {
    type Target = Rc<RefCell<Document<automerge::ChangeHash>>>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
