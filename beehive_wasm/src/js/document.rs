use super::{change_ref::JsChangeRef, identifier::JsIdentifier};
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
}
