use wasm_bindgen::prelude::*;

use super::{
    change_ref::JsChangeRef, doc_content_refs::DocContentRefs, document::JsDocument,
    signed_delegation::JsSignedDelegation, signed_revocation::JsSignedRevocation,
};
use beehive_core::{
    crypto::signed::Signed,
    principal::{
        document::{id::DocumentId, Document},
        group::operation::{delegation::Delegation, revocation::Revocation},
    },
};
use dupe::Dupe;
use std::{cell::RefCell, collections::BTreeMap, rc::Rc};

#[wasm_bindgen]
#[derive(Debug, Clone)]
pub struct After {
    pub(crate) delegations: Vec<Rc<Signed<Delegation<JsChangeRef>>>>,
    pub(crate) revocations: Vec<Rc<Signed<Revocation<JsChangeRef>>>>,
    pub(crate) content:
        BTreeMap<DocumentId, (Rc<RefCell<Document<JsChangeRef>>>, Vec<JsChangeRef>)>,
}

#[wasm_bindgen]
impl After {
    pub fn delegations(&self) -> Vec<JsSignedDelegation> {
        self.delegations
            .iter()
            .map(|d| JsSignedDelegation(d.as_ref().clone()))
            .collect()
    }

    pub fn revocations(&self) -> Vec<JsSignedRevocation> {
        self.revocations
            .iter()
            .map(|r| JsSignedRevocation(r.as_ref().clone()))
            .collect()
    }

    #[wasm_bindgen(js_name = contentRefs)]
    pub fn content_refs(&self) -> Vec<DocContentRefs> {
        self.content
            .values()
            .map(|(doc, refs)| DocContentRefs {
                doc: JsDocument(doc.dupe()),
                change_hashes: refs.clone(),
            })
            .collect()
    }
}
