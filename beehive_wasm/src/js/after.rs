use super::{
    change_ref::JsChangeRef, doc_content_refs::DocContentRefs, document_id::JsDocumentId,
    signed_delegation::JsSignedDelegation, signed_revocation::JsSignedRevocation,
};
use beehive_core::{
    crypto::signed::Signed,
    principal::{
        document::id::DocumentId,
        group::operation::{delegation::Delegation, revocation::Revocation},
    },
};
use dupe::Dupe;
use std::{collections::BTreeMap, rc::Rc};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
#[derive(Debug, Clone)]
pub struct After {
    pub(crate) delegations: Vec<Rc<Signed<Delegation<JsChangeRef>>>>,
    pub(crate) revocations: Vec<Rc<Signed<Revocation<JsChangeRef>>>>,
    pub(crate) content: BTreeMap<DocumentId, Vec<JsChangeRef>>,
}

#[wasm_bindgen]
impl After {
    pub fn delegations(&self) -> Vec<JsSignedDelegation> {
        self.delegations
            .iter()
            .map(|d| JsSignedDelegation(d.dupe()))
            .collect()
    }

    pub fn revocations(&self) -> Vec<JsSignedRevocation> {
        self.revocations
            .iter()
            .map(|r| JsSignedRevocation(r.dupe()))
            .collect()
    }

    #[wasm_bindgen(js_name = contentRefs)]
    pub fn content_refs(&self) -> Vec<DocContentRefs> {
        self.content
            .iter()
            .map(|(doc_id, refs)| DocContentRefs {
                doc_id: JsDocumentId(*doc_id),
                change_hashes: refs.clone(),
            })
            .collect()
    }
}
