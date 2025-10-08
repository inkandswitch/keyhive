use super::{
    change_ref::JsChangeRef, doc_content_refs::DocContentRefs, document_id::JsDocumentId,
    event_handler::JsEventHandler, signed_delegation::JsSignedDelegation,
    signed_revocation::JsSignedRevocation, signer::JsSigner,
};
use dupe::Dupe;
use futures::lock::Mutex;
use keyhive_core::{
    crypto::signed::Signed,
    principal::{
        document::id::DocumentId,
        group::{delegation::Delegation, dependencies::Dependencies, revocation::Revocation},
    },
};
use std::{collections::BTreeMap, sync::Arc};
use wasm_bindgen::prelude::*;

#[wasm_bindgen(js_name = History)]
#[derive(Debug, Clone)]
pub struct JsHistory {
    pub(crate) delegations: Vec<Arc<Signed<Delegation<JsSigner, JsChangeRef, JsEventHandler>>>>,
    pub(crate) revocations: Vec<Arc<Signed<Revocation<JsSigner, JsChangeRef, JsEventHandler>>>>,
    pub(crate) content: BTreeMap<DocumentId, Vec<JsChangeRef>>,
}

#[wasm_bindgen(js_class = History)]
impl JsHistory {
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
                change_hashes: Arc::new(Mutex::new(refs.clone())),
            })
            .collect()
    }
}

impl From<Dependencies<'_, JsSigner, JsChangeRef, JsEventHandler>> for JsHistory {
    fn from(deps: Dependencies<JsSigner, JsChangeRef, JsEventHandler>) -> Self {
        Self {
            delegations: deps.delegations,
            revocations: deps.revocations,
            content: deps.content.clone(),
        }
    }
}
