use super::{
    capability::Capability, document_id::JsDocumentId, identifier::JsIdentifier,
    keyhive::InnerKeyhive, keyline_storage_error::JsKeylineStorageError, membership::Membership,
    membership_list::direct_members, principal::JsPrincipal,
};
use keyhive_core::principal::document::Document;
use wasm_bindgen::prelude::*;

#[wasm_bindgen(js_name = Document)]
#[derive(Debug, Clone)]
pub struct JsDocument(pub(crate) Document<InnerKeyhive>);

#[wasm_bindgen(js_class = Document)]
impl JsDocument {
    #[wasm_bindgen(getter)]
    pub fn id(&self) -> JsIdentifier {
        JsIdentifier(self.0.id())
    }

    #[wasm_bindgen(getter, js_name = docId)]
    pub fn doc_id(&self) -> JsDocumentId {
        JsDocumentId(self.0.doc_id())
    }

    #[wasm_bindgen(js_name = toPrincipal)]
    pub async fn to_principal(&self) -> JsPrincipal {
        JsPrincipal::new(self.0.keyhive().get_principal(self.0.id())).await
    }

    /// The individuals in this keyhive's tree for the document; empty if it
    /// holds no tree for it.
    ///
    /// This is the set to watch when deciding whether a new reader needs a key
    /// rotation. `members()` reports the document's own delegations, which do
    /// not change when a group that already has access gains a member.
    #[wasm_bindgen(js_name = cgkaMembers)]
    pub async fn cgka_members(&self) -> Vec<JsIdentifier> {
        self.0
            .cgka_members()
            .await
            .into_iter()
            .flatten()
            .map(|id| JsIdentifier(id.into()))
            .collect()
    }

    /// Every individual who reaches this document, following groups all the
    /// way down, with the power for each one.
    #[wasm_bindgen(js_name = transitiveMembers)]
    pub async fn transitive_members(&self) -> Result<Vec<Membership>, JsKeylineStorageError> {
        let members = self.0.transitive_members().await?;
        Ok(Membership::individuals(self.0.keyhive(), members).await)
    }

    /// The direct members: each live delegation about this document, at the
    /// best power it gives per member.
    #[wasm_bindgen]
    pub async fn members(&self) -> Result<Vec<Capability>, JsKeylineStorageError> {
        direct_members(self.0.keyhive(), self.0.doc_id().into()).await
    }
}
