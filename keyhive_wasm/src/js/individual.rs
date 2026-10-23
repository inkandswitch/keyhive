use super::{
    document_id::JsDocumentId, identifier::JsIdentifier, individual_id::JsIndividualId,
    keyhive::InnerKeyhive, principal::JsPrincipal, share_key::JsShareKey,
};
use keyhive_core::principal::individual::Individual;
use wasm_bindgen::prelude::*;

#[wasm_bindgen(js_name = Individual)]
#[derive(Debug, Clone)]
pub struct JsIndividual(pub(crate) Individual<InnerKeyhive>);

#[wasm_bindgen(js_class = Individual)]
impl JsIndividual {
    #[wasm_bindgen(js_name = toPrincipal)]
    pub async fn to_principal(&self) -> JsPrincipal {
        JsPrincipal::new(self.0.keyhive().get_principal(self.0.id())).await
    }

    #[wasm_bindgen(getter)]
    pub fn id(&self) -> JsIdentifier {
        JsIdentifier(self.0.id())
    }

    #[wasm_bindgen(getter, js_name = individualId)]
    pub fn individual_id(&self) -> JsIndividualId {
        JsIndividualId(self.0.individual_id())
    }

    /// Pick a prekey for this individual for `doc_id`, or `undefined` if it
    /// has no live prekeys.
    #[wasm_bindgen(js_name = pickPrekey)]
    pub async fn pick_prekey(&self, doc_id: &JsDocumentId) -> Option<JsShareKey> {
        self.0.pick_prekey(doc_id.0).await.map(JsShareKey)
    }
}
