use super::{change_id::JsChangeId, document_id::JsDocumentId, identifier::JsIdentifier};
use keyhive_core::content::heads::ContentHeads;
use keyhive_crypto::id::Id;
use keyline::revocation::Revocation;
use wasm_bindgen::prelude::*;

/// A Keyline revocation: `issuer` withdraws the delegation `revoked` names.
#[wasm_bindgen(js_name = Revocation)]
#[derive(Debug, Clone)]
pub struct JsRevocation {
    pub(crate) issuer: Id,
    pub(crate) revocation: Revocation<ContentHeads<JsChangeId>>,
}

#[wasm_bindgen(js_class = Revocation)]
impl JsRevocation {
    #[wasm_bindgen(getter)]
    pub fn issuer(&self) -> JsIdentifier {
        JsIdentifier(self.issuer.into())
    }

    /// The digest of the delegation revoked.
    #[wasm_bindgen(getter)]
    pub fn revoked(&self) -> Vec<u8> {
        self.revocation.revoke.as_slice().to_vec()
    }

    /// The content heads of `doc` the issuer had seen when revoking, if the
    /// revocation records them: content from the revoked member that does not
    /// causally precede them came after the revocation.
    pub fn retained(&self, doc: &JsDocumentId) -> Option<Vec<JsChangeId>> {
        let doc = Id::try_from(doc.0).ok()?;
        self.revocation
            .retain
            .get(&doc)
            .map(|heads| heads.as_slice().to_vec())
    }
}
