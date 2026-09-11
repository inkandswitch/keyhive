use super::{document_id::JsDocumentId, group_id::JsGroupId};
use crate::js::identifier::JsIdentifier;
use keyhive_core::principal::{identifier::Identifier, membered::id::MemberedId};
use std::fmt::{Display, Formatter};
use wasm_bindgen::prelude::*;

/// ID for a resource that can have members, which is either a group or a document.
#[wasm_bindgen(js_name = MemberedId)]
#[derive(Debug, Clone, Copy)]
pub struct JsMemberedId(pub(crate) MemberedId);

#[wasm_bindgen(js_class = MemberedId)]
impl JsMemberedId {
    #[wasm_bindgen(js_name = group)]
    pub fn group(group_id: &JsGroupId) -> Self {
        JsMemberedId(MemberedId::GroupId(group_id.0))
    }

    #[wasm_bindgen(js_name = document)]
    pub fn document(doc_id: &JsDocumentId) -> Self {
        JsMemberedId(MemberedId::DocumentId(doc_id.0))
    }

    #[wasm_bindgen(js_name = isGroup)]
    pub fn is_group(&self) -> bool {
        matches!(self.0, MemberedId::GroupId(_))
    }

    #[wasm_bindgen(js_name = isDocument)]
    pub fn is_document(&self) -> bool {
        matches!(self.0, MemberedId::DocumentId(_))
    }

    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes().to_vec()
    }

    #[wasm_bindgen(js_name = toString)]
    pub fn to_js_string(&self) -> String {
        self.0.to_string()
    }

    #[wasm_bindgen(js_name = toIdentifier)]
    pub fn to_identifier(&self) -> JsIdentifier {
        JsIdentifier(Identifier::from(self.0))
    }
}

impl From<MemberedId> for JsMemberedId {
    fn from(id: MemberedId) -> Self {
        JsMemberedId(id)
    }
}

impl Display for JsMemberedId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}
