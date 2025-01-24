use super::{
    change_ref::JsChangeRef, history::JsHistory, identifier::JsIdentifier,
    signed_delegation::JsSignedDelegation,
};
use beehive_core::principal::group::operation::revocation::Revocation;
use derive_more::{From, Into};
use dupe::Dupe;
use wasm_bindgen::prelude::*;

#[wasm_bindgen(js_name = Revocation)]
#[derive(Debug, Clone, From, Into)]
pub struct JsRevocation(pub(crate) Revocation<JsChangeRef>);

#[wasm_bindgen(js_class = Revocation)]
impl JsRevocation {
    #[wasm_bindgen(getter)]
    pub fn subject_id(&self) -> JsIdentifier {
        self.0.subject_id().into()
    }

    #[wasm_bindgen(getter)]
    pub fn revoked(&self) -> JsSignedDelegation {
        self.0.revoked().dupe().into()
    }

    #[wasm_bindgen(getter)]
    pub fn proof(&self) -> Option<JsSignedDelegation> {
        Some(self.0.proof()?.dupe().into())
    }

    #[wasm_bindgen(getter)]
    pub fn after(&self) -> JsHistory {
        self.0.after().into()
    }
}
