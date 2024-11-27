use super::{
    after::After, change_ref::JsChangeRef, identifier::JsIdentifier,
    signed_delegation::JsSignedDelegation,
};
use beehive_core::principal::group::operation::revocation::Revocation;
use dupe::Dupe;
use std::rc::Rc;
use wasm_bindgen::prelude::*;

#[wasm_bindgen(js_name = Revocation)]
#[derive(Debug, Clone)]
pub struct JsRevocation(pub(crate) Revocation<JsChangeRef>);

#[wasm_bindgen(js_class = Revocation)]
impl JsRevocation {
    #[wasm_bindgen(getter)]
    pub fn subject(&self) -> JsIdentifier {
        self.0.subject().into()
    }

    #[wasm_bindgen(getter)]
    pub fn revoked(&self) -> JsSignedDelegation {
        self.0.revoked().as_ref().clone().into()
    }

    #[wasm_bindgen(getter)]
    pub fn proof(&self) -> Option<JsSignedDelegation> {
        let rc = self.0.proof()?;
        Some(Rc::unwrap_or_clone(rc.dupe()).into())
    }

    #[wasm_bindgen(getter)]
    pub fn after(&self) -> After {
        let (delegations, revocations, cs) = self.0.after();
        After {
            delegations,
            revocations,
            content: cs.clone(),
        }
    }
}

impl From<Revocation<JsChangeRef>> for JsRevocation {
    fn from(delegation: Revocation<JsChangeRef>) -> Self {
        JsRevocation(delegation)
    }
}

impl From<JsRevocation> for Revocation<JsChangeRef> {
    fn from(delegation: JsRevocation) -> Self {
        delegation.0
    }
}
