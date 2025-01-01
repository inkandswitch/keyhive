use super::{
    access::JsAccess, after::After, agent::JsAgent, change_ref::JsChangeRef,
    signed_delegation::JsSignedDelegation, signer::JsSigner,
};
use beehive_core::principal::group::operation::delegation::{Delegation, DelegationError};
use dupe::Dupe;
use std::rc::Rc;
use thiserror::Error;
use wasm_bindgen::prelude::*;

#[wasm_bindgen(js_name = Delegation)]
#[derive(Debug, Clone)]
pub struct JsDelegation(pub(crate) Delegation<JsChangeRef, JsSigner>);

#[wasm_bindgen(js_class = Delegation)]
impl JsDelegation {
    #[wasm_bindgen(getter)]
    pub fn delegate(&self) -> JsAgent {
        self.0.delegate().dupe().into()
    }

    #[wasm_bindgen(getter)]
    pub fn can(&self) -> JsAccess {
        self.0.can().into()
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

impl From<Delegation<JsChangeRef, JsSigner>> for JsDelegation {
    fn from(delegation: Delegation<JsChangeRef, JsSigner>) -> Self {
        JsDelegation(delegation)
    }
}

impl From<JsDelegation> for Delegation<JsChangeRef, JsSigner> {
    fn from(delegation: JsDelegation) -> Self {
        delegation.0
    }
}

#[wasm_bindgen(js_name = DelegationError)]
#[derive(Debug, Error)]
#[error(transparent)]
pub struct JsDelegationError(DelegationError);

#[wasm_bindgen(js_class = DelegationError)]
impl JsDelegationError {
    pub fn message(&self) -> String {
        self.0.to_string()
    }
}

impl From<DelegationError> for JsDelegationError {
    fn from(error: DelegationError) -> Self {
        JsDelegationError(error)
    }
}
