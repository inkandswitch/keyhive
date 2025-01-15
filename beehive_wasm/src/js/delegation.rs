use super::{
    access::JsAccess, agent::JsAgent, change_ref::JsChangeRef, history::JsHistory,
    signed_delegation::JsSignedDelegation,
};
use beehive_core::principal::group::operation::delegation::{Delegation, DelegationError};
use dupe::Dupe;
use thiserror::Error;
use wasm_bindgen::prelude::*;

#[wasm_bindgen(js_name = Delegation)]
#[derive(Debug, Clone)]
pub struct JsDelegation(pub(crate) Delegation<JsChangeRef>);

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
        Some(self.0.proof()?.dupe().into())
    }

    #[wasm_bindgen(getter)]
    pub fn after(&self) -> JsHistory {
        self.0.after().into()
    }
}

impl From<Delegation<JsChangeRef>> for JsDelegation {
    fn from(delegation: Delegation<JsChangeRef>) -> Self {
        JsDelegation(delegation)
    }
}

impl From<JsDelegation> for Delegation<JsChangeRef> {
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
