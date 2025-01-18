use super::{
    access::JsAccess, after::After, agent::JsAgent, change_ref::JsChangeRef,
    signed_delegation::JsSignedDelegation,
};
use beehive_core::principal::group::operation::delegation::{Delegation, DelegationError};
use derive_more::{From, Into};
use dupe::Dupe;
use thiserror::Error;
use wasm_bindgen::prelude::*;

#[wasm_bindgen(js_name = Delegation)]
#[derive(Debug, Clone, From, Into)]
pub struct JsDelegation(Delegation<JsChangeRef>);

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
    pub fn after(&self) -> After {
        let (delegations, revocations, cs) = self.0.after();
        After {
            delegations,
            revocations,
            content: cs.clone(),
        }
    }
}

#[wasm_bindgen(js_name = DelegationError)]
#[derive(Debug, Error, From, Into)]
#[error(transparent)]
pub struct JsDelegationError(DelegationError);

#[wasm_bindgen(js_class = DelegationError)]
impl JsDelegationError {
    pub fn message(&self) -> String {
        self.0.to_string()
    }
}
