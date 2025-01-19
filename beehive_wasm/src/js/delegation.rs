use super::{
    access::JsAccess, agent::JsAgent, change_ref::JsChangeRef, history::JsHistory,
    signed_delegation::JsSignedDelegation,
};
use beehive_core::principal::group::operation::delegation::{Delegation, DelegationError};
use derive_more::{From, Into};
use dupe::Dupe;
use thiserror::Error;
use wasm_bindgen::prelude::*;

#[wasm_bindgen(js_name = Delegation)]
#[derive(Debug, Clone, From, Into)]
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

#[wasm_bindgen(js_name = DelegationError)]
#[derive(Debug, Error, From, Into)]
#[error(transparent)]
pub struct JsDelegationError(DelegationError);
