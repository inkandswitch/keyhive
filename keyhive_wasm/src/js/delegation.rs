use super::{
    access::JsAccess, agent::JsAgent, change_id::JsChangeId, event_handler::JsEventHandler,
    history::JsHistory, signed_delegation::JsSignedDelegation, signer::JsSigner,
};
use derive_more::{From, Into};
use dupe::Dupe;
use keyhive_core::principal::group::delegation::{Delegation, DelegationError};
use thiserror::Error;
use wasm_bindgen::prelude::*;

#[wasm_bindgen(js_name = Delegation)]
#[derive(Debug, Clone, From, Into)]
pub struct JsDelegation(pub(crate) Delegation<JsSigner, JsChangeId, JsEventHandler>);

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

#[derive(Debug, Error)]
#[error(transparent)]
pub struct JsDelegationError(#[from] DelegationError);

impl From<JsDelegationError> for JsValue {
    fn from(err: JsDelegationError) -> Self {
        let err = js_sys::Error::new(&err.to_string());
        err.set_name("DelegationError");
        err.into()
    }
}
