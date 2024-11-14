use beehive_core::principal::group::operation::delegation::DelegationError;
use thiserror::Error;
use wasm_bindgen::prelude::*;

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
