use super::{change_id::JsChangeId, event_handler::JsEventHandler, signer::JsSigner};
use derive_more::{From, Into};
use future_form::Local;
use keyhive_core::invocation::Invocation;
use keyhive_crypto::signed::Signed;
use wasm_bindgen::prelude::*;

#[derive(Debug, Clone, From, Into)]
#[wasm_bindgen(js_name = SignedInvocation)]
pub struct JsSignedInvocation(
    pub(crate) Signed<Invocation<Local, JsSigner, JsChangeId, JsEventHandler, JsChangeId>>,
);
