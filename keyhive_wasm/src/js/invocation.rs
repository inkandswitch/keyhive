use super::secret_key_store::JsSecretKeyStore;
use super::{change_id::JsChangeId, event_handler::JsEventHandler, signer::JsSigner};
use derive_more::{From, Into};
use future_form::Local;
use keyhive_core::invocation::Invocation;
use wasm_bindgen::prelude::*;

#[derive(Clone, Debug, From, Into)]
#[wasm_bindgen(js_name = Invocation)]
pub struct JsInvocation(
    pub(crate) Invocation<Local, JsSigner, JsSecretKeyStore, JsChangeId, JsEventHandler>,
);
