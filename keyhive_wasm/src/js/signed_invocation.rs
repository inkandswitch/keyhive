use super::{change_ref::JsChangeRef, event_handler::JsEventHandler};
use derive_more::{From, Into};
use keyhive_core::{crypto::signed::Signed, invocation::Invocation};
use wasm_bindgen::prelude::*;

#[derive(Debug, Clone, From, Into)]
#[wasm_bindgen(js_name = SignedInvocation)]
pub struct JsSignedInvocation(
    pub(crate) Signed<Invocation<JsChangeRef, JsEventHandler, JsChangeRef>>,
);
