use super::{change_ref::JsChangeRef, event_handler::JsEventHandler};
use beehive_core::{crypto::signed::Signed, invocation::Invocation};
use derive_more::{From, Into};
use wasm_bindgen::prelude::*;

#[derive(Debug, Clone, From, Into)]
#[wasm_bindgen(js_name = SignedInvocation)]
pub struct JsSignedInvocation(
    pub(crate) Signed<Invocation<JsChangeRef, JsEventHandler, JsChangeRef>>,
);
