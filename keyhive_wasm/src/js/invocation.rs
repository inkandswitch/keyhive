use super::{change_ref::JsChangeRef, event_handler::JsEventHandler};
use derive_more::{From, Into};
use keyhive_core::invocation::Invocation;
use wasm_bindgen::prelude::*;

#[derive(Clone, Debug, From, Into)]
#[wasm_bindgen(js_name = Invocation)]
pub struct JsInvocation(pub(crate) Invocation<JsChangeRef, JsEventHandler>);
