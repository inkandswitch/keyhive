use super::{change_ref::JsChangeRef, event_handler::JsEventHandler};
use beehive_core::invocation::Invocation;
use derive_more::{From, Into};
use wasm_bindgen::prelude::*;

#[derive(Clone, Debug, From, Into)]
#[wasm_bindgen(js_name = Invocation)]
pub struct JsInvocation(pub(crate) Invocation<JsChangeRef, JsEventHandler>);
