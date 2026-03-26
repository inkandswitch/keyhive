use super::{change_id::JsChangeId, event_handler::JsEventHandler, signer::JsSigner};
use future_form::Local;
use keyhive_core::principal::membered::Membered;
use wasm_bindgen::prelude::*;

#[wasm_bindgen(js_name = Membered)]
#[derive(Debug, Clone)]
pub struct JsMembered(pub(crate) Membered<Local, JsSigner, JsChangeId, JsEventHandler>);
