use super::{change_ref::JsChangeRef, event_handler::JsEventHandler, signer::JsSigner};
use keyhive_core::principal::membered::Membered;
use wasm_bindgen::prelude::*;

#[wasm_bindgen(js_name = Membered)]
#[derive(Debug, Clone)]
pub struct JsMembered(pub(crate) Membered<JsSigner, JsChangeRef, JsEventHandler>);
