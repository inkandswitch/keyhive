use keyhive_core::crypto::share_key::ShareKey;
use wasm_bindgen::prelude::*;

#[wasm_bindgen(js_name = ShareKey)]
pub struct JsShareKey(pub(crate) ShareKey);
