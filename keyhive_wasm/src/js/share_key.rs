use derive_more::{From, Into};
use keyhive_core::crypto::share_key::ShareKey;
use wasm_bindgen::prelude::*;

#[wasm_bindgen(js_name = ShareKey)]
#[derive(Debug, Clone, Copy, Into, From)]
pub struct JsShareKey(pub(crate) ShareKey);
