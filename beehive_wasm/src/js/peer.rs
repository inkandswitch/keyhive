use super::{change_ref::JsChangeRef, event_handler::JsEventHandler};
use beehive_core::principal::peer::Peer;
use derive_more::{Deref, From, Into};
use std::fmt::{Display, Formatter};
use wasm_bindgen::prelude::*;

#[wasm_bindgen(js_name = Peer)]
#[derive(Debug, Clone, From, Into, Deref)]
pub struct JsPeer(pub(crate) Peer<JsChangeRef, JsEventHandler>);

#[wasm_bindgen(js_class = Peer)]
impl JsPeer {
    #[wasm_bindgen(js_name = toString)]
    pub fn to_js_string(&self) -> String {
        self.0
            .id()
            .as_slice()
            .iter()
            .fold(String::new(), |mut acc, byte| {
                acc.push_str(&format!("{:#x}", byte));
                acc
            })
    }

    #[wasm_bindgen(js_name = isIndividual)]
    pub fn is_individual(&self) -> bool {
        matches!(self.0, Peer::Individual(_))
    }

    #[wasm_bindgen(js_name = isGroup)]
    pub fn is_group(&self) -> bool {
        matches!(self.0, Peer::Group(_))
    }

    #[wasm_bindgen(js_name = isDocument)]
    pub fn is_document(&self) -> bool {
        matches!(self.0, Peer::Document(_))
    }
}
