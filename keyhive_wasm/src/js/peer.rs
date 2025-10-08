use super::{
    change_ref::JsChangeRef, event_handler::JsEventHandler, identifier::JsIdentifier,
    signer::JsSigner,
};
use keyhive_core::principal::peer::Peer;
use wasm_bindgen::prelude::*;

#[wasm_bindgen(js_name = Peer)]
#[derive(Debug, Clone)]
pub struct JsPeer(pub(crate) Peer<JsSigner, JsChangeRef, JsEventHandler>);

#[wasm_bindgen(js_class = Peer)]
impl JsPeer {
    #[wasm_bindgen(getter)]
    pub fn id(&self) -> JsIdentifier {
        self.0.id().into()
    }

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
        matches!(self.0, Peer::Individual(_, _))
    }

    #[wasm_bindgen(js_name = isGroup)]
    pub fn is_group(&self) -> bool {
        matches!(self.0, Peer::Group(_, _))
    }

    #[wasm_bindgen(js_name = isDocument)]
    pub fn is_document(&self) -> bool {
        matches!(self.0, Peer::Document(_, _))
    }
}
