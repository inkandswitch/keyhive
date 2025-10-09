use super::{
    change_ref::JsChangeRef, event_handler::JsEventHandler, identifier::JsIdentifier,
    signer::JsSigner,
};
use dupe::Dupe;
use keyhive_core::principal::peer::Peer;
use thiserror::Error;
use wasm_bindgen::prelude::*;

#[wasm_bindgen(js_name = Peer)]
#[derive(Debug, Clone, Dupe)]
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

    #[wasm_bindgen(js_name = "__keyhive_toPeer")]
    pub fn __kh_to_peer(&self) -> Self {
        self.dupe()
    }
}

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(typescript_type = "Peer")]
    pub type JsPeerLike;

    #[wasm_bindgen(method, js_name = "__keyhive_toPeer")]
    pub fn kh_to_peer(this: &JsPeerLike) -> JsPeer;
}

pub trait ConvertMe: Sized {
    type JsInterface: JsCast;
    const UPCAST_TAG: &'static str;

    fn from_js_interface(castable: &Self::JsInterface) -> Self;

    fn from_js_value(js_value: &JsValue) -> Result<Self, NotExpectedJsInterface> {
        if js_sys::Reflect::has(&js_value, &JsValue::from(&Self::UPCAST_TAG.to_string())).is_ok() {
            let js_interface: &Self::JsInterface = js_value.unchecked_ref();
            Ok(Self::from_js_interface(js_interface))
        } else {
            Err(NotExpectedJsInterface)
        }
    }
}

#[derive(Debug, Clone, Dupe, Copy, Error)]
#[error("Not the expected JS interface")]
pub struct NotExpectedJsInterface;

impl From<NotExpectedJsInterface> for JsValue {
    fn from(err: NotExpectedJsInterface) -> Self {
        let err = js_sys::Error::new(&err.to_string());
        err.set_name("NotExpectedJsInterface");
        err.into()
    }
}

impl ConvertMe for JsPeer {
    type JsInterface = JsPeerLike;
    const UPCAST_TAG: &'static str = "__keyhive_toPeer";

    fn from_js_interface(castable: &Self::JsInterface) -> Self {
        castable.kh_to_peer()
    }
}
