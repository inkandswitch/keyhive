use super::{
    change_ref::JsChangeRef, event_handler::JsEventHandler, signed_delegation::JsSignedDelegation,
    signed_revocation::JsSignedRevocation, signer::JsSigner,
};
use derive_more::{From, Into};
use dupe::Dupe;
use keyhive_core::event::Event;
use wasm_bindgen::prelude::*;

#[derive(Debug, Clone, From, Into)]
#[wasm_bindgen(js_name = Event)]
pub struct JsEvent(pub(crate) Event<JsSigner, JsChangeRef, JsEventHandler>);

#[wasm_bindgen(js_class = Event)]
impl JsEvent {
    #[wasm_bindgen(getter)]
    pub fn variant(&self) -> String {
        JsEventVariant::from(self).to_string()
    }

    #[wasm_bindgen(getter, js_name = isDelegated)]
    pub fn is_delegated(&self) -> bool {
        matches!(self.0, Event::Delegated(_))
    }

    #[wasm_bindgen(getter, js_name = isRevoked)]
    pub fn is_revoked(&self) -> bool {
        matches!(self.0, Event::Revoked(_))
    }

    #[wasm_bindgen(js_name = tryIntoSignedDelegation)]
    pub fn try_into_signed_delegation(&self) -> Option<JsSignedDelegation> {
        match &self.0 {
            Event::Delegated(d) => Some(d.dupe().into()),
            _ => None,
        }
    }

    #[wasm_bindgen(js_name = tryIntoSignedRevocation)]
    pub fn try_into_signed_revocation(&self) -> Option<JsSignedRevocation> {
        match &self.0 {
            Event::Revoked(r) => Some(r.dupe().into()),
            _ => None,
        }
    }
}

impl Dupe for JsEvent {
    fn dupe(&self) -> Self {
        self.clone()
    }
}

#[derive(Debug, Clone, Copy)]
pub enum JsEventVariant {
    Delegated,
    Revoked,

    CgkaOperation,

    PrekeyRotated,
    PrekeysExpanded,
}

impl From<&JsEvent> for JsEventVariant {
    fn from(event: &JsEvent) -> Self {
        match event.0 {
            Event::Delegated(_) => JsEventVariant::Delegated,
            Event::Revoked(_) => JsEventVariant::Revoked,

            Event::CgkaOperation { .. } => JsEventVariant::CgkaOperation,

            Event::PrekeyRotated { .. } => JsEventVariant::PrekeyRotated,
            Event::PrekeysExpanded { .. } => JsEventVariant::PrekeysExpanded,
        }
    }
}

impl std::fmt::Display for JsEventVariant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self {
            JsEventVariant::Delegated => "DELEGATED",
            JsEventVariant::Revoked => "REVOKED",

            JsEventVariant::CgkaOperation => "CGKA_OPERATION",

            JsEventVariant::PrekeyRotated => "PREKEY_ROTATED",
            JsEventVariant::PrekeysExpanded => "PREKEYS_EXPANDED",
        }
        .fmt(f)
    }
}
