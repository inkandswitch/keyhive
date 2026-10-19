use crate::js::archive::JsSerializationError;

use super::{
    change_id::JsChangeId, signed_delegation::JsSignedDelegation,
    signed_revocation::JsSignedRevocation,
};
use derive_more::{From, Into};
use dupe::Dupe;
use keyhive_core::event::{static_event::StaticEvent, Event};
use std::fmt;
use wasm_bindgen::prelude::*;

#[derive(Debug, Clone, Hash, From, Into)]
#[wasm_bindgen(js_name = Event)]
pub struct JsEvent(pub(crate) Event<JsChangeId>);

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

    /// The delegation a `DELEGATED` event carries.
    #[wasm_bindgen(js_name = asSignedDelegation)]
    pub fn as_signed_delegation(&self) -> Option<JsSignedDelegation> {
        match &self.0 {
            Event::Delegated(d) => Some(JsSignedDelegation(d.dupe())),
            _ => None,
        }
    }

    /// The revocation a `REVOKED` event carries.
    #[wasm_bindgen(js_name = asSignedRevocation)]
    pub fn as_signed_revocation(&self) -> Option<JsSignedRevocation> {
        match &self.0 {
            Event::Revoked(r) => Some(JsSignedRevocation(r.dupe())),
            _ => None,
        }
    }

    /// Converts the underlying [`Event`] to a [`StaticEvent`] and then
    /// serializes it.
    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Result<Box<[u8]>, JsSerializationError> {
        Ok(bincode::serialize(&StaticEvent::from(self.0.clone()))
            .map_err(JsSerializationError::from)?
            .into_boxed_slice())
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

impl fmt::Display for JsEventVariant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
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
