use crate::js::archive::JsSerializationError;

use super::change_id::JsChangeId;
use derive_more::{From, Into};
use dupe::Dupe;
use keyhive_core::event::static_event::StaticEvent;
use wasm_bindgen::prelude::*;

/// JavaScript wrapper for a Keyhive event.
///
/// Events are stored internally as [`StaticEvent`]s (serializable form).
#[derive(Debug, Clone, Hash, From, Into)]
#[wasm_bindgen(js_name = Event)]
pub struct JsEvent(pub(crate) StaticEvent<JsChangeId>);

#[wasm_bindgen(js_class = Event)]
impl JsEvent {
    #[wasm_bindgen(getter)]
    pub fn variant(&self) -> String {
        JsEventVariant::from(self).to_string()
    }

    #[wasm_bindgen(getter, js_name = isDelegated)]
    pub fn is_delegated(&self) -> bool {
        matches!(self.0, StaticEvent::Delegated(_))
    }

    #[wasm_bindgen(getter, js_name = isRevoked)]
    pub fn is_revoked(&self) -> bool {
        matches!(self.0, StaticEvent::Revoked(_))
    }

    /// Serializes the event to bytes.
    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Result<Box<[u8]>, JsSerializationError> {
        Ok(bincode::serialize(&self.0)
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
        match &event.0 {
            StaticEvent::Delegated(_) => JsEventVariant::Delegated,
            StaticEvent::Revoked(_) => JsEventVariant::Revoked,

            StaticEvent::CgkaOperation { .. } => JsEventVariant::CgkaOperation,

            StaticEvent::PrekeyRotated { .. } => JsEventVariant::PrekeyRotated,
            StaticEvent::PrekeysExpanded { .. } => JsEventVariant::PrekeysExpanded,
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
