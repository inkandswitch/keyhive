use derive_more::{Deref, Display, From, Into};
use keyhive_core::{
    contact_card::ContactCard,
    crypto::verifiable::Verifiable,
    event::static_event::StaticEvent,
    principal::{identifier::Identifier, individual::op::KeyOp},
};
use std::sync::Arc;
use wasm_bindgen::prelude::*;

use crate::js::{change_id::JsChangeId, event::JsEvent, identifier::JsIdentifier};

use super::{individual_id::JsIndividualId, share_key::JsShareKey};

#[wasm_bindgen(js_name = ContactCard)]
#[derive(Debug, Clone, From, Into, Deref, Display)]
pub struct JsContactCard(ContactCard);

#[wasm_bindgen(js_class = ContactCard)]
impl JsContactCard {
    #[wasm_bindgen(getter)]
    pub fn id(&self) -> JsIdentifier {
        let identifier = Identifier::from(self.0.id());
        JsIdentifier(identifier)
    }

    #[wasm_bindgen(getter, js_name = "individualId")]
    pub fn individual_id(&self) -> JsIndividualId {
        self.0.id().into()
    }

    #[wasm_bindgen(getter, js_name = "shareKey")]
    pub fn share_key(&self) -> JsShareKey {
        (*self.0.share_key()).into()
    }

    #[wasm_bindgen(getter)]
    pub fn op(&self) -> JsEvent {
        let static_event: StaticEvent<JsChangeId> = match self.0.op().clone() {
            KeyOp::Add(add) => StaticEvent::PrekeysExpanded(Box::new(Arc::unwrap_or_clone(add))),
            KeyOp::Rotate(rot) => StaticEvent::PrekeyRotated(Box::new(Arc::unwrap_or_clone(rot))),
        };
        JsEvent(static_event)
    }

    pub fn signature(&self) -> Vec<u8> {
        self.0.signature().to_bytes().to_vec()
    }

    #[cfg(feature = "json")]
    #[wasm_bindgen(js_name = "fromJson")]
    pub fn from_json(json: &str) -> Result<JsContactCard, JsValue> {
        let contact_card: ContactCard = serde_json::from_str(json)
            .map_err(|e| JsValue::from_str(&format!("Failed to parse JSON: {}", e)))?;
        Ok(JsContactCard(contact_card))
    }

    #[cfg(feature = "json")]
    #[wasm_bindgen(js_name = "toJson")]
    pub fn to_json(&self) -> Result<String, JsValue> {
        serde_json::to_string(&self.0)
            .map_err(|e| JsValue::from_str(&format!("Failed to serialize to JSON: {}", e)))
    }
}

impl Verifiable for JsContactCard {
    fn verifying_key(&self) -> ed25519_dalek::VerifyingKey {
        self.0.verifying_key()
    }
}
