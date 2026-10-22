use derive_more::{Deref, Display, From, Into};
use keyhive_core::{contact_card::ContactCard, event::Event};
use keyhive_crypto::{identifier::Identifier, verifiable::Verifiable};
use wasm_bindgen::prelude::*;

use crate::js::{event::JsEvent, identifier::JsIdentifier};

use super::{individual_id::JsIndividualId, share_key::JsShareKey};
use ed25519_dalek::VerifyingKey;

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
        JsEvent(Event::from(self.0.op().clone()))
    }

    #[wasm_bindgen(getter)]
    pub fn signature(&self) -> Vec<u8> {
        self.0.signature().to_bytes().to_vec()
    }

    /// Read a card from `toBytes`, checking its signature.
    #[wasm_bindgen(js_name = "fromBytes")]
    pub fn from_bytes(bytes: &[u8]) -> Result<JsContactCard, JsValue> {
        let contact_card = ContactCard::from_bytes(bytes).map_err(|e| {
            let err = js_sys::Error::new(&format!("cannot read ContactCard: {e}"));
            err.set_name("ContactCardError");
            JsValue::from(err)
        })?;
        Ok(JsContactCard(contact_card))
    }

    /// The card's bytes: its prekey operation's `KH` frame.
    #[wasm_bindgen(js_name = "toBytes")]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes()
    }
}

impl Verifiable for JsContactCard {
    fn verifying_key(&self) -> VerifyingKey {
        self.0.verifying_key()
    }
}
