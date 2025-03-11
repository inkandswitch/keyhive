use derive_more::{Deref, Display, From, Into};
use keyhive_core::{contact_card::ContactCard, crypto::verifiable::Verifiable};
use wasm_bindgen::prelude::*;

use super::{individual_id::JsIndividualId, share_key::JsShareKey};

#[wasm_bindgen(js_name = ContactCard)]
#[derive(Debug, Clone, From, Into, Deref, Display)]
pub struct JsContactCard(ContactCard);

#[wasm_bindgen(js_class = ContactCard)]
impl JsContactCard {
    #[wasm_bindgen(getter)]
    pub fn id(&self) -> JsIndividualId {
        self.0.id().into()
    }

    #[wasm_bindgen(getter, js_name = "shareKey")]
    pub fn share_key(&self) -> JsShareKey {
        (*self.0.share_key()).into()
    }
}

impl Verifiable for JsContactCard {
    fn verifying_key(&self) -> ed25519_dalek::VerifyingKey {
        self.0.verifying_key()
    }
}
