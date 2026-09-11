use crate::js::identifier::{CannotParseIdentifier, JsIdentifier};
use keyhive_core::principal::{identifier::Identifier, individual::id::IndividualId};
use wasm_bindgen::prelude::*;

#[wasm_bindgen(js_name = IndividualId)]
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct JsIndividualId(pub(crate) IndividualId);

#[wasm_bindgen(js_class = IndividualId)]
impl JsIndividualId {
    /// Build an individual id from its 32 raw bytes.
    #[wasm_bindgen(constructor)]
    pub fn new(bytes: Vec<u8>) -> Result<Self, CannotParseIdentifier> {
        let vec: [u8; 32] = bytes.try_into().map_err(|_| CannotParseIdentifier)?;
        let vk =
            ed25519_dalek::VerifyingKey::from_bytes(&vec).map_err(|_| CannotParseIdentifier)?;
        Ok(Self(IndividualId(Identifier::from(vk))))
    }

    #[wasm_bindgen(js_name = toString)]
    pub fn to_js_string(&self) -> String {
        self.0.to_string()
    }

    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes().to_vec()
    }

    #[wasm_bindgen(js_name = toIdentifier)]
    pub fn to_identifier(&self) -> JsIdentifier {
        JsIdentifier(Identifier::from(self.0))
    }
}

impl From<IndividualId> for JsIndividualId {
    fn from(individual_id: IndividualId) -> Self {
        JsIndividualId(individual_id)
    }
}
