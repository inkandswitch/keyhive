use keyhive_core::principal::individual::id::IndividualId;
use wasm_bindgen::prelude::*;

#[wasm_bindgen(js_name = IndividualId)]
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct JsIndividualId(pub(crate) IndividualId);

#[wasm_bindgen(js_class = IndividualId)]
impl JsIndividualId {
    #[wasm_bindgen(getter)]
    pub fn bytes(&self) -> Box<[u8]> {
        Box::new(self.0.to_bytes())
    }
}

impl From<IndividualId> for JsIndividualId {
    fn from(individual_id: IndividualId) -> Self {
        JsIndividualId(individual_id)
    }
}
