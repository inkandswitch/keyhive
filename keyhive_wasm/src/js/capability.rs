use super::{identifier::JsIdentifier, power::JsPower, signed_delegation::JsSignedDelegation};
use dupe::Dupe;
use keyhive_crypto::id::Id;
use keyline::power::Power;
use wasm_bindgen::prelude::*;

/// A direct member of a group or document: who, at what power, and the live
/// delegation that admits them.
#[wasm_bindgen]
#[derive(Debug, Clone)]
pub struct Capability {
    pub(crate) who: Id,
    pub(crate) can: Power,
    pub(crate) proof: JsSignedDelegation,
}

#[wasm_bindgen]
impl Capability {
    #[wasm_bindgen(getter)]
    pub fn who(&self) -> JsIdentifier {
        JsIdentifier(self.who)
    }

    #[wasm_bindgen(getter)]
    pub fn can(&self) -> JsPower {
        JsPower(self.can)
    }

    #[wasm_bindgen(getter)]
    pub fn proof(&self) -> JsSignedDelegation {
        self.proof.dupe()
    }
}
