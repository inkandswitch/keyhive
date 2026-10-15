use super::{identifier::JsIdentifier, power::JsPower};
use derive_more::{From, Into};
use keyline::delegation::Delegation;
use wasm_bindgen::prelude::*;

/// A Keyline delegation: `issuer` asserts that `delegate` may exercise `can`
/// over `subject`, attenuated to the issuer's own power over it.
#[wasm_bindgen(js_name = Delegation)]
#[derive(Debug, Clone, Copy, From, Into)]
pub struct JsDelegation(pub(crate) Delegation);

#[wasm_bindgen(js_class = Delegation)]
impl JsDelegation {
    #[wasm_bindgen(getter)]
    pub fn issuer(&self) -> JsIdentifier {
        JsIdentifier(self.0.issuer.into())
    }

    /// Who receives the power: the delegation's audience.
    #[wasm_bindgen(getter)]
    pub fn delegate(&self) -> JsIdentifier {
        JsIdentifier(self.0.audience.into())
    }

    #[wasm_bindgen(getter)]
    pub fn subject(&self) -> JsIdentifier {
        JsIdentifier(self.0.subject.into())
    }

    #[wasm_bindgen(getter)]
    pub fn can(&self) -> JsPower {
        JsPower(self.0.power)
    }

    /// Whether this re-issues a delegation identical to a revoked one.
    #[wasm_bindgen(getter, js_name = isReissue)]
    pub fn is_reissue(&self) -> bool {
        self.0.citation.is_some()
    }
}
