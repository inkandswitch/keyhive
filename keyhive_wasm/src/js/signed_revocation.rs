use super::secret_key_store::JsSecretKeyStore;
use super::{
    change_id::JsChangeId, event_handler::JsEventHandler, revocation::JsRevocation,
    signer::JsSigner,
};
use dupe::Dupe;
use future_form::Local;
use keyhive_core::principal::group::revocation::Revocation;
use keyhive_crypto::{signed::Signed, verifiable::Verifiable};
use std::sync::Arc;
use wasm_bindgen::prelude::*;

#[wasm_bindgen(js_name = SignedRevocation)]
#[derive(Debug, Dupe, Clone)]
pub struct JsSignedRevocation(
    pub(crate) 
        Arc<Signed<Revocation<Local, JsSigner, JsSecretKeyStore, JsChangeId, JsEventHandler>>>,
);

#[wasm_bindgen(js_class = SignedRevocation)]
impl JsSignedRevocation {
    pub fn verify(&self) -> bool {
        self.0.try_verify().is_ok()
    }

    #[wasm_bindgen(getter)]
    pub fn delegation(&self) -> JsRevocation {
        self.0.payload().clone().into()
    }

    #[wasm_bindgen(getter, js_name = verifyingKey)]
    pub fn verifying_key(&self) -> Vec<u8> {
        self.0.verifying_key().to_bytes().to_vec()
    }

    #[wasm_bindgen(getter)]
    pub fn signature(&self) -> Vec<u8> {
        self.0.signature().to_vec()
    }
}

impl From<Arc<Signed<Revocation<Local, JsSigner, JsSecretKeyStore, JsChangeId, JsEventHandler>>>>
    for JsSignedRevocation
{
    fn from(
        signed: Arc<
            Signed<Revocation<Local, JsSigner, JsSecretKeyStore, JsChangeId, JsEventHandler>>,
        >,
    ) -> Self {
        Self(signed)
    }
}

impl From<JsSignedRevocation>
    for Arc<Signed<Revocation<Local, JsSigner, JsSecretKeyStore, JsChangeId, JsEventHandler>>>
{
    fn from(js_signed: JsSignedRevocation) -> Self {
        js_signed.0
    }
}
