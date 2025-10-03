use crate::js::membered::JsMembered;

use super::{
    agent::JsAgent, capability::Capability, change_ref::JsChangeRef, event_handler::JsEventHandler,
    group_id::JsGroupId, identifier::JsIdentifier, peer::JsPeer, signer::JsSigner,
};
use derive_more::{From, Into};
use dupe::Dupe;
use futures::lock::Mutex;
use keyhive_core::principal::group::Group;
use std::sync::Arc;
use wasm_bindgen::prelude::*;

#[wasm_bindgen(js_name = Group)]
#[derive(Debug, Clone, Dupe, Into, From)]
pub struct JsGroup(pub(crate) Arc<Mutex<Group<JsSigner, JsChangeRef, JsEventHandler>>>);

#[wasm_bindgen(js_class = Group)]
impl JsGroup {
    #[wasm_bindgen(getter)]
    pub async fn id(&self) -> JsIdentifier {
        let locked = self.0.lock().await;
        JsIdentifier(locked.id())
    }

    #[wasm_bindgen(getter, js_name = groupId)]
    pub async fn group_id(&self) -> JsGroupId {
        JsGroupId(self.0.lock().await.group_id())
    }

    #[wasm_bindgen(getter)]
    pub async fn members(&self) -> Vec<Capability> {
        self.0
            .lock()
            .await
            .members()
            .values()
            .map(|dlgs| {
                let best = dlgs
                    .iter()
                    .max_by_key(|dlg| dlg.payload().can())
                    .expect("should have at least one member");

                Capability {
                    who: dlgs.iter().next().unwrap().payload().delegate().clone(),
                    proof: best.clone(),
                }
            })
            .collect()
    }

    #[wasm_bindgen(js_name = toPeer)]
    pub fn to_peer(&self) -> JsPeer {
        JsPeer(self.0.dupe().into())
    }

    #[wasm_bindgen(js_name = toAgent)]
    pub fn to_agent(&self) -> JsAgent {
        JsAgent(self.0.dupe().into())
    }

    #[wasm_bindgen(js_name = toMembered)]
    pub fn to_membered(&self) -> JsMembered {
        JsMembered(self.0.dupe().into())
    }
}
