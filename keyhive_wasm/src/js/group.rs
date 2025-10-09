use crate::js::membered::JsMembered;

use super::{
    agent::JsAgent, capability::Capability, change_ref::JsChangeRef, event_handler::JsEventHandler,
    group_id::JsGroupId, identifier::JsIdentifier, peer::JsPeer, signer::JsSigner,
};
use derive_more::{From, Into};
use dupe::Dupe;
use futures::lock::Mutex;
use keyhive_core::principal::{
    agent::Agent,
    group::{id::GroupId, Group},
    membered::Membered,
    peer::Peer,
};
use std::sync::Arc;
use wasm_bindgen::prelude::*;

#[wasm_bindgen(js_name = Group)]
#[derive(Debug, Clone, Dupe, Into, From)]
pub struct JsGroup {
    pub(crate) group_id: GroupId,
    pub(crate) inner: Arc<Mutex<Group<JsSigner, JsChangeRef, JsEventHandler>>>,
}

#[wasm_bindgen(js_class = Group)]
impl JsGroup {
    #[wasm_bindgen(getter)]
    pub fn id(&self) -> JsIdentifier {
        JsIdentifier(self.group_id.into())
    }

    #[wasm_bindgen(getter, js_name = groupId)]
    pub fn group_id(&self) -> JsGroupId {
        JsGroupId(self.group_id)
    }

    #[wasm_bindgen]
    pub async fn members(&self) -> Vec<Capability> {
        self.inner
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
        JsPeer(Peer::Group(self.group_id, self.inner.dupe()))
    }

    #[wasm_bindgen(js_name = toAgent)]
    pub fn to_agent(&self) -> JsAgent {
        JsAgent(Agent::Group(self.group_id, self.inner.dupe()))
    }

    #[wasm_bindgen(js_name = toMembered)]
    pub fn to_membered(&self) -> JsMembered {
        JsMembered(Membered::Group(self.group_id, self.inner.dupe()))
    }
}
