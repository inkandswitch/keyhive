use crate::js::membered::JsMembered;

use super::{
    agent::JsAgent, capability::Capability, change_id::JsChangeId, event_handler::JsEventHandler,
    group_id::JsGroupId, identifier::JsIdentifier, membership::Membership, peer::JsPeer,
    signer::JsSigner,
};
use derive_more::{From, Into};
use dupe::Dupe;
use future_form::Local;
use futures::lock::Mutex;
use keyhive_core::principal::{
    agent::Agent,
    group::{id::GroupId, Group},
    membered::Membered,
    peer::Peer,
};
use std::sync::Arc;
use wasm_bindgen::prelude::*;
use wasm_refgen::wasm_refgen;

#[wasm_bindgen(js_name = Group)]
#[derive(Debug, Clone, Dupe, Into, From)]
pub struct JsGroup {
    pub(crate) group_id: GroupId,
    pub(crate) inner: Arc<Mutex<Group<Local, JsSigner, JsChangeId, JsEventHandler>>>,
}

#[wasm_refgen(js_ref = JsGroupRef)]
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

    /// Everyone who reaches this group, following nested groups all the way
    /// down, with the access each one ends up holding.
    ///
    /// [`JsGroup::members`] is the group's own delegations, which is the wrong
    /// question to ask when working out whether a particular person can act
    /// here: someone in a group that is a member of this one holds real access
    /// and appears in no delegation of ours. Documents have
    /// [`JsKeyhive::doc_member_capabilities`] for this; groups had nothing.
    #[wasm_bindgen(js_name = transitiveMembers)]
    pub async fn transitive_members(&self) -> Vec<Membership> {
        let transitive = { self.inner.lock().await.transitive_members().await };
        transitive
            .into_iter()
            // Skip the group itself.
            .filter(|(id, _)| *id != self.group_id.into())
            .filter_map(|(_, (agent, access))| {
                // Individuals and the local identity, matching
                // `doc_member_capabilities`.
                matches!(agent, Agent::Individual(_, _) | Agent::Active(_, _)).then(|| Membership {
                    who: agent,
                    can: access,
                })
            })
            .collect()
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
        tracing::debug!("JsGroup::to_agent");
        JsAgent(Agent::Group(self.group_id, self.inner.dupe()))
    }

    #[wasm_bindgen(js_name = toMembered)]
    pub fn to_membered(&self) -> JsMembered {
        JsMembered(Membered::Group(self.group_id, self.inner.dupe()))
    }
}
