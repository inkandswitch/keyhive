use super::{
    access::JsAccess, agent::JsAgent, change_id::JsChangeId, event_handler::JsEventHandler,
    signer::JsSigner,
};
use dupe::Dupe;
use future_form::Local;
use keyhive_core::{
    access::Access,
    principal::{agent::Agent, identifier::Identifier},
};
use std::collections::HashMap;
use wasm_bindgen::prelude::*;

/// The individuals in a transitive membership, other than `skip`, which is the
/// group or document the membership was taken from.
#[allow(clippy::type_complexity)]
pub(crate) fn individual_memberships(
    transitive: HashMap<Identifier, (Agent<Local, JsSigner, JsChangeId, JsEventHandler>, Access)>,
    skip: Identifier,
) -> Vec<Membership> {
    transitive
        .into_iter()
        .filter(|(id, _)| *id != skip)
        .filter_map(|(_, (agent, access))| {
            matches!(agent, Agent::Individual(_, _) | Agent::Active(_, _)).then(|| Membership {
                who: agent,
                can: access,
            })
        })
        .collect()
}

#[wasm_bindgen]
#[derive(Debug, Clone, Dupe)]
pub struct Membership {
    pub(crate) who: Agent<Local, JsSigner, JsChangeId, JsEventHandler>,
    pub(crate) can: Access,
}

#[wasm_bindgen]
impl Membership {
    #[wasm_bindgen(getter)]
    pub fn who(&self) -> JsAgent {
        JsAgent(self.who.dupe())
    }

    #[wasm_bindgen(getter)]
    pub fn can(&self) -> JsAccess {
        JsAccess(self.can.dupe())
    }
}
