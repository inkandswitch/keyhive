use wasm_bindgen::prelude::*;

/// Result of [`JsKeyhive::all_agent_events`], containing all events for all agents
/// with deduplicated storage and two-tier indirection for membership, prekey, and CGKA ops.
///
/// The consumer follows: agent -> source IDs -> hashes -> event bytes.
#[wasm_bindgen(js_name = AllAgentEvents)]
pub struct JsAllAgentEvents {
    /// All events deduplicated: `Map<Uint8Array(hash), Uint8Array(eventBytes)>`
    events: js_sys::Map,
    /// Membership ops per source: `Map<Uint8Array(sourceId), Uint8Array[](hashes)>`
    membership_sources: js_sys::Map,
    /// Agent -> membership sources: `Map<Uint8Array(agentId), Uint8Array[](sourceIdBytes)>`
    agent_membership_sources: js_sys::Map,
    /// Prekey ops per source: `Map<Uint8Array(identifierBytes), Uint8Array[](hashes)>`
    prekey_sources: js_sys::Map,
    /// Agent -> prekey sources: `Map<Uint8Array(agentId), Uint8Array[](identifierBytes)>`
    agent_prekey_sources: js_sys::Map,
    /// CGKA ops per doc: `Map<Uint8Array(docId), Uint8Array[](hashes)>`
    cgka_sources: js_sys::Map,
    /// Agent -> CGKA sources: `Map<Uint8Array(agentId), Uint8Array[](docIdBytes)>`
    agent_cgka_sources: js_sys::Map,
}

#[wasm_bindgen(js_class = AllAgentEvents)]
impl JsAllAgentEvents {
    pub(crate) fn new(
        events: js_sys::Map,
        membership_sources: js_sys::Map,
        agent_membership_sources: js_sys::Map,
        prekey_sources: js_sys::Map,
        agent_prekey_sources: js_sys::Map,
        cgka_sources: js_sys::Map,
        agent_cgka_sources: js_sys::Map,
    ) -> Self {
        Self {
            events,
            membership_sources,
            agent_membership_sources,
            prekey_sources,
            agent_prekey_sources,
            cgka_sources,
            agent_cgka_sources,
        }
    }

    #[wasm_bindgen(getter)]
    pub fn events(&self) -> js_sys::Map {
        self.events.clone()
    }

    #[wasm_bindgen(getter, js_name = membershipSources)]
    pub fn membership_sources(&self) -> js_sys::Map {
        self.membership_sources.clone()
    }

    #[wasm_bindgen(getter, js_name = agentMembershipSources)]
    pub fn agent_membership_sources(&self) -> js_sys::Map {
        self.agent_membership_sources.clone()
    }

    #[wasm_bindgen(getter, js_name = prekeySources)]
    pub fn prekey_sources(&self) -> js_sys::Map {
        self.prekey_sources.clone()
    }

    #[wasm_bindgen(getter, js_name = agentPrekeySources)]
    pub fn agent_prekey_sources(&self) -> js_sys::Map {
        self.agent_prekey_sources.clone()
    }

    #[wasm_bindgen(getter, js_name = cgkaSources)]
    pub fn cgka_sources(&self) -> js_sys::Map {
        self.cgka_sources.clone()
    }

    #[wasm_bindgen(getter, js_name = agentCgkaSources)]
    pub fn agent_cgka_sources(&self) -> js_sys::Map {
        self.agent_cgka_sources.clone()
    }
}
